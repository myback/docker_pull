#!/usr/bin/env python3

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import logging
import os
import requests
import requests.auth
import shutil
import struct
import tarfile
import typing
import urllib.parse as urlparse

from collections import OrderedDict
from dateutil.parser import parse as date_parse

# TODO: v1_layers_ids, empty_manifest, empty_layer_json use like a struct in golang
# TODO: add function like a digest.Digister in moby/moby

JSON_SEPARATOR = (',', ':')
DOCKER_REGISTRY_HOST = 'registry-1.docker.io'


def py_scanstring(s, end, strict=True, _b=json.decoder.BACKSLASH, _m=json.decoder.STRINGCHUNK.match):
    """Scan the string s for a JSON string. End is the index of the
    character in s after the quote that started the JSON string.
    Unescapes all valid JSON string escape sequences and raises ValueError
    on attempt to decode an invalid string. If strict is False then literal
    control characters are allowed in the string.
    Returns a tuple of the decoded string and the index of the character in s
    after the end quote."""
    chunks = []
    _append = chunks.append
    begin = end - 1
    while 1:
        chunk = _m(s, end)
        if chunk is None:
            raise json.JSONDecodeError("Unterminated string starting at", s, begin)
        end = chunk.end()
        content, terminator = chunk.groups()
        # Content is contains zero or more unescaped string characters
        if content:
            _append(content)
        # Terminator is the end of string, a literal control character,
        # or a backslash denoting that an escape sequence follows
        if terminator == '"':
            break
        elif terminator != '\\':
            if strict:
                msg = "Invalid control character {0!r} at".format(terminator)
                raise json.JSONDecodeError(msg, s, end)
            else:
                _append(terminator)
                continue
        try:
            esc = s[end]
        except IndexError:
            raise json.JSONDecodeError("Unterminated string starting at", s, begin)
        # If not a unicode escape sequence, must be in the lookup table
        if esc != 'u':
            try:
                char = _b[esc]
            except KeyError:
                msg = "Invalid \\escape: {0!r}".format(esc)
                raise json.JSONDecodeError(msg, s, end)
            end += 1
        else:
            st = end - 1
            end += 5
            char = s[st:end]
        _append(char)
    return ''.join(chunks), end


class JSONDecoderRawString(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, *args, **kwargs)
        self.parse_string = JSONDecoderRawString.new_scanstring
        self.scan_once = json.scanner.py_make_scanner(self)
        json.decoder.scanstring = py_scanstring

    @classmethod
    def new_scanstring(cls, _s, end, strict=False):
        ss, end = json.decoder.scanstring(_s, end, strict)
        return ss, end


def www_auth(hdr: str) -> dict:
    ret = {}

    auth_type, info = hdr.split(' ', 1)
    auth_type = auth_type.lower()
    ret[auth_type] = {}

    for part in info.split(','):
        k, v = part.split('=', 1)
        ret[auth_type][k] = v.lower().replace('"', '')

    return ret


def chain_ids(ids: list) -> list:
    chain = list()
    chain.append(ids[0])

    if len(ids) < 2:
        return ids

    nxt = list()
    nxt.append("sha256:" + hashlib.sha256(f'{ids[0]} {ids[1]}'.encode()).hexdigest())
    nxt.extend(ids[2:])

    chain.extend(chain_ids(nxt))

    return chain


def container_config():
    # container.Config
    return OrderedDict(
        Hostname="",
        Domainname="",
        User="",
        AttachStdin=False,
        AttachStdout=False,
        AttachStderr=False,
        Tty=False,
        OpenStdin=False,
        StdinOnce=False,
        Env=None,
        Cmd=None,
        Image="",
        Volumes=None,
        WorkingDir="",
        Entrypoint=None,
        OnBuild=None,
        Labels=None
    )


def v1_layers_ids(chain_ids_list, config_image):
    r = []
    parent = ''
    for chain_id in chain_ids_list:
        if chain_id == chain_ids_list[-1]:
            cfg = OrderedDict(
                architecture='amd64',
                config='',
                container='',
                container_config='',
                created='1970-01-01T00:00:00Z',
                docker_version='18.06.1-ce',
                layer_id=chain_id,
                os='linux'
            )
            if parent:
                cfg['parent'] = parent

            v1_img = config_image.copy()
            del v1_img['history']
            del v1_img['rootfs']

            cfg.update(v1_img)
        else:
            cfg = OrderedDict(
                container_config=container_config(),
                created="1970-01-01T00:00:00Z",
                layer_id=chain_id,
            )

            if parent:
                cfg['parent'] = parent

        j = json.dumps(cfg, separators=JSON_SEPARATOR, ensure_ascii=False).replace(r'\\u', r'\u')
        parent = "sha256:" + hashlib.sha256(j.encode()).hexdigest()
        r.append(parent)

    return r


def sha256sum(filename, chunk_size=16384):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        while 1:
            chunk = memoryview(f.read(chunk_size))
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sizeof_fmt(num):
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if abs(num) < 1024:
            return f'{num:3.1f}{unit}'
        num /= 1024

    return f'{num:3.1f}PiB'


def progress_bar(description, content_length, done, progressbar_length=50):
    # TODO: shutil.get_terminal_size((80, 20))
    fill = int(progressbar_length * done / content_length)
    progress_bar_fill = '=' * (fill - 1) + '>'
    progress_bar_str = "{} [{: <{length}}] {}/{}".format(description,
                                                         progress_bar_fill,
                                                         sizeof_fmt(done),
                                                         sizeof_fmt(content_length),
                                                         length=progressbar_length)

    print("\r", end='')
    print(progress_bar_str, end='', flush=True)
    print(" " * len(progress_bar_str) + "\r", end='')


class FileExporter:
    def __init__(self, temp_dir, work_dir='.'):
        self._path = os.path.join(work_dir, temp_dir)

        if os.path.exists(self.path):
            if not os.path.isdir(self.path):
                raise Exception(f'Path {self.path} is existing file not directory')
        else:
            os.makedirs(self.path, exist_ok=True)

    @property
    def path(self):
        return self._path

    def path_join(self, *args):
        file_path = os.path.join(self.path, *args)
        if os.path.isdir(file_path):
            raise Exception(f'Path {file_path} is a directory')

        layer_dir = os.path.dirname(file_path)
        if os.path.exists(layer_dir):
            if not os.path.isdir(layer_dir):
                raise Exception(f'Path {layer_dir} is existing file not directory')
        else:
            os.makedirs(layer_dir, exist_ok=True)

        return file_path

    def write(self, s: typing.AnyStr):
        if isinstance(s, str) and 'w' in self.fd.mode:
            s = s.encode()

        self.fd.write(s)

    def __call__(self, *path, mode='wb'):
        self.fd = open(self.path_join(*path), mode=mode)
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.fd.close()


class TarExporter(tarfile.TarInfo):
    def get_info(self):
        """Return the TarInfo's attributes as a dictionary.
        """
        info = {
            "name": self.name,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "mtime": self.mtime,
            "chksum": self.chksum,
            "type": self.type,
            "linkname": self.linkname,
            "uname": self.uname,
            "gname": self.gname,
            "devmajor": self.devmajor,
            "devminor": self.devminor
        }

        if info["type"] == tarfile.DIRTYPE and not info["name"].endswith("/"):
            info["name"] += "/"

        return info

    @staticmethod
    def _create_header(info, format_, encoding, errors):
        """Return a header block. info is a dictionary with file
           information, format must be one of the *_FORMAT constants.
        """
        parts = [
            tarfile.stn(info.get("name", ""), 100, encoding, errors),
            tarfile.itn(info.get("mode", 0), 8, format_),
            tarfile.itn(info.get("uid", 0), 8, format_),
            tarfile.itn(info.get("gid", 0), 8, format_),
            tarfile.itn(info.get("size", 0), 12, format_),
            tarfile.itn(info.get("mtime", 0), 12, format_),
            b" " * 8,  # checksum field
            info.get("type", tarfile.REGTYPE),
            tarfile.stn(info.get("linkname", ""), 100, encoding, errors),
            info.get("magic", tarfile.POSIX_MAGIC),
            tarfile.stn(info.get("uname", ""), 32, encoding, errors),
            tarfile.stn(info.get("gname", ""), 32, encoding, errors),
            tarfile.itn(info.get("devmajor", 0), 8, format_),
            tarfile.itn(info.get("devminor", 0), 8, format_),
            tarfile.stn(info.get("prefix", ""), 155, encoding, errors)
        ]

        buf = struct.pack("%ds" % tarfile.BLOCKSIZE, b"".join(parts))
        chksum = tarfile.calc_chksums(buf[-tarfile.BLOCKSIZE:])[0]
        buf = buf[:-364] + bytes("%06o\0" % chksum, "ascii") + buf[-357:]
        return buf


class TarFile(tarfile.TarFile):
    tarinfo = TarExporter
    format = tarfile.USTAR_FORMAT
    tarfile.RECORDSIZE = 512

    def __init__(self, name, mode, fileobj, *, remove_src_dir: bool = False, owner: int = 0, group: int = 0,
                 numeric_owner: bool = True, **kwargs):
        super(TarFile, self).__init__(name, mode, fileobj, **kwargs)
        self._remove_src_dir = remove_src_dir
        self._owner = owner
        self._group = group
        self._numeric_owner = numeric_owner

        self._added_paths_list = []

    def add(self, name, arcname=None, recursive=True, *, filter_=None, created=None):
        if name.split(os.path.sep)[0] not in self._added_paths_list:
            self._added_paths_list.append(name)

        if not arcname:
            arcname = name

        if created is None:
            created = datetime.datetime.now().isoformat()

        for d in sorted(os.listdir(name)):
            file_path = os.path.join(name, d)
            arc_name = os.path.relpath(file_path, arcname)

            if os.path.basename(file_path) in ['manifest.json', 'repositories']:
                mod_time = (0.0, 0.0)
            else:
                ct_time = date_parse(created)
                mod_time = (ct_time.timestamp(), ct_time.timestamp())

            os.utime(file_path, mod_time)

            tarinfo = self.gettarinfo(file_path, arc_name)

            tarinfo.uid = self._owner
            tarinfo.gid = self._group

            if self._numeric_owner:
                tarinfo.uname = ''
                tarinfo.gname = ''

            if os.path.isdir(file_path):
                self.addfile(tarinfo)
                self.add(file_path, name, recursive=recursive, filter_=filter_, created=created)
            else:
                with open(file_path, "rb") as f:
                    self.addfile(tarinfo, f)

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.close()
        else:
            # An exception occurred. We must not call close() because
            # it would try to write end-of-archive blocks and padding.
            if not self._extfileobj:
                self.fileobj.close()
            self.closed = True

        if self._remove_src_dir and exc_type is None:
            for _p in self._added_paths_list:
                shutil.rmtree(_p)


class ImageFetcher:
    def __init__(self, *, user: str = None, password: str = None, ssl: bool = True, verbose: bool = False,
                 save_cache: bool = False):
        self._ssl = ssl
        self._user = user
        self._password = password
        self._session = requests.Session()
        self._save_cache = save_cache

        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    def _make_url(self, registry: str, ns: str) -> str:
        return urlparse.urlunsplit(('https' if self._ssl else 'http', registry, f'/v2/{ns}/', None, None))

    def _auth(self, resp: requests.Response):
        if self._session.headers.get('Authorization'):
            del self._session.headers['Authorization']

        auth = requests.auth.HTTPBasicAuth(self._user, self._password) if self._user else None

        parsed = www_auth(resp.headers['www-authenticate'])
        url_parts = list(urlparse.urlparse(parsed['bearer']['realm']))
        query = urlparse.parse_qs(url_parts[4])
        query.update(service=parsed['bearer']['service'])

        if 'scope' in parsed['bearer']:
            query.update(scope=parsed['bearer']['scope'])

        url_parts[4] = urlparse.urlencode(query, True)

        r = self._session.get(urlparse.urlunparse(url_parts), auth=auth)
        r.raise_for_status()

        self._session.headers.update(Authorization=f"Bearer {r.json()['token']}")

    def _req(self, url, *, method='GET', stream: bool = None, headers: dict = None):
        r = self._session.request(method, url, stream=stream, headers=headers)
        if r.status_code == requests.codes.unauthorized:
            self._auth(r)
            r = self._session.request(method, url, stream=stream, headers=headers)

        if r.status_code != requests.codes.ok:
            r.raise_for_status()

        return r

    def _manifests_req(self, url: str, tag: str, accept_hdr: str) -> requests.Response:
        return self._req(urlparse.urljoin(url, f'manifests/{tag}'), headers={'Accept': accept_hdr})

    def get_manifest(self, url: str, tag: str) -> requests.Response:
        return self._manifests_req(url, tag, 'application/vnd.docker.distribution.manifest.v2+json')

    def get_manifest_list(self, url: str, tag: str) -> requests.Response:
        return self._manifests_req(url, tag, 'application/vnd.docker.distribution.manifest.list.v2+json')

    def get_blob(self, url: str, tag: str, stream: bool = False) -> requests.Response:
        if stream:
            self._session.headers['Accept'] = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
        return self._req(urlparse.urljoin(url, f'blobs/{tag}'), stream=stream)

    @property
    def empty_manifest(self):
        return [OrderedDict(
            Config='',
            RepoTags=[],
            Layers=[]
        )]

    # TODO: remove last_layer arg
    def empty_layer_json(self, *, image_os: str = 'linux', last_layer: bool = False):
        od = OrderedDict(created="1970-01-01T00:00:00Z")

        if last_layer:
            od['container'] = ''

        od['container_config'] = container_config()

        if last_layer:
            od['docker_version'] = '18.06.1-ce'
            od['config'] = ''
            od['architecture'] = ''

        od['os'] = image_os

        return od

    @staticmethod
    def parser(image: str) -> tuple:
        registry = DOCKER_REGISTRY_HOST

        image_parts = image.split('/')
        if len(image_parts) == 1:
            ns_parts = ['library']
        elif '.' in image_parts[0] or ':' in image_parts[0]:
            registry = image_parts[0]
            ns_parts = image_parts[1:-1]
        else:
            ns_parts = image_parts[:-1]

        image_name_tag = image_parts[-1].rsplit('@') if '@' in image_parts[-1] else image_parts[-1].split(':')
        ns_parts.append(image_name_tag[0])

        if len(image_name_tag) == 1:
            tag = 'latest'
        elif len(image_name_tag) == 2:
            tag = image_name_tag[1]
        else:
            raise Exception(f'Image format name {image} is invalid')

        return registry, '/'.join(ns_parts), tag

    def _get_layer(self, url, layer_digest, diff_id, output_file):
        gziped_file = f'{output_file}.gz'
        layer_id_short = layer_digest[7:19]

        if os.path.exists(output_file):
            if sha256sum(output_file) != diff_id[7:]:
                self._session.headers['Range'] = 'bytes={}-'.format(os.path.getsize(gziped_file))
                open_file_mode = 'ab'
                logging.debug(f'File {output_file} is exist, resume download')
            else:
                print("\r{}: Pull complete {}".format(layer_id_short, " " * 100), flush=True)
                logging.debug(f'File {output_file} is exist, download next blob')
                return
        else:
            open_file_mode = 'wb'

        r = self.get_blob(url, layer_digest, stream=True)
        logging.debug(f'Blob headers: {layer_digest}: {r.headers}')

        content_length = int(r.headers.get('Content-Length', 0))

        with open(gziped_file, open_file_mode) as file:
            done = 0
            chunk_size = 8192
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    file.write(chunk)
                    done += len(chunk)

                    progress_bar(f"{layer_id_short}: Downloading", content_length, done)

        if 'Range' in self._session.headers:
            del self._session.headers['Range']

        with gzip.open(gziped_file, 'rb') as gz_data, open(output_file, 'wb') as gunzip_data:
            gz_data.myfileobj.seek(-4, 2)
            isize = struct.unpack('I', gz_data.myfileobj.read(4))[0]
            gz_data.myfileobj.seek(0)

            done = 0
            copy_chunk = 131072
            while 1:
                chunk = gz_data.read(copy_chunk)
                if not chunk:
                    break
                gunzip_data.write(chunk)
                done += len(chunk)

                progress_bar(f"{layer_id_short}: Extracting", isize, done)

        os.remove(gziped_file)
        print("\r{}: Pull complete {}".format(layer_id_short, " " * 100), flush=True)

    def pull(self, image: str, arch: str = 'amd64'):
        tag_digest = None
        image_os = 'linux'

        reg, ns, tag = self.parser(image)
        url = self._make_url(reg, ns)

        print(f'{tag}: Pulling from {ns}')
        manifests_list = self.get_manifest_list(url, tag)
        manifests_list_data = manifests_list.json()
        logging.debug(f'Manifest list headers: {manifests_list.headers}')

        for manifest in manifests_list_data.get('manifests', []):
            if manifest['platform']['architecture'] == arch:
                tag_digest = manifest['digest']
                image_os = manifest['platform']['os']
                break

        image_manifest_res = self.get_manifest(url, tag_digest or tag)
        logging.debug(f'Image manifest headers: {tag_digest or tag}: {image_manifest_res.headers}')
        image_manifest = image_manifest_res.json()

        image_id = image_manifest['config']['digest']
        image_name = '{}_{}'.format(ns.replace('/', '_'), tag.replace(':', '_'))
        tmp_dir = f'{image_name}.tmp'

        config_filename = f'{image_id[7:]}.json'
        image_repo = ns.replace('library/', '') if ns.startswith('library/') and reg == DOCKER_REGISTRY_HOST else ns

        saver = FileExporter(tmp_dir)

        image_config = self.get_blob(url, image_id)
        logging.debug(f'Image config headers: {image_id}: {image_config.headers}')
        with saver(config_filename) as f:
            f.write(image_config.content)

        image_config = image_config.json(object_pairs_hook=OrderedDict, cls=JSONDecoderRawString)
        diff_ids = image_config['rootfs']['diff_ids']

        layers = image_manifest['layers']
        if len(layers) != len(diff_ids):
            raise Exception("The number of layers is not equal to the number of diff_ids")

        chain_ids_list = chain_ids(diff_ids)
        v1_layer_ids_list = v1_layers_ids(chain_ids_list, image_config)

        man = self.empty_manifest
        man[0]['Config'] = config_filename
        man[0]['RepoTags'].append(f'{image_repo}:{tag}')

        v1_layer_id = ''
        parent_id = ''
        for i, layer_info in enumerate(layers):
            last_layer = layer_info == layers[-1]
            v1_layer_id = v1_layer_ids_list[i][7:]

            man[0]['Layers'].append(f'{v1_layer_id}/layer.tar')
            layer_tar = saver.path_join(v1_layer_id, 'layer.tar')

            self._get_layer(url, layer_info['digest'], diff_ids[i], layer_tar)

            layer_json = OrderedDict(id=v1_layer_id)
            if parent_id:
                layer_json['parent'] = parent_id

            layer_json.update(self.empty_layer_json(image_os=image_os, last_layer=last_layer))

            if last_layer:
                layer_json.update(image_config)

                del layer_json['history']
                del layer_json['rootfs']

            with saver(v1_layer_id, "json") as f:
                f.write(json.dumps(layer_json, separators=JSON_SEPARATOR, ensure_ascii=False).replace(r'\\u', r'\u'))

            with saver(v1_layer_id, "VERSION") as f:
                f.write("1.0")

            parent_id = v1_layer_id

        print('Digest:', image_manifest_res.headers.get('Docker-Content-Digest'))

        with saver("manifest.json") as f:
            f.write(json.dumps(man, separators=JSON_SEPARATOR))
            f.write('\n')

        with saver("repositories") as f:
            f.write(json.dumps({image_repo: {tag: v1_layer_id}}, separators=JSON_SEPARATOR))
            f.write('\n')

        with TarFile.open(f'{image_name}.tar', 'w', remove_src_dir=not self._save_cache) as tar:
            tar.add(tmp_dir, created=image_config['created'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='docker_pull.py',
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=36,
                                                                                         width=93))
    parser.add_argument('image', nargs='+')
    parser.add_argument('--save-cache', '-s', action='store_true',
                        help="Do not delete the temp folder after downloading the image")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable verbose output")
    parser.add_argument('--user', '-u', type=str, help="Registry login")
    parser.add_argument('--password', '-p', type=str, help="Registry password")
    arg = parser.parse_args()

    p = ImageFetcher(user=arg.user, password=arg.password, verbose=arg.verbose, save_cache=arg.save_cache)
    for img in arg.image:
        p.pull(img)
