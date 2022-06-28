#!/usr/bin/env python3

import argparse
import dataclasses
import datetime
import getpass
import gzip
import hashlib
import json
import logging
import os
import platform
import shutil
import struct
import tarfile
import typing
import urllib.parse as urlparse
from typing import List

import requests
import requests.auth
from dateutil.parser import parse as date_parse

JSON_SEPARATOR = (',', ':')
DOCKER_REGISTRY_HOST = 'registry-1.docker.io'


@dataclasses.dataclass
class ContainerConfig:
    Hostname: str = ''
    Domainname: str = ''
    User: str = ''
    AttachStdin: bool = False
    AttachStdout: bool = False
    AttachStderr: bool = False
    Tty: bool = False
    OpenStdin: bool = False
    StdinOnce: bool = False
    Env: list = None
    Cmd: list = None
    Image: str = ''
    Volumes: list = None
    WorkingDir: str = ''
    Entrypoint: list = None
    OnBuild: list = None
    Labels: dict = None


@dataclasses.dataclass
class StructClasses:
    @property
    def json(self) -> str:
        d = dataclasses.asdict(self)

        for field in dataclasses.fields(self):
            if field.metadata.get('omitempty') and d[field.name] is None:
                del d[field.name]

        return json.dumps(d, separators=JSON_SEPARATOR, ensure_ascii=False).replace(r'\\u', r'\u')

    def update(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)


@dataclasses.dataclass
class LayerConfig(StructClasses):
    architecture: str = dataclasses.field(default=None, metadata={'omitempty': True})
    comment: str = dataclasses.field(default=None, metadata={'omitempty': True})
    config: ContainerConfig = dataclasses.field(default=None, metadata={'omitempty': True})
    container: str = dataclasses.field(default=None, metadata={'omitempty': True})
    container_config: ContainerConfig = dataclasses.field(default=None, metadata={'omitempty': True})
    created: str = '1970-01-01T00:00:00Z'
    docker_version: str = dataclasses.field(default=None, metadata={'omitempty': True})
    layer_id: str = None
    os: str = dataclasses.field(default=None, metadata={'omitempty': True})
    parent: str = dataclasses.field(default=None, metadata={'omitempty': True})


@dataclasses.dataclass
class V1Image(StructClasses):
    id: str = dataclasses.field(default=None, metadata={'omitempty': True})
    parent: str = dataclasses.field(default=None, metadata={'omitempty': True})
    comment: str = dataclasses.field(default=None, metadata={'omitempty': True})
    created: str = '1970-01-01T00:00:00Z'
    container: str = dataclasses.field(default=None, metadata={'omitempty': True})
    container_config: ContainerConfig = dataclasses.field(default=None, metadata={'omitempty': True})
    docker_version: str = dataclasses.field(default=None, metadata={'omitempty': True})
    author: str = dataclasses.field(default=None, metadata={'omitempty': True})
    config: ContainerConfig = dataclasses.field(default=None, metadata={'omitempty': True})
    architecture: str = dataclasses.field(default=None, metadata={'omitempty': True})
    variant: str = dataclasses.field(default=None, metadata={'omitempty': True})
    os: str = dataclasses.field(default='linux', metadata={'omitempty': True})
    size: int = dataclasses.field(default=None, metadata={'omitempty': True})


@dataclasses.dataclass
class RootFS:
    type: str
    diff_ids: List[str] = dataclasses.field(default_factory=list, metadata={'omitempty': True})


@dataclasses.dataclass
class Image(V1Image):
    rootfs: RootFS = dataclasses.field(default=None, metadata={'omitempty': True})
    history: List[str] = dataclasses.field(default_factory=list, metadata={'omitempty': True})
    # os.version: str  # omitempty
    # os.features: List[str]  # omitempty


@dataclasses.dataclass
class Manifest:
    Config: str = ''
    RepoTags: List[str] = dataclasses.field(default_factory=list)
    Layers: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ManifestList:
    manifests: List[Manifest] = dataclasses.field(default_factory=list)

    @property
    def json(self) -> str:
        r = []
        for m in self.manifests:
            r.append(dataclasses.asdict(m))

        return json.dumps(r, separators=JSON_SEPARATOR, ensure_ascii=False)


def chain_ids(ids_list: list) -> list:
    chain = list()
    chain.append(ids_list[0])

    if len(ids_list) < 2:
        return ids_list

    nxt = list()
    nxt.append("sha256:" + hashlib.sha256(f'{ids_list[0]} {ids_list[1]}'.encode()).hexdigest())
    nxt.extend(ids_list[2:])

    chain.extend(chain_ids(nxt))

    return chain


def layer_ids_list(chain_ids_list: list, config_image: dict):
    chan_ids = []
    parent = None

    if 'id' in config_image:
        del config_image['id']

    _info = dict(sorted(config_image.items()))
    for chain_id in chain_ids_list:
        config = LayerConfig(layer_id=chain_id, parent=parent)

        if chain_id == chain_ids_list[-1]:
            del _info['history']
            del _info['rootfs']

            config.update(**_info)

        else:
            config.container_config = ContainerConfig()

        parent = "sha256:" + hashlib.sha256(config.json.encode()).hexdigest()
        chan_ids.append(parent)

    return chan_ids


def image_name_parser(image: str) -> tuple:
    registry = ''
    tag = 'latest'

    idx = image.find('/')
    if idx > -1 and ('.' in image[:idx] or ':' in image[:idx]):
        registry = image[:idx]
        image = image[idx + 1:]

    idx = image.find('@')
    if idx > -1:
        tag = image[idx + 1:]
        image = image[:idx]

    idx = image.find(':')
    if idx > -1:
        tag = image[idx + 1:]
        image = image[:idx]

    idx = image.find('/')
    if idx == -1 and registry == '':
        image = 'library/' + image

    return registry or DOCKER_REGISTRY_HOST, image, tag


def www_auth(hdr: str) -> dict:
    ret = {}

    auth_type, info = hdr.split(' ', 1)
    auth_type = auth_type.lower()
    ret[auth_type] = {}

    for part in info.split(','):
        k, v = part.split('=', 1)
        ret[auth_type][k] = v.lower().replace('"', '')

    return ret


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
    for unit in ['B', 'KiB', 'MiB', 'GiB']:
        if abs(num) < 1024:
            return f'{num:3.1f}{unit}'
        num /= 1024

    return f'{num:3.1f}TiB'


def progress_bar(description, content_length, done, progressbar_length=50):
    # TODO: shutil.get_terminal_size((80, 20))
    if not content_length:
        content_length = done

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
        super().__init__(name, mode, fileobj, **kwargs)
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

    def _req(self, url, *, method='GET', headers: dict = None, stream: bool = None):
        r = self._session.request(method, url, headers=headers, stream=stream)
        if r.status_code == requests.codes.unauthorized:
            self._auth(r)
            r = self._session.request(method, url, headers=headers, stream=stream)

        logging.debug(f'Response headers: {r.headers}')
        if r.status_code != requests.codes.ok:
            logging.error(f'Response: {r.content}')
            r.raise_for_status()

        return r

    def _manifests_req(self, url: str, tag: str, media_type: str) -> requests.Response:
        return self._req(urlparse.urljoin(url, f'manifests/{tag}'), headers={'Accept': media_type})

    def get_manifest_list(self, url: str, tag: str, oci: bool = False) -> requests.Response:
        if oci:
            mt = 'application/vnd.oci.image.manifest.v1+json'
        else:
            mt = 'application/vnd.docker.distribution.manifest.list.v2+json'

        return self._manifests_req(url, tag, mt)

    def get_blob(self, url: str, tag: str, media_type: str, stream: bool = False) -> requests.Response:
        if stream:
            self._session.headers['Accept'] = media_type
        return self._req(urlparse.urljoin(url, f'blobs/{tag}'), stream=stream)

    def _get_layer(self, url, layer_digest, media_type, diff_id, output_file):
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

        r = self.get_blob(url, layer_digest, media_type, stream=True)
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

    def pull(self, image: str, image_platform: str):
        if image_platform:
            image_os, image_arch = image_platform.split('/')
        else:
            image_os, image_arch = 'linux', platform.machine()

        reg, ns, tag = image_name_parser(image)
        url = self._make_url(reg, ns)

        print(f'{tag}: Pulling from {ns}')
        manifests_list = self.get_manifest_list(url, tag)
        manifests_list_data = manifests_list.json()
        logging.debug(f'Manifest list headers: {manifests_list.headers}')

        tag_digest = None
        media_type = 'application/vnd.docker.distribution.manifest.v2+json'
        for manifest in manifests_list_data.get('manifests', []):
            if manifest['platform']['architecture'] == image_arch:
                tag_digest = manifest['digest']
                media_type = manifest['mediaType']
                break

        image_manifest_res = self._manifests_req(url, tag_digest or tag, media_type)
        logging.debug(f'Image manifest headers: {tag_digest or tag}: {image_manifest_res.headers}')
        image_manifest = image_manifest_res.json()
        logging.debug(image_manifest)

        image_id = image_manifest['config']['digest']
        image_name = '{}_{}_{}'.format(ns.replace('/', '_'), image_arch, tag.replace(':', '_'))
        tmp_dir = f'{image_name}.tmp'

        config_filename = f'{image_id[7:]}.json'
        image_repo = ns.replace('library/', '') if ns.startswith('library/') and reg == DOCKER_REGISTRY_HOST else ns

        saver = FileExporter(tmp_dir)

        image_config = self.get_blob(url, image_id, media_type)
        logging.debug(f'Image config headers: {image_id}: {image_config.headers}')
        with saver(config_filename) as f:
            f.write(image_config.content)

        image_config = image_config.json()
        diff_ids = image_config['rootfs']['diff_ids']

        layers = image_manifest['layers']
        if len(layers) != len(diff_ids):
            raise Exception("The number of layers is not equal to the number of diff_ids")

        chain_ids_list = chain_ids(diff_ids)
        v1_layer_ids_list = layer_ids_list(chain_ids_list, image_config)

        m0 = Manifest(Config=config_filename)
        m0.RepoTags.append(f'{image_repo}:{tag}')

        v1_layer_id = None
        parent_id = None
        for i, layer_info in enumerate(layers):
            v1_layer_id = v1_layer_ids_list[i][7:]

            m0.Layers.append(f'{v1_layer_id}/layer.tar')
            layer_tar = saver.path_join(v1_layer_id, 'layer.tar')

            self._get_layer(url, layer_info['digest'], layer_info['mediaType'], diff_ids[i], layer_tar)

            v1_layer_info = V1Image(
                id=v1_layer_id,
                parent=parent_id,
                os=image_os
            )

            if layer_info == layers[-1]:
                v1_layer_info.update(**image_config)
            else:
                v1_layer_info.container_config = ContainerConfig()

            with saver(v1_layer_id, "json") as f:
                f.write(v1_layer_info.json)

            with saver(v1_layer_id, "VERSION") as f:
                f.write("1.0")

            parent_id = v1_layer_id

        print('Digest:', image_manifest_res.headers.get('Docker-Content-Digest'), "\n")

        images_manifest_list = ManifestList()
        images_manifest_list.manifests.append(m0)

        with saver("manifest.json") as f:
            f.write(images_manifest_list.json)
            f.write('\n')

        with saver("repositories") as f:
            f.write(json.dumps({image_repo: {tag: v1_layer_id}}, separators=JSON_SEPARATOR))
            f.write('\n')

        with TarFile.open(f'{image_name}.tar', 'w', remove_src_dir=not self._save_cache) as tar:
            tar.add(tmp_dir, created=image_config['created'])

        os.chmod(f'{image_name}.tar', 0o600)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='docker_pull.py',
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=36, width=93))

    parser.add_argument('image', nargs='+')
    parser.add_argument('--save-cache', '-s', action='store_true',
                        help="Do not delete the temp folder after downloading the image")
    parser.add_argument('--verbose', '-v', action='store_true', help="Enable verbose output")
    parser.add_argument('--user', '-u', type=str, help="Registry login")
    # TODO: not implemented
    # parser.add_argument('--oci', action='store_true', help="Use OCI Image Spec")
    parser.add_argument('--platform', type=str, help="Set platform if server is multi-platform capable")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument('--password', '-p', type=str, help="Registry password")
    grp.add_argument('-P', action='store_true', help="Registry password (interactive)")
    arg = vars(parser.parse_args())

    if arg.pop('P'):
        arg['password'] = getpass.getpass()

    img_list = arg.pop('image')
    img_platform = arg.pop('platform')

    p = ImageFetcher(**arg)
    for img in img_list:
        p.pull(img, img_platform)
