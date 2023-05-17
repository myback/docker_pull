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
import platform as os_platform
import shutil
import struct
import sys
import tarfile
import urllib.parse as urlparse
from pathlib import Path

import requests
import requests.auth

JSON_SEPARATOR = (',', ':')


# based on json.decoder.py_scanstring
def raw_scanstring(s, end, strict=True, _b=json.decoder.BACKSLASH,
                   _m=json.decoder.STRINGCHUNK.match):
    chunks = []
    _append = chunks.append
    begin = end - 1
    while 1:
        chunk = _m(s, end)
        if chunk is None:
            raise json.JSONDecodeError("Unterminated string starting at",
                                       s, begin)
        end = chunk.end()
        content, terminator = chunk.groups()
        if content:
            _append(content)
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
            raise json.JSONDecodeError("Unterminated string starting at",
                                       s, begin) from None
        if esc != 'u':
            try:
                char = _b[esc]
            except KeyError:
                msg = "Invalid \\escape: {0!r}".format(esc)
                raise json.JSONDecodeError(msg, s, end)
            end += 1
        else:
            # deleted unicode parsing code
            st = end - 1
            end += 5
            char = s[st:end]
        _append(char)
    return ''.join(chunks), end


class JSONDecoderRawString(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parse_string = raw_scanstring
        self.scan_once = json.scanner.py_make_scanner(self)


class StructClassesJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            res = []
            for f in dataclasses.fields(o):
                value = getattr(o, f.name)
                if not (f.metadata.get('omitempty') and not value):
                    res.append((f.name, value))

            return dict(res)
        return super().default(o)


@dataclasses.dataclass
class StructClasses:
    @property
    def json(self) -> str:
        j = json.dumps(self, cls=StructClassesJSONEncoder,
                       separators=JSON_SEPARATOR)

        return j.replace(r'\\u', r'\u')

    def _update(self, o, kwargs):
        for k, v in kwargs.items():
            if hasattr(o, k):
                _o = getattr(o, k)
                if dataclasses.is_dataclass(_o):
                    _v = type(_o)()
                    self._update(_v, v)
                    v = _v

                setattr(o, k, v)

    def deepcopy(self, kwargs):
        self._update(self, kwargs)


@dataclasses.dataclass
class HealthConfig(StructClasses):
    Test: list[str] = dataclasses.field(default_factory=list,
                                        metadata={'omitempty': True})
    Interval: str = dataclasses.field(default='',
                                      metadata={'omitempty': True})
    Timeout: str = dataclasses.field(default='',
                                     metadata={'omitempty': True})
    StartPeriod: str = dataclasses.field(default='',
                                         metadata={'omitempty': True})
    Retries: int = dataclasses.field(default=0,
                                     metadata={'omitempty': True})


@dataclasses.dataclass
class ContainerConfig(StructClasses):
    Hostname: str = dataclasses.field(default='')
    Domainname: str = dataclasses.field(default='')
    User: str = dataclasses.field(default='')
    AttachStdin: bool = dataclasses.field(default=False)
    AttachStdout: bool = dataclasses.field(default=False)
    AttachStderr: bool = dataclasses.field(default=False)
    ExposedPorts: dict = dataclasses.field(default=None,
                                           metadata={'omitempty': True})
    Tty: bool = dataclasses.field(default=False)
    OpenStdin: bool = dataclasses.field(default=False)
    StdinOnce: bool = dataclasses.field(default=False)
    Env: list = dataclasses.field(default=None)
    Cmd: list = dataclasses.field(default=None)
    Healthcheck: HealthConfig = dataclasses.field(default=None,
                                                  metadata={'omitempty': True})
    ArgsEscaped: bool = dataclasses.field(default=False,
                                          metadata={'omitempty': True})
    Image: str = dataclasses.field(default='')
    Volumes: dict = dataclasses.field(default=None)
    WorkingDir: str = dataclasses.field(default='')
    Entrypoint: list = dataclasses.field(default=None)
    NetworkDisabled: bool = dataclasses.field(default=False,
                                              metadata={'omitempty': True})
    MacAddress: str = dataclasses.field(default='',
                                        metadata={'omitempty': True})
    OnBuild: list = dataclasses.field(default=None)
    Labels: dict = dataclasses.field(default=None)
    StopSignal: str = dataclasses.field(default='',
                                        metadata={'omitempty': True})
    StopTimeout: int = dataclasses.field(default=0,
                                         metadata={'omitempty': True})
    Shell: list = dataclasses.field(default=None,
                                    metadata={'omitempty': True})


@dataclasses.dataclass
class LayerConfig(StructClasses):
    architecture: str = dataclasses.field(default=None,
                                          metadata={'omitempty': True})
    comment: str = dataclasses.field(default=None,
                                     metadata={'omitempty': True})
    config: ContainerConfig = dataclasses.field(default=None,
                                                metadata={'omitempty': True})
    container: str = dataclasses.field(default=None,
                                       metadata={'omitempty': True})
    container_config: ContainerConfig = dataclasses.field(
        default=None, metadata={'omitempty': True})
    created: str = dataclasses.field(default='1970-01-01T00:00:00Z')
    docker_version: str = dataclasses.field(default=None,
                                            metadata={'omitempty': True})
    layer_id: str = dataclasses.field(default='')
    os: str = dataclasses.field(default=None, metadata={'omitempty': True})
    parent: str = dataclasses.field(default=None, metadata={'omitempty': True})


@dataclasses.dataclass
class V1Image(StructClasses):
    id: str = dataclasses.field(default=None, metadata={'omitempty': True})
    parent: str = dataclasses.field(default=None, metadata={'omitempty': True})
    comment: str = dataclasses.field(default=None,
                                     metadata={'omitempty': True})
    created: str = '1970-01-01T00:00:00Z'
    container: str = dataclasses.field(default=None,
                                       metadata={'omitempty': True})
    container_config: ContainerConfig = dataclasses.field(
        default=None, metadata={'omitempty': True})
    docker_version: str = dataclasses.field(default=None,
                                            metadata={'omitempty': True})
    author: str = dataclasses.field(default=None, metadata={'omitempty': True})
    config: ContainerConfig = dataclasses.field(default=None,
                                                metadata={'omitempty': True})
    architecture: str = dataclasses.field(default=None,
                                          metadata={'omitempty': True})
    variant: str = dataclasses.field(default=None,
                                     metadata={'omitempty': True})
    os: str = dataclasses.field(default='linux', metadata={'omitempty': True})
    size: int = dataclasses.field(default=None, metadata={'omitempty': True})


@dataclasses.dataclass
class RootFS:
    type: str
    diff_ids: list[str] = dataclasses.field(default_factory=list,
                                            metadata={'omitempty': True})


@dataclasses.dataclass
class Image(V1Image):
    rootfs: RootFS = dataclasses.field(default=None,
                                       metadata={'omitempty': True})
    history: list[str] = dataclasses.field(default_factory=list,
                                           metadata={'omitempty': True})


@dataclasses.dataclass
class Manifest:
    Config: str = ''
    RepoTags: list[str] = dataclasses.field(default_factory=list)
    Layers: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ManifestList:
    manifests: list[Manifest] = dataclasses.field(default_factory=list)

    @property
    def json(self) -> str:
        r = []
        for m in self.manifests:
            r.append(dataclasses.asdict(m))

        return json.dumps(r, separators=JSON_SEPARATOR, ensure_ascii=False)


class FilesManager:
    def __init__(self, work_dir: str | Path):
        if isinstance(work_dir, str):
            work_dir = Path(work_dir)
        self._work_dir = work_dir
        self._work_dir.mkdir(0o755, True, True)

    def __call__(self, path: str):
        return FilesManager(self._join_path(Path(path)))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def _join_path(self, p: Path) -> Path:
        path = self._work_dir.joinpath(p)
        path.resolve().relative_to(p.parent.resolve())

        return path

    def filepath(self, name: str) -> Path:
        return self._join_path(Path(name))

    def write(self, name: str, data: str | bytes):
        mode = 'w'
        if isinstance(data, bytes):
            mode = 'wb'

        with self.open(name, mode) as f:
            f.write(data)

    def open(self, name: str | Path, mode='r', buffering=-1, encoding=None,
             errors=None, newline=None):
        if isinstance(name, str):
            name = Path(name)

        path = self._join_path(name)
        if 'w' in mode:
            path.parent.mkdir(0o755, True, True)

        return path.open(mode, buffering, encoding, errors, newline)

    @property
    def work_dir(self) -> Path:
        return self._work_dir.resolve()


class EmptyProgressBar:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, item):
        def func(*args, **kwargs):
            pass

        return func


class ProgressBar:
    def __init__(self, progressbar_length: int = 96):
        self._end = '\r'
        self._description = ''
        self._content_sizeof_fmt = '0'
        self._content_size = 0
        self._progressbar_length = progressbar_length

    def set_size(self, size: int):
        self._content_sizeof_fmt = sizeof_fmt(size)
        self._content_size = size
        self._end = '\r'

        return self

    def update_description(self, s: str):
        self._description = s
        self._end = '\r'

        return self

    def flush(self, description: str):
        self.set_size(0)
        self.update_description(description)
        self._end = '\n'
        self.write(self._content_size)

    def write(self, done: int):
        size_fmt_length = 18
        fill = progressbar_fill_length = self._progressbar_length - \
                                         (4 + len(self._description) + size_fmt_length)

        if self._content_size:
            fill = int(progressbar_fill_length * done / self._content_size)

        fill_suffix = '=' if progressbar_fill_length == fill else '>'
        progressbar_fill = '=' * (fill - 1) + fill_suffix

        if done and self._content_sizeof_fmt:
            tmpl = "{} [{:<{length}}] {:>{sizes}}"
            sizes = f'{sizeof_fmt(done)}/{self._content_sizeof_fmt}'
            progress_bar_str = tmpl.format(self._description,
                                           progressbar_fill,
                                           sizes,
                                           length=progressbar_fill_length,
                                           sizes=size_fmt_length)
        else:
            fill = self._progressbar_length - len(self._description)
            progress_bar_str = f'{self._description}{" " * fill}'

        print(progress_bar_str, end=self._end, flush=True)


class Registry:
    def __init__(self, credentials: requests.auth.HTTPBasicAuth = None, ssl: bool = True):
        self.__credentials = credentials
        self._ssl = ssl
        self._session = requests.Session()

    def _auth(self, resp: requests.Response):
        if not resp.headers.get('www-authenticate'):
            raise ValueError("empty the www-authenticate header")

        auth_scheme, parsed = www_auth(resp.headers['www-authenticate'])
        if auth_scheme.lower() == 'basic':
            self.__credentials(self._session)
            return

        url_parts = list(urlparse.urlparse(parsed['realm']))

        query = urlparse.parse_qs(url_parts[4])
        query.update(service=parsed['service'])
        scope = parsed.get('scope')
        if scope:
            query.update(scope=scope)

        url_parts[4] = urlparse.urlencode(query, True)

        r = self._session.get(urlparse.urlunparse(url_parts),
                              auth=self.__credentials)
        r.raise_for_status()

        a_str = f"{auth_scheme} {r.json()['token']}"
        self._session.headers['Authorization'] = a_str

    def get(self, url: str, *,
            headers: dict = None, stream: bool = None) -> requests.Response:
        if not url.startswith('http'):
            url = f"http{'s' if self._ssl else ''}://{url}"

        logging.debug('Request headers: %s', json.dumps(headers))
        r = self._session.get(url, headers=headers, stream=stream)
        if r.status_code == requests.codes.unauthorized:
            self._auth(r)
            r = self._session.get(url, headers=headers, stream=stream)

        if r.status_code != requests.codes.ok:
            logging.error(
                f'Status code: {r.status_code}, Response: {r.content}')
            r.raise_for_status()

        logging.debug('Response headers: %s', json.dumps(r.headers.__dict__))
        if not stream:
            logging.debug('Response body: %s', r.content)

        return r

    def fetch_blob(self, url: str, out_file: Path, *,
                   sha256: str = None,
                   headers: dict = None,
                   progress: ProgressBar = EmptyProgressBar()):

        mode = 'wb'
        done = 0
        layer_id_short = os.path.basename(url)[7:19]
        temp_file = out_file.with_suffix('.gz')

        if temp_file.exists():
            done = temp_file.stat().st_size
            if done:
                logging.debug(f'resume download layer blob "{temp_file}"')
                mode = 'ab'

            if sha256sum(temp_file) == sha256:
                if progress:
                    progress.flush(f'{layer_id_short}: Pull complete')

                logging.debug(f'File {temp_file} is up to date')
                return

            headers['Range'] = f'bytes={done}-'

        progress.update_description(f'{layer_id_short}: Pulling fs layer')
        progress.set_size(0)
        progress.write(0)

        r = self.get(url, headers=headers, stream=True)

        progress.update_description(f'{layer_id_short}: Downloading')
        progress.set_size(int(r.headers.get('Content-Length', 0)))

        with open(temp_file, mode) as f:
            for chunk in r.iter_content(chunk_size=131072):
                if chunk:
                    f.write(chunk)
                    done += len(chunk)

                    if progress:
                        progress.write(done)

        progress.update_description(f'{layer_id_short}: Extracting')

        unzip(temp_file, out_file, progress=progress)

        progress.flush(f'{layer_id_short}: Pull complete')


class TarInfo(tarfile.TarInfo):
    @staticmethod
    def _create_header(info, fmt, encoding, errors):
        o_type = info.get('type', tarfile.REGTYPE)
        oct_mode = 0o100000 if o_type == tarfile.REGTYPE else 0o40000
        mode = info.get('mode', 0) | oct_mode

        parts = [
            tarfile.stn(info.get("name", ""), 100, encoding, errors),
            tarfile.itn(mode, 8, fmt),
            tarfile.itn(info.get("uid", 0), 8, fmt),
            tarfile.itn(info.get("gid", 0), 8, fmt),
            tarfile.itn(info.get("size", 0), 12, fmt),
            tarfile.itn(info.get("mtime", 0), 12, fmt),
            b" " * 8,  # checksum field
            o_type,
            tarfile.stn(info.get("linkname", ""), 100, encoding, errors),
            info.get("magic", tarfile.POSIX_MAGIC),
            tarfile.stn(info.get("uname", ""), 32, encoding, errors),
            tarfile.stn(info.get("gname", ""), 32, encoding, errors),
            tarfile.itn(info.get("devmajor", 0), 8, fmt),
            tarfile.itn(info.get("devminor", 0), 8, fmt),
            tarfile.stn(info.get("prefix", ""), 155, encoding, errors)
        ]

        buf = struct.pack("%ds" % tarfile.BLOCKSIZE, b"".join(parts))
        chksum = tarfile.calc_chksums(buf[-tarfile.BLOCKSIZE:])[0]
        buf = buf[:-364] + bytes("%06o\0" % chksum, "ascii") + buf[-357:]
        return buf


def chain_ids(ids_list: list) -> list[str]:
    chain = list()
    chain.append(ids_list[0])

    if len(ids_list) < 2:
        return ids_list

    nxt = list()
    chain_b = f'{ids_list[0]} {ids_list[1]}'.encode()
    nxt.append("sha256:" + hashlib.sha256(chain_b).hexdigest())
    nxt.extend(ids_list[2:])

    chain.extend(chain_ids(nxt))

    return chain


def layer_ids_list(chain_ids_list: list, config_image: dict) -> list[str]:
    config_image.pop('id', '')

    chan_ids = []
    parent = None
    for chain_id in chain_ids_list:
        config = LayerConfig(layer_id=chain_id, parent=parent)

        config.container_config = ContainerConfig()
        if chain_id == chain_ids_list[-1]:
            config.config = ContainerConfig()
            config.deepcopy(config_image)

        parent = "sha256:" + hashlib.sha256(config.json.encode()).hexdigest()
        chan_ids.append(parent)

    return chan_ids


def date_parse(s: str) -> datetime.datetime:
    layout = '%Y-%m-%dT%H:%M:%S.%f%z'

    # remove Z at the end of the line
    if s.endswith('Z'):
        s = s[:-1]

    nano_s = 0
    datetime_parts = s.split('.')
    if len(datetime_parts) == 2:
        nano_s = datetime_parts[-1]
        # cut nanoseconds to microseconds
        if len(nano_s) > 6:
            nano_s = nano_s[:6]

    dt = "{}.{}+00:00".format(datetime_parts[0], nano_s)

    return datetime.datetime.strptime(dt, layout)


def www_auth(hdr: str) -> tuple[str, dict]:
    auth_scheme, info = hdr.split(' ', 1)

    out = {}
    for part in info.split(','):
        k, v = part.split('=', 1)
        out[k] = v.replace('"', '').strip()

    return auth_scheme, out


def sha256sum(name: str | Path, chunk_num_blocks: int = 128) -> str:
    h = hashlib.sha256()

    with open(name, 'rb', buffering=0) as f:
        while chunk := f.read(chunk_num_blocks * h.block_size):
            h.update(chunk)

    return h.hexdigest()


def sizeof_fmt(num: int) -> str:
    for unit in ['B', 'KiB', 'MiB', 'GiB']:
        if abs(num) < 1024.:
            return f'{num:3.1f}{unit}'
        num /= 1024.

    return f'{num:3.2f}TiB'


def image_platform(s: str) -> tuple[str, str]:
    _os, arch = 'linux', os_platform.machine()
    if s:
        _os, arch = s.split('/')

    return _os, arch


def unzip(zip_file_path: str | Path,
          out_file_path: str | Path,
          remove_zip_file: bool = True,
          progress: ProgressBar = EmptyProgressBar()):
    with gzip.open(zip_file_path, 'rb') as zip_data, \
            open(out_file_path, 'wb') as unzip_data:
        zip_data.myfileobj.seek(-4, 2)
        size_bytes = zip_data.myfileobj.read(4)
        zip_data.myfileobj.seek(0)

        progress.set_size(struct.unpack('I', size_bytes)[0])

        done = 0
        while chunk := zip_data.read(131072):
            unzip_data.write(chunk)
            done += len(chunk)

            progress.write(done)

    if remove_zip_file:
        os.remove(zip_file_path)


def make_tar(out_path: Path, path: Path, created: float):
    tar = tarfile.open(out_path, 'w')
    tar.tarinfo = TarInfo
    tar.format = tarfile.USTAR_FORMAT
    tarfile.RECORDSIZE = 512

    def mod(t: tarfile.TarInfo):
        t.uid = 0
        t.gid = 0
        t.uname = ''
        t.gname = ''

        if t.name in ['manifest.json', 'repositories']:
            t.mtime = 0
        else:
            t.mtime = created

        return t

    walk = []
    for d in path.iterdir():
        walk.append(d)

    for d in sorted(walk):
        tar.add(str(d.resolve()), str(d.relative_to(path)), filter=mod)

    tar.close()


class ImageParser:
    REGISTRY_HOST = 'registry-1.docker.io'
    REGISTRY_IMAGE_PREFIX = 'library'
    DEFAULT_IMAGE_TAG = 'latest'

    def __init__(self, image: str):
        self._registry = None
        self._image = None
        self._tag = None
        self._digest = None
        self._manifest_digest = None

        self._from_string(image)

    def __str__(self):
        return f'{self.registry}/{self.image}:{self.image_digest or self.tag}'

    def _from_string(self, image: str):
        registry = self.REGISTRY_HOST
        tag = self.DEFAULT_IMAGE_TAG

        idx = image.find('/')
        if idx > -1 and ('.' in image[:idx] or ':' in image[:idx]):
            registry = image[:idx]
            image = image[idx + 1:]

        idx = image.find('@')
        if idx > -1:
            self._manifest_digest = tag = image[idx + 1:]
            image = image[:idx]

        idx = image.find(':')
        if idx > -1:
            tag = image[idx + 1:]
            image = image[:idx]

        self._registry = registry
        self._image = image
        if not self._manifest_digest:
            self._tag = tag

    def _url(self, typ: str, tag: str):
        image = self.image
        idx = image.find('/')
        if idx == -1 and self.registry == self.REGISTRY_HOST:
            image = os.path.join(self.REGISTRY_IMAGE_PREFIX, image)

        return f'{self._registry}/v2/{image}/{typ}/{tag}'

    @property
    def url_manifests(self):
        return self._url('manifests', self._manifest_digest or self._tag)

    @property
    def url_config_image(self):
        return self.url_blobs(self._digest or self._tag)

    def url_blobs(self, layer_digest: str):
        return self._url('blobs', layer_digest)

    @property
    def image_digest(self):
        return self._digest

    @property
    def manifest_digest(self):
        return self._manifest_digest

    @property
    def image(self):
        return self._image

    @property
    def registry(self):
        return self._registry

    @property
    def tag(self):
        return self._tag

    def set_manifest_digest(self, dig: str):
        self._manifest_digest = dig

    def set_image_digest(self, dig: str):
        self._digest = dig


class ImageFetcher:
    __LST_MTYPE = 'application/vnd.docker.distribution.manifest.list.v2+json'

    def __init__(self,
                 work_dir: Path, *,
                 progress: ProgressBar = EmptyProgressBar(),
                 save_cache: bool = False):

        self.__registry_list: dict[str, Registry] = {}
        self._fsm = FilesManager(work_dir)
        self._save_cache = save_cache
        self.__progress_bar = progress

    def set_registry(self, registry: str, user: str = None,
                     password: str = None, ssl: bool = True):
        registry = registry.lstrip('https://').lstrip('http://')

        creds = requests.auth.HTTPBasicAuth(user, password) if user else None
        self.__registry_list[registry] = Registry(creds, ssl)

    def _get_registry(self, registry: str) -> Registry:
        return self.__registry_list.get(registry, Registry())

    def _fetch_image(self, img: ImageParser, media_type: str, dir_name: str):
        registry = self._get_registry(img.registry)
        saver = self._fsm(dir_name)

        # get image manifest
        image_manifest_resp = registry.get(img.url_manifests,
                                           headers={'Accept': media_type})
        image_manifest_spec = image_manifest_resp.json()

        if image_manifest_spec['schemaVersion'] == 1:
            raise ValueError("schema version 1 image manifest not supported")

        img.set_image_digest(image_manifest_spec['config']['digest'])

        # get image config
        image_config_resp = registry.get(img.url_config_image)
        image_config = image_config_resp.json(cls=JSONDecoderRawString)

        # save image config
        image_digest_hash = img.image_digest.split(":")[1]
        image_config_filename = f'{image_digest_hash}.json'
        saver.write(image_config_filename, image_config_resp.content)

        image_manifest = Manifest(Config=image_config_filename)
        if img.tag:
            image_manifest.RepoTags.append(f'{img.image}:{img.tag}')
        else:
            image_manifest.RepoTags = None

        # fetch all layers with metadata
        diff_ids = image_config['rootfs']['diff_ids']
        chain_ids_list = chain_ids(diff_ids)
        v1_layer_ids_list = layer_ids_list(chain_ids_list, image_config)

        v1_layer_id = None
        parent_id = None
        layers = image_manifest_spec['layers']
        for i, layer_info in enumerate(layers):
            v1_layer_id = v1_layer_ids_list[i][7:]
            image_manifest.Layers.append(f'{v1_layer_id}/layer.tar')

            v1_layer_info = V1Image(
                id=v1_layer_id,
                parent=parent_id,
                os=image_config['os'],
                container_config=ContainerConfig()
            )

            if layer_info == layers[-1]:
                v1_layer_info.config = ContainerConfig()
                v1_layer_info.deepcopy(image_config)

            with saver(v1_layer_id) as fw:
                headers = {'Accept': layer_info['mediaType']}
                registry.fetch_blob(img.url_blobs(layer_info['digest']),
                                    fw.filepath('layer.tar'),
                                    headers=headers,
                                    progress=self.__progress_bar)

                fw.write('json', v1_layer_info.json)
                fw.write('VERSION', '1.0')

            parent_id = v1_layer_id

        if img.tag:
            # https://github.com/moby/moby/issues/45440
            # docker didn't create this file when pulling image by digest, 
            # but podman created ¯\_(ツ)_/¯
            repos_legacy = {img.image: {img.tag: v1_layer_id}}
            data = json.dumps(repos_legacy, separators=JSON_SEPARATOR) + '\n'

            saver.write('repositories', data)

        images_manifest_list = ManifestList()
        images_manifest_list.manifests.append(image_manifest)
        saver.write("manifest.json", images_manifest_list.json + '\n')

        # Save layers with metadata to tar file
        filename = str(self._fsm.work_dir.joinpath(dir_name)) + '.tar'
        created = date_parse(image_config['created']).timestamp()

        make_tar(Path(filename), saver.work_dir, created)
        os.chmod(filename, 0o600)
        if not self._save_cache:
            shutil.rmtree(saver.work_dir)

    def pull(self, image: str, platform: str):
        img = ImageParser(image)
        registry = self._get_registry(img.registry)

        print(f'{img.tag}: Pulling from {img.image}')
        # get manifest list
        headers = {'Accept': self.__LST_MTYPE}
        manifest_list_resp = registry.get(img.url_manifests, headers=headers)
        manifest_list = manifest_list_resp.json()

        if not img.manifest_digest:
            for mfst in self._manifests(manifest_list, platform):
                img.set_manifest_digest(mfst['digest'])
                img_name_n = img.image.replace('/', '_')
                img_tag_n = img.tag.replace(':', '_')
                plf = mfst['platform']
                arch = plf['architecture']
                dir_name = f"{img_name_n}_{img_tag_n}_{plf['os']}_{arch}"

                self._fetch_image(img, mfst['mediaType'], dir_name)
        else:
            img_name_n = img.image.replace('/', '_')
            img_tag_n = img.manifest_digest.replace(':', '_').replace('@', '_')
            img_os, img_arch = image_platform(platform)
            dir_name = f"{img_name_n}_{img_tag_n}_{img_os}_{img_arch}"

            self._fetch_image(img, manifest_list['mediaType'], dir_name)

        print('Digest:', img.image_digest, "\n")

    def _manifests(self, manifest_list: dict, platform: str) -> list:
        img_os, img_arch = image_platform(platform)
        manifests = manifest_list.get('manifests', [])
        if manifest_list.get('schemaVersion') == 1:
            raise ValueError("schema version 1 image manifest not supported")

        if not img_os and not img_arch:
            return manifests

        out = []
        for mfst in manifests:
            plf = mfst['platform']

            if img_os and img_arch:
                if plf['os'] == img_os and plf['architecture'] == img_arch:
                    out.append(mfst)
                    break
            else:
                if plf['os'] == img_os or plf['architecture'] == img_arch:
                    out.append(mfst)

        return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='docker_pull.py',
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog,
            max_help_position=36,
            width=120
        ))

    parser.add_argument('images', nargs='+')

    parser.add_argument('--output', '-o', default="output", type=Path,
                        help="Output dir")
    parser.add_argument('--save-cache', action='store_true',
                        help="Do not delete the temp folder")
    parser.add_argument('--registry', '-r', type=str, help="Registry")
    parser.add_argument('--user', '-u', type=str, help="Registry login")
    parser.add_argument('--platform', type=str, default='linux/amd64',
                        help="Set platform for downloaded image")

    verbose_grp = parser.add_mutually_exclusive_group()
    verbose_grp.add_argument('--silent', '-s', action='store_true',
                             help="Silent mode")
    verbose_grp.add_argument('--verbose', '-v', action='store_true',
                             help="Enable debug output")

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument('--password', '-p', type=str, help="Registry password")
    grp.add_argument('--stdin-password', '-P', action='store_true',
                     help="Registry password (interactive)")
    parsed_args = parser.parse_args()

    if parsed_args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    if parsed_args.silent or parsed_args.verbose:
        progress = EmptyProgressBar()
    else:
        progress = ProgressBar()

    puller = ImageFetcher(
        parsed_args.output,
        progress=progress,
        save_cache=parsed_args.save_cache
    )

    if parsed_args.user:
        password = parsed_args.password
        if parsed_args.stdin_password:
            std = sys.stdin
            if sys.stdin.isatty():
                password = getpass.getpass()
            else:
                password = sys.stdin.readline().strip()

        puller.set_registry(
            parsed_args.registry or ImageParser.REGISTRY_HOST,
            parsed_args.user,
            password
        )

    for image in parsed_args.images:
        puller.pull(image, parsed_args.platform)
