Starting from version 25, docker saves images in oci format

# docker_pull
The script makes it possible to download a docker-image without docker

Required Python 3.10+

## Use
```bash
> git clone https://github.com/myback/docker_pull.git
> cd docker_pull
> chmod +x docker_pull.py
> ./docker_pull.py -h
usage: docker_pull.py [-h] [--output OUTPUT] [--save-cache] [--registry REGISTRY] [--user USER] [--platform PLATFORM]
                      [--silent | --verbose] [--password PASSWORD | --stdin-password]
                      images [images ...]

positional arguments:
  images

options:
  -h, --help                        show this help message and exit
  --output OUTPUT, -o OUTPUT        Output dir
  --save-cache                      Do not delete the temp folder
  --registry REGISTRY, -r REGISTRY  Registry
  --user USER, -u USER              Registry login
  --platform PLATFORM               Set platform for downloaded image
  --silent, -s                      Silent mode
  --verbose, -v                     Enable debug output
  --password PASSWORD, -p PASSWORD  Registry password
  --stdin-password, -P              Registry password (interactive)

> ./docker_pull.py alpine:3.17
3.17: Pulling from alpine
f56be85fc22e: Pull complete                                                                     
Digest: sha256:9ed4aefc74f6792b5a804d1d146fe4b4a2299147b0f50eaf2b08435d7b38c27e 
> docker pull --platform linux/amd64 alpine:3.17
> docker save alpine:3.17 -o output/alpine_3.17.tar
> sha256sum output/*.tar
c9b254e3e3645bc58fd622d9bd3cd44e3987837b42dfec65f133fb58ce34ff93  output/alpine_3.17.tar
c9b254e3e3645bc58fd622d9bd3cd44e3987837b42dfec65f133fb58ce34ff93  output/alpine_3.17_linux_amd64.tar
```
Fetch multiple images
```bash
> ./docker_pull.py alpine:3.10 ubuntu:18.04 bitnami/redis:5.0
```
Verbose
```bash
> ./docker_pull.py -v alpine
```
Fetch image from private registry
```bash
> ./docker_pull.py --registry private-registry.mydomain.com --user username --password 'P@$$w0rd' private-registry.mydomain.com/my_image:1.2.3
# or
> echo 'P@$$w0rd' | ./docker_pull.py --registry private-registry.mydomain.com --user username --stdin-password private-registry.mydomain.com/my_image:1.2.3
# or
> ./docker_pull.py --registry private-registry.mydomain.com --user username --stdin-password private-registry.mydomain.com/my_image:1.2.3
Password:
```
