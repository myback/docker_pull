# docker_pull
The script makes it possible to download a docker-image without docker

## Use
```bash
> git clone https://github.com/myback/docker_pull.git
> cd docker_pull
> chmod +x docker_pull.py
> ./docker_pull.py -h
usage: docker_pull.py [-h] [--save-cache] [--verbose] [--user USER] [--password PASSWORD]
                      image [image ...]

positional arguments:
  image

optional arguments:
  -h, --help                        show this help message and exit
  --save-cache, -s                  Do not delete the temp folder after downloading the image
  --verbose, -v                     Enable verbose output
  --user USER, -u USER              Registry login
  --password PASSWORD, -p PASSWORD  Registry password
>
> ./docker_pull.py alpine:3.10
3.10: Pulling from library/alpine
21c83c524219: Pull complete
Digest: sha256:a143f3ba578f79e2c7b3022c488e6e12a35836cd4a6eb9e363d7f3a07d848590
> docker pull alpine:3.10
> docker save alpine:3.10 -o alpine_3.10.tar
> sha256sum *.tar
d59b494721c87e7536ad6b68d9066b82b55b9697d89239adb56a6ba2878a042d  alpine_3.10.tar
d59b494721c87e7536ad6b68d9066b82b55b9697d89239adb56a6ba2878a042d  library_alpine_3.10.tar
```
Fetch multiple images
```bash
> ./docker_pull.py alpine:3.10 ubuntu:18.04 bitnami/redis:5.0
```
Verbose
```bash
> ./docker_pull.py -v alpine  # Same as alpine:latest
```
Fetch image from private registry
```bash
> ./docker_pull.py --user username --password 'P@$$w0rd' private-registry.mydomain.com/my_image:1.2.3
```
