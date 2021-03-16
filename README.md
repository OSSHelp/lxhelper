# LXHelper

[![Build Status](https://drone.osshelp.ru/api/badges/OSSHelp/lxhelper/status.svg)](https://drone.osshelp.ru/OSSHelp/lxhelper)

## About

This script is used with the lxd-functions library for LXD container deployment.

## Requirements

* Ubuntu Xenial/Bionic/Focal
* LXD client and accessible LXD server (2.15+, 3.x, 4.x)

There is also limited support for the following distributions:

* CentOS 7.x or newer
* Debian 8.x or newer

Mostly it should work but without any guarantees ;)

## How to use it

### Installtion

LXHelper is just a wrapper around lxd-functions.sh library. For deployment you need:

1. Place lxd-function.sh library in the `/usr/local/include/osshelp/` path
1. Place lxhelper script in the `/usr/local/sbin/` path
1. Place the container YAML config in the `/usr/local/etc/lxc/` path (see examples dir)

There’re install/update scripts in the repository. Command for installation (lxd-function.sh, lxhelper, yq and minio-client):

```shell
curl -s https://oss.help/scripts/lxc/lxhelper/install.sh | bash
```

### Options

LXHelper usage is described in the table below:

Action | Description| Usage
---|---|---
deploy-container |deploy one container from specified YAML config |`lxhelper deploy-container [-y=(URL|Path)] [--force] container_name`
deploy-containers |deploy all containers from specified YAML config | `lxhelper deploy-containers [-y=(URL|Path)] [--force]`
download-image|download container image with specified source URL in the YAML config |`lxhelper download-image [-y=(URL|Path)] container_name`
create-image|create image from the container with the same name or with specified name |`lxhelper create-image container_name [image_name]`
export-image|export specified image to archive|`lxhelper export-image image_name`
update-image|create and export container image from the container |`lxhelper update-image image_name`
update-configs|update all YAML configs in specified path (default path /usr/local/etc/lxc/) |`lxhelper update-configs [/path/to/dir]`

### Useful

LXHelper is tightly coupled with [deploy-functions](https://github.com/OSSHelp/deploy-functions) library, but it's still possible to use LXHelper without it.

## Author

OSSHelp Team, see <https://oss.help>
