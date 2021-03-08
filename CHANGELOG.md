# Changelog

## v1.38

* Added postdeploy tests support

## v1.37

* Fixed containers limiting bug (when profiles aren't exists)

## v1.35

* Added limiting support for containers to profiles

## v1.33

* Added LXD version check (minimum required version is 2.15)

## v1.32

* Added name, network and devices parameters supports to profiles

## v1.31

* Added used profile name pushing into the container for default-setup.local

## v1.23

* Added files download feature (for download section in the container yaml configuration file), works with S3 storage and HTTP protocol with authorization

## v1.22

* Added container image download feature without image import

## v1.17

* Added protection for containers which weren't deployed by lxhelper (lxhelper checks key config.user.deployed_from in the containers configs)

## v1.15

* Fixed warning when cpu.allowance was used in the container config
* Updated warning messages
* Added yaml syntax test
* Added check for null values in keys in the yaml config

## v1.14

* Added warning for absented CPU/RAM limits in the container config

## v1.10

* Fixed bug in push_profile function

## v1.09

* Fixed bug when used limits with a dot in the name (e.g. cpu.allowance)
* Added drives limiting feature (mounting folders)

## v1.08

* Fixed bug with broken permissions for mounted directories (remade mount_directories_to_container function)
* Optimized information messages output for mount_directories_to_container function call
