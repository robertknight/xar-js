# Change Log

## [Unreleased]

### Fixed

- Calculate signature length by signing dummy data, rather than assuming
  a fixed size. Fixes signing when private key length is not 2048 bits.

  See https://github.com/robertknight/xar-js/issues/9

- Fixed an issue where `xarjs create` would fail to read input files
  outside of the current directory.

## [0.2.0]

Initial release
