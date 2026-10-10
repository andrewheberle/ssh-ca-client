# Changelog

## [0.23.0](https://github.com/andrewheberle/ssh-ca-client/compare/v0.22.1...v0.23.0) (2026-10-10)


### Features

* **krl:** reject a KRL older than the existing output file ([#88](https://github.com/andrewheberle/ssh-ca-client/issues/88)) ([8f5549d](https://github.com/andrewheberle/ssh-ca-client/commit/8f5549da2ab58e43b563125ecc3bf3d7e31986cc))
* **systemd:** add a timer to refresh the user KRL for sshd ([#92](https://github.com/andrewheberle/ssh-ca-client/issues/92)) ([4544373](https://github.com/andrewheberle/ssh-ca-client/commit/454437308b0b0dc6f3ead8f7e63f323cfa9a5bcd))


### Bug Fixes

* **cli:** report the verified KRL and deprecate krl --force ([#89](https://github.com/andrewheberle/ssh-ca-client/issues/89)) ([da50194](https://github.com/andrewheberle/ssh-ca-client/commit/da50194d5301bfb9e229a4c093e0d6fa5e60595b))
* include the CA's error messages in certificate request errors ([#91](https://github.com/andrewheberle/ssh-ca-client/issues/91)) ([c525807](https://github.com/andrewheberle/ssh-ca-client/commit/c525807a380ddac884eca6174055b37c49151579))
* **krl:** avoid nil pointer panics in Get and VerifyStrict ([#83](https://github.com/andrewheberle/ssh-ca-client/issues/83)) ([f1b6431](https://github.com/andrewheberle/ssh-ca-client/commit/f1b64314f59ceadc6f55b3f4d372e1ee69331f31))
* **krl:** pass context to Get and keep the default HTTP client ([#85](https://github.com/andrewheberle/ssh-ca-client/issues/85)) ([4038c2b](https://github.com/andrewheberle/ssh-ca-client/commit/4038c2b987f174a5700edef2af1eeef745c9d5a2))
* **krl:** verify the signature before parsing the KRL ([#86](https://github.com/andrewheberle/ssh-ca-client/issues/86)) ([b771164](https://github.com/andrewheberle/ssh-ca-client/commit/b7711645ff5f0012ca1d339ffc2fa1a4691c7a8d))
* **policy:** describe the trusted CA as required ([#90](https://github.com/andrewheberle/ssh-ca-client/issues/90)) ([b960c3e](https://github.com/andrewheberle/ssh-ca-client/commit/b960c3e658a7011ea351ce222c11633c243af169))

## [0.22.1](https://github.com/andrewheberle/ssh-ca-client/compare/v0.22.0...v0.22.1) (2026-10-09)


### Bug Fixes

* **deps:** update module github.com/knadh/koanf/v2 to v2.3.8 ([#65](https://github.com/andrewheberle/ssh-ca-client/issues/65)) ([c6deab6](https://github.com/andrewheberle/ssh-ca-client/commit/c6deab61ee4ccc02124f095d1095391a4ece03bd))
