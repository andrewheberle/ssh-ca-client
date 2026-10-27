# Changelog

## [0.26.0](https://github.com/andrewheberle/ssh-ca-client/compare/v0.25.4...v0.26.0) (2026-10-27)


### Bug Fixes

* **windows:** load config when registry keys are absent and align GPO value names ([#137](https://github.com/andrewheberle/ssh-ca-client/issues/137)) ([57f28fe](https://github.com/andrewheberle/ssh-ca-client/commit/57f28fe078ec1d4187623cb9ad1c53fd0ac3df20))


### Miscellaneous Chores

* force release v0.26.0 ([#139](https://github.com/andrewheberle/ssh-ca-client/issues/139)) ([da48ef5](https://github.com/andrewheberle/ssh-ca-client/commit/da48ef50dc697f2dc9d5cdfdb68600333d18e91a))

## [0.25.4](https://github.com/andrewheberle/ssh-ca-client/compare/v0.25.3...v0.25.4) (2026-10-25)


### Bug Fixes

* **deps:** update module golang.org/x/crypto to v0.58.0 ([#35](https://github.com/andrewheberle/ssh-ca-client/issues/35)) ([98b775e](https://github.com/andrewheberle/ssh-ca-client/commit/98b775e3cff01cb6830f1c62c4ab3a4a060df6d9))
* **msi:** resolve issue that prevented MSI build being added to last release ([62b507f](https://github.com/andrewheberle/ssh-ca-client/commit/62b507fd0e7bcc562225c475da3e1746a5785f36))

## [0.25.3](https://github.com/andrewheberle/ssh-ca-client/compare/v0.25.2...v0.25.3) (2026-10-25)


### Bug Fixes

* **auth:** log login server error received during shutdown ([#129](https://github.com/andrewheberle/ssh-ca-client/issues/129)) ([c206242](https://github.com/andrewheberle/ssh-ca-client/commit/c2062428fbb0f942f3f403c8f2fde21eebf0d343))
* **deps:** update module github.com/gen2brain/beeep to v0.11.3 ([#125](https://github.com/andrewheberle/ssh-ca-client/issues/125)) ([ad81cf2](https://github.com/andrewheberle/ssh-ca-client/commit/ad81cf227e57876c39364dcad75e3c149722ffde))
* **deps:** update module github.com/knadh/koanf/v2 to v2.4.1 ([#123](https://github.com/andrewheberle/ssh-ca-client/issues/123)) ([11aae0a](https://github.com/andrewheberle/ssh-ca-client/commit/11aae0a67d20d3945b833e5948b5b260222249b6))
* **deps:** update module github.com/oapi-codegen/runtime to v1.8.0 ([#127](https://github.com/andrewheberle/ssh-ca-client/issues/127)) ([43183d6](https://github.com/andrewheberle/ssh-ca-client/commit/43183d6368d7ee43a65d5232ea06169478d25380))

## [0.25.2](https://github.com/andrewheberle/ssh-ca-client/compare/v0.25.1...v0.25.2) (2026-10-16)


### Bug Fixes

* **deps:** update module github.com/go-jose/go-jose/v4 to v4.1.6 ([#120](https://github.com/andrewheberle/ssh-ca-client/issues/120)) ([bab9bef](https://github.com/andrewheberle/ssh-ca-client/commit/bab9bef41d0ae06be2d6e74c883dfddbb6e71e22))

## [0.25.1](https://github.com/andrewheberle/ssh-ca-client/compare/v0.25.0...v0.25.1) (2026-10-14)


### Bug Fixes

* **krl:** allow an installed KRL to be replaced on Windows ([#116](https://github.com/andrewheberle/ssh-ca-client/issues/116)) ([074386e](https://github.com/andrewheberle/ssh-ca-client/commit/074386e9b505e415e39bffd01a0bfead1ca66b8c))

## [0.25.0](https://github.com/andrewheberle/ssh-ca-client/compare/v0.24.0...v0.25.0) (2026-10-12)


### Features

* **systemd:** add a user timer to refresh the host KRL ([#109](https://github.com/andrewheberle/ssh-ca-client/issues/109)) ([49244cf](https://github.com/andrewheberle/ssh-ca-client/commit/49244cfd4542aee9700ef58241f9ae7d36417d73))


### Bug Fixes

* **httpclient:** allow 15 seconds for requests to the CA ([#107](https://github.com/andrewheberle/ssh-ca-client/issues/107)) ([d22ea2a](https://github.com/andrewheberle/ssh-ca-client/commit/d22ea2a99a3521bbc5b1eb9a303abbc3300ed3aa))
* **krl:** don't rewrite the output file when the KRL is unchanged ([#108](https://github.com/andrewheberle/ssh-ca-client/issues/108)) ([7f6b730](https://github.com/andrewheberle/ssh-ca-client/commit/7f6b73033e7a71c58dfed9e8d0df6e0126713dd7))

## [0.24.0](https://github.com/andrewheberle/ssh-ca-client/compare/v0.23.1...v0.24.0) (2026-10-12)


### ⚠ BREAKING CHANGES

* **api:** migrate to the v4 CA API- #97

### Features

* **api:** migrate to the v4 CA API- [#97](https://github.com/andrewheberle/ssh-ca-client/issues/97) ([7c40e1f](https://github.com/andrewheberle/ssh-ca-client/commit/7c40e1fc484b64e4ca8df8b28e05f7be81df1a98))
* **cli:** implement certificate revocation ([#100](https://github.com/andrewheberle/ssh-ca-client/issues/100)) ([e1d826c](https://github.com/andrewheberle/ssh-ca-client/commit/e1d826c5d4d2e0b7004b795689dd56bcc632a9cd))


### Bug Fixes

* **cert:** don't contact the SSH agent when revoking host certificates ([#101](https://github.com/andrewheberle/ssh-ca-client/issues/101)) ([2e7c05a](https://github.com/andrewheberle/ssh-ca-client/commit/2e7c05ab6cf939016fc1e1f6f4c1c02f8611f7c3))

## [0.23.1](https://github.com/andrewheberle/ssh-ca-client/compare/v0.23.0...v0.23.1) (2026-10-11)


### Bug Fixes

* **deps:** update module golang.org/x/sys to v0.49.0 ([#79](https://github.com/andrewheberle/ssh-ca-client/issues/79)) ([eb33b1a](https://github.com/andrewheberle/ssh-ca-client/commit/eb33b1ae0ff414383c10d893e6333b0acc1c115b))

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
