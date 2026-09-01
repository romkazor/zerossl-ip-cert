# zerossl-ip-cert &middot; [![License](https://img.shields.io/hexpm/l/plug?logo=Github&style=flat)](https://github.com/tinkernels/zerossl-ip-cert/blob/master/LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/tinkernels/zerossl-ip-cert)](https://goreportcard.com/report/github.com/tinkernels/zerossl-ip-cert) [![Go Reference](https://pkg.go.dev/badge/github.com/tinkernels/zerossl-ip-cert.svg)](https://pkg.go.dev/github.com/tinkernels/zerossl-ip-cert) [![Build workflow](https://github.com/tinkernels/zerossl-ip-cert/actions/workflows/build.yml/badge.svg)](https://github.com/tinkernels/zerossl-ip-cert/actions/workflows/build.yml)

## ⚠️ Note on free accounts

ZeroSSL removed the `Delete Certificate` API endpoint, and on a free account every certificate in `draft`,
`pending_validation`, `issued` **or `expired`** status counts against the 3-certificate quota. An expired
certificate can be neither cancelled nor revoked, so it holds its slot forever.

zerossl-ip-cert works around this by **revoking the superseded certificate right after the new one is
installed** (`revokeOldOnRenew`, on by default), which releases the slot while the certificate is still
`issued`. Combined with `cleanUnfinished`, renewal on a free account keeps working indefinitely and never
occupies more than 2 of the 3 slots.

zerossl-ip-cert is a automation tool for issuing ZeroSSL IP certificates.

* Use ZeroSSL [REST API](https://zerossl.com/documentation/api/)  to implement certificate issuing.
* Mainly made for **IP** certificates (ipv4 only for now).
* Call external program for automatically verification.
* Painless certificate renewal.
* Cross platform (Linux/Macos/Windows).

## Development

```bash
make build            # host binary
make check            # go vet + go test, what CI runs
make release          # all 8 cross-compiled targets
```

`go test ./...` needs no network. The live API tests skip themselves unless `ZEROSSL_API_KEY` is set:

```bash
ZEROSSL_API_KEY=... make test-integration                                    # read-only
ZEROSSL_API_KEY=... ZEROSSL_ALLOW_WRITE=1 go test -v -run Integration ./...   # also create/cancel a draft
```

`ZEROSSL_ALLOW_WRITE` gates the tests that consume quota; they create a draft and cancel it again. No test
ever revokes an issued certificate.

## Installation

* Package zerossl-ip-cert contains ZeroSSL [REST API](https://zerossl.com/documentation/api/) client, one can
  just `go get github.com/tinkernels/zerossl-ip-cert` and import it to use the client.
* To build static executables, clone this repository and `make release` , or you can make your desire target binary, just take a look at the [Makefile](https://github.com/tinkernels/zerossl-ip-cert/blob/master/Makefile).

## Usage

zerossl-ip-cert rely on configuration file to run. To archive the goal of issuing certificate automatically, you need do some additional work, saying the external hook.

### Usage Info

```
Usage: zerossl-ip-cert [ -renew | -cleanup ] -config CONFIG_FILE

  -config string
        Config file
  -renew
        Renew existing certs only
  -cleanup
        Cleanup pending certs only
```

With no flag, certificates from the config file are issued (or renewed, if a state record already exists).
`-cleanup` cancels every certificate stuck in `draft` or `pending_validation`, freeing the quota slots they hold.

### Configuration File

You can find a sample configuration file [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-config.yaml), with enough comments in it.

Two top-level options matter for quota and API compatibility:

| Key | Default | Meaning |
|---|---|---|
| `revokeOldOnRenew` | `true` | Revoke the superseded certificate once the new one is installed, freeing its quota slot. Set to `false` to keep the old certificate until it expires. |
| `legacyQueryAuth` | `false` | Also send the deprecated `?access_key=` query parameter. The recommended `Authorization: ApiKey <key>` header is always sent. |

And one per certificate entry:

| Key | Default | Meaning |
|---|---|---|
| `verifyListen` | port from the challenge URL, i.e. `:80` | Address of the built-in validation server. Only used when `verifyHook` is empty. |
| `renewBeforeDays` | `29` | How many days before expiry a renewal starts. Raise it if your scheduler runs rarely: a monthly cron against a 90-day certificate can land exactly on the threshold and skip the only window it had. |

Both are optional; a configuration file written for an earlier version keeps working unchanged.

 And also a sample  state record file [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-current.yaml), just for troubleshooting.

### External Hook

zerossl-ip-cert use `HTTP_CSR_HASH` validation method to verify domains (including ip address surely), get more information from the ZeroSSL official [documentation](https://zerossl.com/documentation/api/verify-domains/).

There are two ways to serve the challenge file:

1. **Built-in validation server** (no hook needed). Leave `verifyHook` empty and zerossl-ip-cert binds port 80
   itself for the duration of the issuance, serves the `/.well-known/pki-validation/<hash>.txt` file and shuts
   down afterwards. Use `verifyListen` to bind somewhere else (behind a reverse proxy, for instance). Port 80
   must be free while the certificate is issued -- ZeroSSL only ever connects there.
2. **External hooks.** If `verifyHook` is set, it takes priority: your hook reconfigures whichever web server
   already owns port 80. This is the right choice when nginx or caddy must keep running.

For the hook route you need a http server running and hook programs to finish the domain verification.

* **verify-hook** will be called before domain verification, some environment variables will be passed to it.

  `ZEROSSL_HTTP_FV_HOST` stands for listening host, here will be ip address.

  `ZEROSSL_HTTP_FV_PATH` stands for url path, where verification content will locate.

  `ZEROSSL_HTTP_FV_PORT` stands for listening port, ZeroSSL only reach port `80` of your http server according to use experience.

  `ZEROSSL_HTTP_FV_CONTENT` stands for validation content, ZeroSSL will check it when domain verification started.

  And a sample script for nginx can be found [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-nginx-verify-hook.sh), a sample script for caddy can be found [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-caddy-verify-hook.cmd).

  *P.S.* When running in **Windows OS**, text lines are concatenated with spaces in `%ZEROSSL_HTTP_FV_CONTENT%`, as windows doesn't accept multiline variables without using magic.

* **post-hook** will be called after certification downloading, and some other environment variables will be passed to it.

  `ZEROSSL_CERT_FPATH` stands for the store path of certificate.

  `ZEROSSL_KEY_FPATH` stands for the store path of private key.

  And a sample script for nginx can be found [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-nginx-post-hook.sh), a sample script for caddy can be found [here](https://github.com/tinkernels/zerossl-ip-cert/blob/master/exec/sample-caddy-post-hook.cmd).

## License

[Apache-2.0](https://github.com/tinkernels/zerossl-ip-cert/blob/master/LICENSE)
