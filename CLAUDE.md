# CLAUDE.md

Working notes on the `zerossl-ip-cert` repository. Read before making changes.

## 1. What this is

A tool for issuing and auto-renewing **ZeroSSL TLS certificates for IP addresses** (IPv4) through the
REST API. The ACME path is not used here: ZeroSSL issues IP certificates through the REST API with
file validation.

- A fork of `NyaMisty/zerossl-ip-cert`, itself a fork of `tinkernels/zerossl-ip-cert`.
- Module path is **`github.com/romkazor/zerossl-ip-cert/v2`**. The `/v2` suffix is required by Go modules
  for major version 2 and up, and every import inside the repo carries it. Renaming the module means editing
  go.mod and every import in `exec/` together.
- Apache-2.0 licensed; the header is mandatory in every `.go` file.
- Development branch is `master`. Last substantial upstream change was May 2025 (rate limiting + cancellation
  of pending certificates); everything after that is this fork.
- Version lives in `const Version` in `exec/main.go` and must be bumped together with the git tag.

## 2. Layout and commands

The structure is flat. No `cmd/`, `internal/` or `pkg/`.

| Path | What |
|---|---|
| root | `package zerosslIPCert` — API client, models, key/CSR generation |
| `exec/` | `package main` — CLI, config, hooks |
| `exec/sample-*.yaml`, `exec/sample-*.sh`, `exec/sample-*.cmd` | sample config, state file and hooks |

```bash
make                   # == make release: 8 cross-compiled targets into dist/
make build             # build for the host platform
make test              # go test ./... (live tests skip themselves)
make vet               # go vet ./...
make check             # vet + test, exactly what CI runs
make fmt               # gofmt -l -w . exec
make clean             # rm -rf dist zerossl-ip-cert
make linux-amd64       # a single cross target
make test-integration  # live tests, requires ZEROSSL_API_KEY
```

There is still no linter config (`.golangci.yml`).

Running it (flags, not subcommands; `exec/main.go:41-43`):

```bash
zerossl-ip-cert -config /path/config.yaml            # issue (or renew, if current.yaml has an entry)
zerossl-ip-cert -renew   -config /path/config.yaml   # renew only
zerossl-ip-cert -cleanup -config /path/config.yaml   # cancel draft/pending only
```

`-config` is mandatory: without it you get `panic("Config file not found")` (`exec/main.go:62`).

### Tests

`go test ./...` passes in full and needs no network — that was not the case before.

- Offline: `csr_test.go`, `zerossl_request_factory_test.go`, `zerossl_client_transport_test.go` (httptest —
  retry/429/`Retry-After`/`decodeJSON`), `exec/config_test.go`, `exec/config_defaults_test.go`,
  `exec/main_test.go` (the hook env contract, via a stub script), `exec/util_perm_test.go`,
  `exec/verify_server_test.go`.
- Live: everything prefixed `TestIntegration`. **Skipped** unless `ZEROSSL_API_KEY` is set.

```bash
ZEROSSL_API_KEY=... make test-integration                                   # read-only
ZEROSSL_API_KEY=... ZEROSSL_ALLOW_WRITE=1 go test -v -run Integration ./...  # + create/cancel
```

`TestIntegrationIssueAndRevoke` additionally needs a publicly reachable IP on port 80 and a way to publish
the challenge file. The publisher is invoked with the **same environment as a verify hook**, so an existing
hook can be reused verbatim:

```bash
ZEROSSL_API_KEY=... ZEROSSL_ALLOW_WRITE=1 \
ZEROSSL_TEST_IP=203.0.113.5 \
ZEROSSL_CHALLENGE_CMD='ssh myhost /path/to/verify-hook.sh' \
go test -v -timeout 15m -run TestIntegrationIssueAndRevoke ./
```

It issues a certificate separate from any production one and revokes it at the end, so a live certificate is
never touched. Budget ~2 minutes and one quota slot.

`ZEROSSL_ALLOW_WRITE` gates the tests that **consume quota**: they create a draft and cancel it in a `defer`.
Live tests never touch an `issued` certificate — revoking one would break whatever is currently serving it.
The key is passed through the environment only; it must never end up in the repository.

### CI

- `.github/workflows/build.yml` — push to `master`/`dev` plus path-filtered PRs; Go **1.23.7**;
  `checkout` → `setup-go` → `gofmt` check → `make vet` → `make test` → `make release`.
  Live tests skip in CI because `ZEROSSL_API_KEY` is not set there.
- `.github/workflows/release.yml` — on **any** tag: `make check` → `make release`
  → `.github/helpers/pack4release.sh` (a tar.gz per directory in `dist/`) → `ncipollo/release-action@v1`.
- The version is a hardcoded `const Version` in `exec/main.go`. No tag matches the current code.

## 3. Code conventions

- Local variables carry a **trailing underscore**: `conf_`, `certInfo_`, `csrStr_`, `rspModel_`, `client_`.
  This is the project-wide style — follow it in new code, do not "fix" it in old code.
- Logging is stdlib `log` only, written to `io.MultiWriter(os.Stdout, logFile_)` (`exec/main.go:81`),
  with `log.LstdFlags | log.Lshortfile`. There are no levels.
- Fatal conditions in `main` use `panic`, not `log.Fatal` (`exec/main.go:62,67,73,78,89`).
- The typo in the filename `zerossl_model_verfify_domains.go` stays as is.
- Dependencies: only `gopkg.in/yaml.v3` and `golang.org/x/time`. Keep the count minimal.

## 4. Issuance flow (traced)

```
main() exec/main.go:50
 └─ issueCerts()  :117      → for each CertConf
     └─ issueCert()  :129
         ├─ if current.yaml has an entry with the same confId → renewCert()  :405
         ├─ (opt.) client_.CleanUnfinished()   when cleanUnfinished: true
         └─ issueCertImpl()  :162
             ├─ recreate {dataDir}/temp                          :163-175
             ├─ KeyGeneratorWrapper   csr.go:48
             ├─ pkix.Name                                        :180-187
             ├─ CSRGeneratorWrapper   csr.go:104 → GetCSRString
             ├─ WritePrivKeyWrapper → {dataDir}/temp/privkey.pem  :203
             ├─ client_.CreateCert(...)  POST /certificates       :209
             ├─ runVerifyHook(conf.VerifyHook, &certInfo_)        :216 (impl :296)
             ├─ verifyHttpCsrHash(client_, &certInfo_)            :221 (impl :264)
             │    └─ waitCert2BReady()                            :345
             ├─ DownloadCertInline(id, "1") → fullchain            :226
             ├─ CopyFile temp → conf.CertFile / conf.KeyFile       :244-251
             ├─ runPostHook(conf)                                  :253 (impl :362)
             └─ os.RemoveAll(tempDir_)                             :259
```

Renewal (`renew()` → `renewCert()`) is a **full re-issue**: new key, new CSR, new certificate. Threshold:
status `expiring_soon` **or** less than 29 days to `Expires` (parsed with layout `"2006-01-02 15:04:05"`).
The old certificate is revoked once the new one is installed — see §6.

`issueCertImpl(conf, replacementFor)` takes the hash of the certificate being replaced: `""` on a fresh
issue, the old id on renewal.

State lives in `{dataDir}/current.yaml`; config and state entries are matched by `confId`, and an entry is
updated by looking up the old `certId`.

**The API, not `current.yaml`, is the source of truth.** The state file is a cache and can drift: a rotated
API key, a restored backup, or a state write that failed after the old certificate was already revoked.
`Client.ResolveIssuedCert(commonName)` recovers the live certificate from `ListCerts`, and two paths use it:

- `renewCert` — when `GetCert(stateID)` fails, it looks the certificate up by common name and carries on.
  `stateID_` is kept separately from `id`, because the state entry still has to be found by its original value.
- `renewUntrackedConfigs` — for config entries with no state entry at all. Without it, a lost `current.yaml`
  turned `-renew` into a silent no-op forever, since `renew()` only walks the state. It adopts an existing
  certificate; it never issues one from scratch (that stays a job for a run without `-renew`).
- `issueCert` handles the opposite drift: when the tracked certificate is found neither by its id nor by
  common name, `renewCert` returns `errCertGone`, the dead state entry is dropped and a **plain run issues
  from scratch**. This is what makes moving `apiKey` to a different ZeroSSL account work — the stale `certId`
  would otherwise send every future run down the renewal path to the same failure. `-renew` still returns the
  error: creating a certificate out of nothing is deliberately not its job.

`ListCerts`' `search` matches **substrings** (`search=203.0.113` returns `203.0.113.10`), so `ResolveIssuedCert`
compares the common name exactly and picks the latest `Expires`.

### The renewal threshold

`renewalNotDue()` is the single decision point. A certificate is left alone **only when its status is
`issued`** and more than `renewBeforeDays` remain (default `DefaultRenewBeforeDays` = 29). Every other status re-issues, even with a future expiry date:
a `revoked` or `cancelled` certificate keeps its original dates but is dead, and skipping on the date alone
would leave a dead certificate installed indefinitely.

`Expires` comes back as UTC with no zone suffix, and `time.Parse` reads a zoneless layout as UTC, so the
comparison against `time.Now()` is correct. Test fixtures must build their timestamps in UTC too, otherwise
they silently shift by the local offset.

### Validation

The method is **hardcoded** to `HTTP_CSR_HASH`. The `verifyMethod` config field is parsed but never read.
The `/.well-known/pki-validation/<hash>.txt` file is served in one of two ways:

1. **External `verifyHook`** — takes priority whenever the field is non-empty. The hook reconfigures whatever
   web server already owns the port (nginx and caddy samples live in `exec/`).
2. **Built-in server** (`exec/verify_server.go`) — used when `verifyHook` is empty. It brings up a
   `net.Listener`, serves the challenge files and `404`s everything else, and is shut down via `defer` once
   issuance finishes.

The default port is 80 (ZeroSSL only ever connects to **80**), taken from `file_validation_url_http`;
`verifyListen` in the config overrides the whole address.

A subtlety of the built-in server: `Shutdown` only closes listeners that `Serve` has already registered.
That is why the stop function additionally calls `ln.Close()` and waits for the goroutine — otherwise a
quick cancellation leaves the port bound.

### Config keys added for free accounts

Both are optional and live at the top level next to `cleanUnfinished`:

| Key | Default | Meaning |
|---|---|---|
| `revokeOldOnRenew` | `true` (a `*bool` field, `nil` → true) | revoke the superseded certificate, so a key the host no longer serves stops being valid. It does **not** free a quota slot — see §6 |
| `legacyQueryAuth` | `false` | additionally send the deprecated `?access_key=` |

And one per `certConfigs[]` entry:

| Key | Default | Meaning |
|---|---|---|
| `verifyListen` | port from the challenge URL, usually `:80` | address of the built-in validation server; only used when `verifyHook` is empty |
| `renewBeforeDays` | `29` | how many days before expiry a renewal starts. Raise it when the scheduler runs rarely — a monthly cron against a 90-day cert can land exactly on the threshold and skip its only window |

`Config.ShouldRevokeOldOnRenew()` is the single place the revoke policy is read.

### Hook contract (do not break)

verify-hook receives: `ZEROSSL_HTTP_FV_HOST`, `ZEROSSL_HTTP_FV_PATH`, `ZEROSSL_HTTP_FV_PORT`,
`ZEROSSL_HTTP_FV_CONTENT`.
post-hook receives: `ZEROSSL_CERT_FPATH`, `ZEROSSL_KEY_FPATH`.

On Windows the content lines are joined with a **space** rather than `\n` (`exec/main.go:320-324`) — Windows
does not accept multiline environment variables. `sample-caddy-verify-hook.cmd` splits them back apart with
`for /f "tokens=1*"`.

Both runners call `ChmodPlusX` first (`exec/util.go:90`, shells out to `chmod +x`, a no-op on Windows) and
pipe the hook's stdout and stderr to `os.Stdout`.

## 5. ZeroSSL API: code vs. current documentation

Host: `const ApiEndpoint = "api.zerossl.com"` (`zerossl_request_factory.go:27`), always https.
Requests are built as **struct literals** `&http.Request{...}` rather than through `http.NewRequest` —
see the pitfalls in §7.

| Client method | HTTP | Path | Status |
|---|---|---|---|
| `CreateCert` | POST | `/certificates` | ok; sends `replacement_for_certificate` on renewal |
| `ListCerts` | GET | `/certificates` | ok |
| `GetCert` | GET | `/certificates/{id}` | ok |
| `VerifyDomains` | POST | `/certificates/{id}/challenges` | ok |
| `VerificationStatus` | GET | `/certificates/{id}/status` | implemented, but the CLI never calls it; the endpoint is EMAIL-validation only |
| `CancelCert` | POST | `/certificates/{id}/cancel` | ok, `draft`/`pending_validation` only; inspects `success` in the body |
| `DownloadCertInline` | GET | `/certificates/{id}/download/return` | **`/download/json` and `/download/zip` are the documented ones**; `/download/return` is an undocumented alias, verify before changing |
| `RevokeCert` | POST | `/certificates/{id}/revoke` | ok, `issued` only; inspects `success` in the body |
| `ResolveIssuedCert` | GET | `/certificates` | helper over `ListCerts`: recovers the live cert id by common name |

### Authentication

Every request always carries the recommended header:

```
Authorization: ApiKey <ACCESS_KEY>
```

The prefix is strictly `ApiKey`; ZeroSSL accepts nothing else. The deprecated `?access_key=` is **no longer
sent by default** — it is only added when the config sets `legacyQueryAuth: true` (package-level flag
`zerosslIPCert.UseLegacyQueryAuth`, assigned in `exec/main.go` after the config is read).

The single point of truth is `setAuth(req, q_, accessKey)` in `zerossl_request_factory.go`; it also creates
`req.Header`, which is why factories that build a body **must not** do `req.Header = make(http.Header)` —
that would wipe out `Authorization`. Keeping the key out of the query is also a hygiene matter: it otherwise
lands in proxy/CDN logs and in shell history.

### API error handling

ZeroSSL can return `{"success":false,"error":{"code":...,"type":...}}` **with HTTP 200**.

The shared entry point is `decodeJSON(resp, out)` in `zerossl_client.go`. It reads the body once, catches the
`error` object via `embeddedError()`, falls back to a status-code error carrying the body (truncated at
`maxErrorBodyLen`), and only then decodes into the model. `GetCert`, `CreateCert`, `ListCerts`,
`DownloadCertInline`, `VerificationStatus` and `doActionRequest` (cancel/revoke) all go through it.
`ApiErrorModel` implements `error`, so the reason reaches the caller intact. `ActionResultModel.Err()`
additionally catches a `success:false` that carries no `error` object.

The order inside `decodeJSON` matters: `embeddedError` is checked **before** the status code, because
authentication failures arrive as HTTP 401 with that very same `{"success":false,"error":{...}}` body — and
the error object reads far better than a bare "status code 401".

**The one exception is `VerifyDomains`**: it has its own path without `embeddedError`, because for
`HTTP_CSR_HASH` ZeroSSL **always** answers `success:false` with an error object, and the shared check would
reject every perfectly normal verification response. Any future `success` check must keep this exception
(see the note in `exec/main.go:272`).

### Verified against the live API (2026-09-01)

| Case | Result |
|---|---|
| `Authorization: ApiKey <key>`, no query param | HTTP 200 — works |
| `?access_key=<key>` (legacy) | HTTP 200 — still works for now |
| No authentication | HTTP 401, `code 101`, `type missing_access_key` |
| `Authorization: Bearer <key>` | HTTP 401, `missing_access_key` — the prefix is strictly `ApiKey` |
| Invalid key | HTTP 401, `code 101`, `type invalid_access_key` |
| `GET /certificates/{unknown}` | `code 2803`, `certificate_not_found` |
| `download/return` on a draft | `code 2832`, `certificate_not_issued` |
| Full issue → `revoke(Superseded)` | status becomes `revoked`; the quota slot is **not** released — see the correction below |
| `POST /certificates` at the cap, plain | `code 2817`, `certificate_limit_reached` — no draft is created |
| `POST /certificates` at the cap, with `replacement_for_certificate` | **accepted and issued** — the limit does not apply to renewal |
| time from challenge published to `issued` | 90 s twice, over 11 min once — latency varies widely |
| `POST /certificates` for an IP that already has a live cert on **another** account | `code 2839`, `duplicate_certificates_found`; `strict_domains: 0` does not lift it |
| `GET /certificates/{id}` for another account's certificate | `code 2801`, `permission_denied` |
| `search=203.0.113` | returns `203.0.113.10` — search matches substrings |

The error object is exactly `{"code":int,"type":string,"info":string}`, which is what `ApiErrorModel`
describes. The `ListCerts` response also carries `acmeUsageLevel` and `acmeLocked` — not in the model, not
needed.

**Important:** `CreateCert` for a reserved IP (verified with `203.0.113.x`, TEST-NET-3) **successfully
creates a draft**. ZeroSSL rejects reserved ranges not at creation time but later, during validation. So a
wrong IP in the config silently eats a quota slot — which is what makes a public-IPv4 check on our side
worth having (remaining item under §8.7).

Cancelled certificates stay visible in `ListCerts` with status `cancelled` but do not hold a quota slot:
after four create+cancel cycles, a query for `draft,pending_validation,issued,expired` returned
`total_count = 0`.

The **renewal chain** was driven end to end by the tool itself on an isolated config
(`renewBeforeDays: 200` forces the renewal path on a fresh certificate). These observations stand:

| Assumption | Outcome |
|---|---|
| `replacement_for_certificate` is accepted with a live hash | accepted; the new cert came back with `replacement_for` set to the old id |
| the old cert stays `issued` after its replacement is issued | it does — otherwise `revokeSuperseded` would silently skip the revoke |
| the whole `renewCert` order works (issue → install → write state → revoke) | ran clean, state ended up pointing at the new id |
| a 4th certificate could still be created while 3 were occupied | it could, so the cap is not enforced exactly where the account page counts |

### What the free allowance actually does (2026-09-01, corrected twice)

This section was rewritten twice in one day because two earlier readings were wrong. Both mistakes are kept
below, because each one is easy to make again.

**Mistake 1 — "revoking frees a slot."** It does not. The check that "proved" it counted
`certificate_status=draft,pending_validation,issued,expired` before and after a revoke and watched it go
2 → 1. That status list **does not contain `revoked`**, so the certificate left the result set by
definition. A tautology, not a measurement. What the account really reports, holding 1 `issued`,
3 `revoked` and 4 `cancelled`:

```
account page:  4 / 3  90-Day Certificates      →  4 = issued(1) + revoked(3); cancelled excluded
```

So a `revoked` certificate keeps its slot exactly like an `issued` one, and only `cancelled` is free of
charge. That much stands. `QuotaStatuses` in `zerossl_client.go` encodes the counting statuses so the same
query is never written by hand again.

**Mistake 2 — "so a free account cannot renew."** Also wrong, and it followed from testing the wrong verb.
A plain create past the limit is refused:

```
POST /certificates                          →  {"code":2817,"type":"certificate_limit_reached"}
```

But a create carrying **`replacement_for_certificate`** is accepted *and issued*, on the very same account —
verified twice, at 4 and then 5 slots used against an allowance of 3, each time reaching `issued` with a
normal expiry date. The limit applies to **first-time issuance, not to renewal.**

That is the whole picture, and it is good news:

| Operation | Past the allowance |
|---|---|
| first issue of a new certificate | refused, `2817` |
| renewal (`replacement_for_certificate` set, certificate owned by the account) | **goes through** |

Since `renewCert` always sends `replacement_for_certificate` for an `issued`/`expiring_soon` certificate,
**renewal on a free account keeps working indefinitely.** The upstream README warning applies to fresh
issuance only. `revokeOldOnRenew` therefore buys no quota — it is a security setting, and a good one, but
nothing depends on it.

Still unobserved: whether a slot is ever released at a certificate's original expiry. Every certificate on
the account was created the same day. Worth a look after 2026-11-30, though it no longer blocks anything.

### The duplicate wall, which does block things

`POST /certificates` for an identifier that already has a live certificate answers:

```
{"code":2839,"type":"duplicate_certificates_found"}
```

This is **not scoped to the account**. A brand new account with zero certificates gets it for an IP whose
live certificate belongs to somebody else, while the same account creates certificates for unrelated
identifiers without complaint. `strictDomains: 0` does not lift it. Only a create declared as the
replacement of a certificate **the account itself owns** gets through — and that cannot cross accounts,
since `GET /certificates/{id}` on a foreign certificate is `2801 permission_denied`.

The consequence: **moving a certificate to a different ZeroSSL account is not a key swap.** The old
certificate has to be gone first, and neither route is clean — revoking it is irreversible and it is
unverified whether that even lifts `2839`, while waiting for expiry means a scheduled gap. Given that
renewal on the existing account works indefinitely, the honest answer is usually *do not move accounts*.

### Issuance latency

Measured on one host with an identical challenge, minutes apart: **90 seconds** twice, and **over 11
minutes** once. `waitCert2BReady` used to give up after 5 minutes, report a timeout, and abandon a
certificate that was on its way to being issued — which then sat there occupying a slot. The bound is now
`waitCertAttempts = 30` (15 minutes), and each poll is logged instead of the tool going quiet.

This is the most likely shape of the June 2026 production failure, and it is a reminder that a stuck
`pending_validation` says nothing about its own cause. `accountHint` appends the slot count to the timeout
as context only — never read it as the diagnosis.

### Parameters and values

- `certificate_validity_days`: `90` (default) or `200`/annual on paid plans.
- `validation_method`: `EMAIL` | `CNAME_CSR_HASH` | `HTTP_CSR_HASH` | `HTTPS_CSR_HASH`.
- `certificate_status` for listing: `draft,pending_validation,issued,cancelled,revoked,expired` plus the
  special value `expiring_soon`. All of them exist in `CertStatus` (`zerossl_model_get_cert.go`).
- `revoke` `reason`: `Unspecified` (default) | `keyCompromise` | `affiliationChanged` | `Superseded` |
  `cessationOfOperation` — constants in `RevokeReason` (`zerossl_model_action_result.go`).
- List parameters are comma-separated strings, not arrays.
- `CertificateInfoModel.ReplacementFor` (`json:"replacement_for"`) already exists in the model — on creation
  its counterpart is named `replacement_for_certificate`.

## 6. Free accounts: limits and quota strategy

**This is the key section — the free plan is what this tool is being modernized for.**

- Free plan: **3 certificates of 90 days**. The REST API is available on free (the pricing page lists
  "REST API Access: Yes"), yet ZeroSSL's developer page says "free and unlimited in API request volume for
  customers subscribed to the Pro Plan or higher" — a contradiction in their own material. Assume free-tier
  requests are metered and do not hammer the API.
- **Quota is consumed by the statuses `draft`, `pending_validation`, `issued` and `expired`.** Example from
  their help centre: 1 draft + 1 issued + 1 expired means the quota is full; the only way out is cancelling
  the draft.
- `cancel` works **only** for `draft`/`pending_validation`. `revoke` works **only** for `issued`.
  **An `expired` certificate can be neither cancelled nor revoked.**
- **`revoked` counts as well.** Verified 2026-09-01: an account holding 1 `issued` + 3 `revoked` reports
  `4 / 3`, and a plain `POST /certificates` is refused with `code 2817, certificate_limit_reached` (§5).
  Revoking buys no quota back.
- **But the limit does not apply to renewal.** A create carrying `replacement_for_certificate` is issued on
  the same over-limit account (§5, verified twice). So the upstream README warning — "free account can't
  renew certificate infinitely" — holds for **first-time issuance only**; renewal keeps working.

### Implemented strategy

Issue the new one (with `replacement_for_certificate` = old hash) → verify → download → install the files →
post-hook → **write `current.yaml`** → **`revoke(old, reason=Superseded)`**.

The order matters and deviates from the original plan: the revoke happens **after** the state is persisted
(`exec/main.go`, the `else` branch after `WriteCurrentData`). Revoking first and then failing on the write
would lose the id of the new certificate, and the next run would treat an already revoked one as current.
A revoke failure is logged but never fails the renewal — the new certificate is installed by then.

A fresh `GetCert` precedes the revoke: we only revoke while the old certificate is still `issued`.
`replacement_for_certificate` is sent only for `issued`/`expiring_soon` — ZeroSSL would reject an expired hash.

Disabled with `revokeOldOnRenew: false`. On top of that, all `draft`/`pending_validation` certificates are
cancelled before issuing (`cleanUnfinished: true`).

`revokeOldOnRenew` is therefore a **security** setting, not a quota one: it stops a superseded key from
staying valid once the host no longer serves it. That is reason enough to leave it on, but it neither helps
nor hurts the certificate count.

What the allowance does constrain is **first-time issuance**, so keep one certificate per free account under
management and never issue test certificates on an account that carries production — a filled account can no
longer take on anything new, and nothing buys a slot back. An account that is already renewing is fine.

### Limits specific to IP certificates

- Validation is **File Upload only** (`HTTP_CSR_HASH` / `HTTPS_CSR_HASH`). EMAIL and CNAME are not supported
  for IPs.
- Reserved/private IANA ranges are not issued. There is **no** public-IPv4 check on `commonName` in the code —
  the failure only surfaces in an API response.
- IPv6 is not supported (the README states IPv4-only).
- The HTTP check requires a plain **200 with no redirects** on port 80.

## 7. Known bugs and pitfalls

Listed as they stand in the code; the fix history is in §8.

**Network and retry**

- ~~Infinite retry on 429~~ — fixed: `MaxRetries` (default `DefaultMaxRetries` = 5), exponential backoff
  `2s << attempt` capped at `maxRetryDelay` = 60s, honouring `Retry-After` (both a seconds count and an
  HTTP date). Exhausting the retries is an error, not a silent 429 return.
- ~~A retried POST went out with an empty body~~ — fixed: `newFormBody` sets `ContentLength` and `GetBody`,
  and `doRequest` rebuilds `req.Body` before replaying.
- ~~`http.DefaultClient` without a timeout~~ — fixed: `Client.HTTPClient` with `DefaultTimeout` = 60s, filled
  in lazily by `deps()`, so a bare `&Client{ApiKey: k}` keeps working.
- ~~`NewClient` was never used, a limiter was created per call~~ — fixed: `apiClient(apiKey)` in
  `exec/main.go` keeps one shared `Client` per key, so the limiter is now global.
- `req.Context()` on a literal-built request is still `context.Background()`: there is no deadline for the
  whole operation, the timeout only covers an individual HTTP call. Remaining item under §8.5.

**Logic**

- ~~Unstable pagination cursor in `CleanUnfinished`~~ — fixed: it always requests `page=1`, loops in rounds,
  and stops when the page comes back empty **or** a round cancelled nothing (a guard against an infinite loop
  when cancellation keeps failing).
- ~~`cleanup()` only handled the first `apiKey`~~ — fixed, the unconditional `break` is gone.
- ~~Shadowed `err` in `verifyHttpCsrHash`~~ — fixed (`var` + `=` instead of `:=`).
- ~~`ReadConfig`/`ReadCurrentData` swallowed the file read error~~ — fixed.
- ~~The log file was opened before `dataDir` was created~~ — fixed: a first run on a clean machine used to
  panic (`os.OpenFile` on a non-existent path); the log directory is now created up front.
- ~~The renewal threshold ignored the status~~ — fixed: it only checked `!= expiring_soon`, so a **revoked
  certificate with a future `Expires` was skipped forever** while a dead certificate stayed installed.
  `renewalNotDue()` now requires status `issued` to skip.
- ~~A stale or missing `current.yaml` was unrecoverable~~ — fixed via `ResolveIssuedCert`, see §4.
- The config fields `city` and `verifyMethod` are parsed but **never used** (`city` is absent from the
  `pkix.Name` at `exec/main.go:180-187`; `verifyMethod` is overridden by the hardcoded method).

**Security** — closed

- The private key is `0600`, and `CopyFile` now actually applies the mode to the file (`os.OpenFile` +
  `Chmod`, because `O_CREATE` does not change the mode of an existing file). Previously `perm` only reached
  the parent directory.
- `csr.go` writes the key with `0600` and `O_TRUNC` instead of `O_APPEND` — appending corrupted a re-issued key.
- Certificate `0644`, `current.yaml` `0600`, `dataDir` and `temp` `0700`, log `0640`.
- The `temp` directory holding the private key is removed via `defer`, not only on the success path.
- The CSR and the downloaded certificate are no longer logged (only the CSR length remains).
- The API key is not sent in the query by default (see §5).

**Hygiene**

- ~~`golang.org/x/time` marked `// indirect`~~ — fixed by `go mod tidy`.
- ~~`confID` instead of `confId` in `exec/sample-current.yaml`~~ — fixed.
- `sample-nginx-verify-hook.sh` writes `verify.conf` into the **current working directory**, not into
  `conf.d` — users must adapt it.
- ~~The usage line only advertised `[ -renew ]`~~ — fixed, `-cleanup` added.
- Commented-out dead blocks: `zerossl_client.go:207-231`, `exec/main.go:449-470`,
  `zerossl_request_factory.go:94-118`.

## 8. Modernization roadmap

**The roadmap is complete.** Items 1-9 are closed; only the pinpoint leftovers marked "Remaining" are open.

1. ~~**Auth**: move to `Authorization: ApiKey <key>`~~ — done. Header always, query parameter behind
   `legacyQueryAuth: false`.
2. **Free quota**: `RevokeCert`, `replacement_for_certificate` and `CertStatus.Revoked` are implemented and
   work. The *goal* they were meant to serve is not met: revoking does not free a slot (§5), so a free
   account still cannot renew indefinitely. **Remaining**: nothing to build here — the ceiling is ZeroSSL's,
   not ours.
3. ~~**API errors**~~ — done: shared `decodeJSON`, body included on `>=400`, `embeddedError` on HTTP 200,
   `ApiErrorModel` as an `error`. The `VerifyDomains` + `HTTP_CSR_HASH` exception is respected.
4. ~~**Built-in HTTP validation server**~~ — done: `exec/verify_server.go`, engaged only when `verifyHook`
   is empty, address via `verifyListen`. Verified against a real ZeroSSL challenge.
5. **Transport**: done — `DefaultTimeout`, bounded retry with backoff and `Retry-After`, one shared `Client`
   per API key via `apiClient()`. **Remaining**: a `context` deadline for the whole operation (requests still
   go out with `context.Background()`).
6. ~~**Permissions and logs**~~ — done: `0600` on the key and `current.yaml`, `0644` on the certificate,
   `0700` on `dataDir` and `temp`, `0640` on the log; `CopyFile` applies the mode to the file; the CSR and
   certificate are no longer logged; `temp` is cleaned via `defer`.
7. ~~**Fixes**~~ — done: `CleanUnfinished` pagination, shadowed `err`, `ReadConfig`/`ReadCurrentData`,
   `go mod tidy`, `confID` in the sample, the `break` in `cleanup()`, the usage line, the log directory
   ordering. **Remaining**: the unused `city`/`verifyMethod`, and the missing public-IPv4 check
   (see §5 — a reserved IP silently eats a quota slot).
8. ~~**Tests and CI**~~ — done: `go test ./...` passes in full without network; live tests moved behind the
   `TestIntegration` prefix and the `ZEROSSL_API_KEY` / `ZEROSSL_ALLOW_WRITE` gates; the Makefile gained
   `build`/`test`/`test-integration`/`vet`/`fmt`/`check`/`clean`; CI runs gofmt + vet + test before building,
   and releases go through `make check`.
9. ~~**README**~~ — done: `-cleanup`, the revoke strategy, the new config keys, an accurate free-account warning.

**Compatibility.** Every new config key is optional and an old `config.yaml` is read unchanged
(covered by `exec/config_defaults_test.go`); the `current.yaml` format did not change.

Two deliberate departures from "defaults reproduce the current behaviour" — they are the point of the task:
- `revokeOldOnRenew` defaults to **true**: a superseded key should stop being valid once it is off the host.
  (It was originally defaulted on for quota reasons; that rationale turned out to be wrong — see §5 — but the
  security one stands on its own.)
- authentication defaults to the **header**, not the query parameter.

Breaking changes to the library API (for external importers of the package):
- `Client.CreateCert` and `ApiReqFactory.CreateCertificate` gained a sixth parameter, `replacementFor`;
- client methods now return meaningful errors where they used to silently hand back a zero-valued model.

## 9. What not to do

- Do not drop the `/v2` suffix from the module path while the major version is 2 — `go get` would break.
- Do not move packages into `cmd/` / `internal/` — the layout stays flat.
- Do not break the hook env contract (`ZEROSSL_*`) and do not rename existing YAML keys.
- Do not "fix" the trailing-underscore style.
- Do not replace the hardcoded `HTTP_CSR_HASH` with a config-driven method unless `HTTPS_CSR_HASH` is
  supported too — for IPs there is no other option anyway.
- Do not check `success` on a `VerifyDomains` response under `HTTP_CSR_HASH` — it is always `false`.
- Do not write `req.Header = make(http.Header)` in the request factories: `setAuth` has already created the
  header and put `Authorization` in it. Use `req.Header.Set(...)` only.
- Do not revoke the old certificate before `current.yaml` is written — that loses the link to the installed one.

## 10. Deployment recipe: nginx + hooks

The two hook samples that ship in `exec/` rewrite an nginx server block on the fly.
That works, but it is fragile: it needs a writable conf directory, a reload per
issuance, and it fights whatever else owns port 80. The layout below is what the
production host in question actually runs, and it is the one to recommend — nginx serves
the challenge directory statically and never needs reconfiguring.

### Which validation route to pick

| Situation | Choice |
|---|---|
| A web server already owns port 80 | external `verifyHook` writing into a served directory (below) |
| Nothing listens on port 80 | leave `verifyHook` empty, the built-in server binds it (§4) |
| Something owns port 80 but can proxy | built-in server on a spare port via `verifyListen`, proxied by the front server |

ZeroSSL only ever connects to **port 80** and requires a plain `200` with no
redirects, so an HTTP→HTTPS redirect must not swallow `/.well-known/`.

### nginx: serve the challenge directory

The `location ^~ /.well-known/` block has to come **before** the catch-all redirect,
and `^~` makes it win over regex locations:

```nginx
server {
    listen 80;
    server_name 203.0.113.10;          # the IP the certificate is for

    location ^~ /.well-known/ {
        root /var/www/acme;            # serves /var/www/acme/.well-known/...
        default_type "text/plain";
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
```

The same directory is what certbot uses in webroot mode, so a host that already has
Let's Encrypt certificates usually has this block already.

Where the certificate is consumed:

```nginx
server {
    listen 443 ssl;
    server_name 203.0.113.10;

    ssl_certificate     /var/local/zerossl/cert1.pem;   # fullchain: leaf + CA bundle
    ssl_certificate_key /var/local/zerossl/key1.pem;
}
```

> **A certificate issued for an IP has no DNS name in it** — only
> `X509v3 Subject Alternative Name: IP Address:...`. Clients reach it by connecting
> to the bare IP, and per RFC 6066 they then send **no SNI at all**, because an IP
> literal is not a legal SNI value. On a host that routes by SNI, the empty-SNI
> branch is what must lead to this server block; a rule matching the IP as an SNI
> string will never fire.

### verify-hook: write the file, do not touch nginx

```sh
#!/bin/sh
# Receives ZEROSSL_HTTP_FV_HOST / _PATH / _PORT / _CONTENT.
set -eu
WEB_DIR="/var/www/acme"

FILE_PATH="$WEB_DIR$ZEROSSL_HTTP_FV_PATH"
mkdir -p "$(dirname "$FILE_PATH")"

# printf %b, not echo -e: the content is three lines and echo -e is not portable.
printf "%b" "$ZEROSSL_HTTP_FV_CONTENT" > "$FILE_PATH"

test -f "$FILE_PATH" || { echo "ERROR: could not write $FILE_PATH"; exit 1; }
echo "challenge written: $FILE_PATH"
# No nginx reload here: static files are picked up straight off disk.
```

### post-hook: reload whatever holds the certificate

```sh
#!/usr/bin/env bash
# Receives ZEROSSL_CERT_FPATH and ZEROSSL_KEY_FPATH.
set -euo pipefail

nginx -t
nginx -s reload
```

> **Anything that reads the certificate at startup needs restarting here too**, not
> just nginx — a panel, a proxy, a DoH daemon with its own TLS listener. nginx
> reload alone would leave them serving the previous certificate until their next
> restart.

### zero.yaml, annotated

```yaml
dataDir: /var/local/zerossl        # state, logs and the temp dir live here (0700)
logFile: /var/local/zerossl/log.txt
cleanUnfinished: true              # cancel leftover draft/pending before issuing
revokeOldOnRenew: true             # kills the superseded key; does NOT free a quota slot
legacyQueryAuth: false             # header auth only; true also sends ?access_key=

certConfigs:
  - commonName: 203.0.113.10       # a public IPv4; reserved ranges are refused late
    confId: ip1                    # ties this config to its current.yaml entry -- never reuse
    apiKey: <ZeroSSL REST API key> # keep this file 0600
    days: 90                       # 90 on the free plan
    keyType: rsa                   # or ecdsa
    keyBits: 2048                  # rsa only
    keyCurve: P-256                # ecdsa only: P-256 | P-384
    sigAlg: SHA256-RSA             # match keyType: SHA256-RSA / ECDSA-SHA256 / ...
    strictDomains: 1
    verifyMethod: HTTP_CSR_HASH    # parsed but unused, the method is hardcoded
    # renewBeforeDays: 29          # raise only for a rarely-running scheduler
    verifyHook: /var/local/zerossl/verify-hook.sh   # empty -> built-in server
    # verifyListen: ":80"          # only used when verifyHook is empty
    postHook: /var/local/zerossl/post-hook.sh
    certFile: /var/local/zerossl/cert1.pem
    keyFile: /var/local/zerossl/key1.pem
```

Make both hooks executable (`chmod +x`); the tool also does it, but it shells out to
`chmod` to get there.

### Scheduling

```cron
17 4 * * * /usr/local/bin/zerossl-ip-cert -renew -config /usr/local/bin/zero.yaml > /dev/null 2>&1
```

**Run it daily, not monthly.** A run outside the renewal window is a single GET and
an exit, so it costs nothing, while `@monthly` against a 90-day certificate can miss
its only window: with the default 29-day lead time a certificate issued on the 1st
leaves exactly 29 days at the next monthly tick, which is a skip, and the tick after
that is already past expiry. Output goes to `/dev/null` on purpose — the tool writes
its own `logFile`.

### First run

`-renew` only walks `current.yaml`, so the very first issuance must run **without**
a flag:

```bash
zerossl-ip-cert -config /path/zero.yaml          # issue
zerossl-ip-cert -renew -config /path/zero.yaml   # what cron does afterwards
zerossl-ip-cert -cleanup -config /path/zero.yaml # cancel stuck draft/pending
```

### When it goes wrong

```bash
tail -50 /var/local/zerossl/log.txt

# is the challenge reachable exactly as ZeroSSL will fetch it?
echo probe > /var/www/acme/.well-known/pki-validation/probe.txt
curl -sS -o /dev/null -w 'http=%{http_code} redirects=%{num_redirects}\n' \
  http://203.0.113.10/.well-known/pki-validation/probe.txt   # want 200 and 0

# cert and key must be one pair
diff <(openssl x509 -in cert1.pem -noout -pubkey) <(openssl rsa -in key1.pem -pubout)

# how many of the 3 free slots are taken -- `revoked` MUST be in this list, it counts
# too, and leaving it out is exactly the mistake corrected in section 5
curl -sS -H "Authorization: ApiKey $KEY" \
  'https://api.zerossl.com/certificates?certificate_status=draft,pending_validation,issued,revoked,expired&limit=100'
```

A `404` on the redirect check usually means the `location / { return 301 ... }` block
is winning; make sure the `/.well-known/` location uses `^~`.
