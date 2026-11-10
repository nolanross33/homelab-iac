# threat-feed-fix

Fixes three abuse.ch threat-feed integrations into NetWitness.

## Current approach: CEF over syslog

`fetch-urlhaus.py`, `fetch-feodo.py`, and `fetch-threatfox.py` all emit [CEF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
over UDP syslog, and NetWitness's **stock CEF parser** handles the events —
no custom parser XML is deployed. This replaces an earlier attempt (see
"Deprecated" below) that never worked: the custom `urlhausfeed`/
`feodotracker` parsers matched events (`device.type` got set) but
extracted zero fields, because their content used NetWitness *meta-key*
names instead of the table-map *envision* names the parser engine expects.
That mismatch is moot now — CEF sidesteps the custom-parser layer
entirely, and this was verified empirically with test lines.

```
<134>{Mon DD HH:MM:SS} k3s-node0 CEF:0|abuse.ch|{Product}|1.0|{SignatureID}|{Name}|5|{extension}
```

| Feed | Product | SignatureID | Name | Extension |
|---|---|---|---|---|
| Feodo | `Feodo` | `C2` | `Feodo C2 Server` | `dst=<ip> dpt=<port> cs1Label=malware cs1=<malware> outcome=<status>` |
| URLhaus | `URLhaus` | `<threat>` (e.g. `malware_download`) | `URLhaus <id>` | `dst=<ip>` **or** `dhost=<domain>`, then `dpt=<port> cs1Label=malware cs1=<normalized tags> outcome=<status>` |
| ThreatFox | `ThreatFox` | `<threat_type>` (e.g. `botnet_cc`) | `ThreatFox <id>` | `dst=<ip>` **or** `dhost=<domain>`, then `dpt=<port>` (domain-type IOCs have no port and omit `dpt`), `cs1Label=malware cs1=<malware_printable>`, `cs2Label=confidence cs2=<confidence_level>`, `cs3Label=tags cs3=<comma-joined tags>` |

URLhaus and ThreatFox both use `dst=` for an IPv4-hosted indicator and
`dhost=` for a hostname-hosted one — same `classify_host()` logic
(duplicated in each script), just a different output field.

Only `cs1`/`cs1Label` are used for the free-text malware/tag field in
Feodo/URLhaus — `externalId`, `cn1`, `request`, `msg`, `reason`, and any
other `csNLabel` were verified **not** to map in this NetWitness instance
and are deliberately not used. ThreatFox additionally uses `cs2`/`cs3` for
`confidence_level` and `tags`, since those fields don't exist on the other
two feeds and there's no reason to leave real, structured ThreatFox data
unmapped just to stay uniform with scripts that never had it. **ThreatFox
has no `outcome=` field at all** — unlike URLhaus's online/offline status
or Feodo's `c2_status`, ThreatFox has no per-IOC up/down state, so
`outcome=` is never emitted for it, not even conditionally.

CEF escaping implemented in both scripts (`escape_cef_header`,
`escape_cef_extension`):
- **Header fields** (vendor/product/version/signature/name): backslash
  escaped first, then pipe (`|`), since pipe is the header field separator.
- **Extension values**: backslash escaped first, then `=` (the
  key/value separator), then any newline/carriage-return.

`fetch-urlhaus.py` and `fetch-threatfox.py` only forward rows/IOCs added
within `LOOKBACK_HOURS` to avoid resending the whole feed every run — see
"Lookback / schedule" below for the current default and why it changed.

## ThreatFox requires a free Auth-Key

Unlike URLhaus/Feodo (plain anonymous CSV downloads), ThreatFox's API
requires a free Auth-Key — confirmed empirically: a request with no
`Auth-Key` header returns HTTP 401, and one with a present-but-wrong key
returns HTTP 403 with `query_status="unknown_auth_key"`. Get a free key at
<https://auth.abuse.ch/> and export it as `THREATFOX_AUTH_KEY` before
running `fetch-threatfox.py` (including `--dry-run` — the API requires the
key for every request, there's no anonymous read-only tier). The script
reads it from the `THREATFOX_AUTH_KEY` environment variable first; it is
never hardcoded or logged. In the cluster, it's supplied via a k3s Secret
referenced by the CronJob — see APPLY.md.

**Local, non-manual option:** if `THREATFOX_AUTH_KEY` isn't already in the
environment, the script falls back to reading it from a `.env` file next to
the script (`_read_dotenv_key()` — a minimal stdlib KEY=VALUE parser). On
this machine that `.env` isn't a plaintext file at rest: it's a FIFO
(`prw-------`, owner-only) created by the 1Password MCP server's
`create_local_env_file` against a 1Password Environment named
`threat-feed-fix` holding the real `THREATFOX_AUTH_KEY` secret — 1Password
serves the value on open rather than it sitting on disk. This means
`python3 fetch-threatfox.py --dry-run` works with no `export` at all, as
long as 1Password's local MCP server is running. If you ever want to check
or rotate the key, do it from 1Password's Developer settings or via the
`mcp__1password__*` tools — never by reading this `.env` directly.

## Deprecated: custom parser XML

`parsers/urlhausfeedmsg.xml`, `parsers/urlhausfeed-attr.xml`,
`parsers/feodotrackermsg.xml`, `parsers/feodotracker-attr.xml` are kept in
this repo for history only. **They are not deployed, not tested, and not
referenced by APPLY.md.** The custom-parser approach they represent never
extracted fields correctly and has been replaced by the CEF approach above.
If you ever want to retire them for good, nothing else in this project
depends on them.

Nothing in this project touches the lab. The fetch scripts only reach the
public abuse.ch feed URLs and (outside of `--dry-run`) the lab's syslog
listener at deploy time — neither is run against the lab from here. See
`APPLY.md` for the (unexecuted) deployment runbook.

## Layout

```
fetch-urlhaus.py          URLhaus fetch script, emits CEF (stdlib only, python:3-alpine)
fetch-feodo.py            Feodo fetch script, emits CEF (stdlib only, python:3-alpine)
fetch-threatfox.py        ThreatFox fetch script, emits CEF (stdlib only, python:3-alpine, needs THREATFOX_AUTH_KEY)
parsers/                  DEPRECATED — old custom-parser XML, not deployed (see above)
  urlhausfeedmsg.xml
  urlhausfeed-attr.xml
  feodotrackermsg.xml
  feodotracker-attr.xml
k8s/
  urlhaus-configmap.yaml     ConfigMap urlhaus-script (ns threat-intel, key fetch-urlhaus.py)
  feodo-configmap.yaml       ConfigMap feodo-script   (ns threat-intel, key fetch-feodo.py)
  threatfox-configmap.yaml   ConfigMap threatfox-script (ns threat-intel, key fetch-threatfox.py)
  threatfox-cronjob.yaml     NEW CronJob threatfox-threat-intel — unlike the other two, this
                              object doesn't already exist in the cluster; see APPLY.md before applying
tests/                     pytest suite, fixtures only, no network
APPLY.md                   deployment runbook — NOT executed, for you to run
```

## Lookback / schedule

`LOOKBACK_HOURS` in `fetch-urlhaus.py` defaults to **2** (hourly CronJob
cadence + 1h buffer for a missed run), overridable with `--lookback-hours`.
This is the main fix for the original dedupe problem (URLhaus resending
~34k events/hour, nearly all duplicates): at the old default of 26h, every
hourly run would resend roughly the last 26 hours of rows. `APPLY.md`
documents this as the recommended pairing (hourly schedule + 2h lookback),
with a daily (`0 6 * * *`) + longer-lookback schedule as an alternative if
you'd rather run it less often.

Feodo has no lookback filtering — it's a small IP blocklist, not a
duplicate-flood problem the way URLhaus's recent-URLs feed is.

`fetch-threatfox.py` defaults to `--days 1` (ThreatFox's own API-side
window, min 1/max 7) plus `--lookback-hours 2` on top, same role as
URLhaus's lookback: a local filter so an hourly CronJob with a 1h buffer
doesn't have to trust the API's day-granularity alone.

## Running the fetch scripts

```bash
python3 fetch-urlhaus.py --dry-run
python3 fetch-urlhaus.py --dry-run --lookback-hours 6
python3 fetch-feodo.py --dry-run
python3 fetch-threatfox.py --dry-run   # pulls THREATFOX_AUTH_KEY from 1Password automatically (see above)
# or, without the 1Password setup:
THREATFOX_AUTH_KEY="<your free key>" python3 fetch-threatfox.py --dry-run
```

`--dry-run` still fetches the feed over HTTPS but prints the would-be CEF
syslog lines and a summary instead of sending anything over UDP. Without
`--dry-run`, all three scripts send to `192.168.33.43:514` — that's the
real k3s CronJob behavior, not something to run casually from a
workstation.

**Verified live (this environment, no real key available):** with
`THREATFOX_AUTH_KEY` unset, `fetch-threatfox.py --dry-run` fails fast with
a clear message before touching the network. With a key set but invalid,
the script reaches the real `threatfox-api.abuse.ch` endpoint, confirming
the request shape (endpoint, header name, JSON body) is correct, and
surfaces the resulting `HTTP 403 Forbidden` cleanly instead of crashing.
A full successful fetch wasn't verified end-to-end — that needs a real
key, which wasn't available in this environment. Verify it once you have
one before relying on the CronJob.

## Running the tests

```bash
pip install pytest   # if not already available
python3 -m pytest tests/ -v
```

63 tests, all fixture-based — no network calls, no UDP sends, nothing that
touches `192.168.33.43` or the k3s cluster.

### Testing approach — what's real vs. approximated

- **Real fixture rows** (marked `# REAL` in the test files) are the two
  sample URLhaus rows given in the task:
  `id=3949637 url=http://219.157.238.6:35642/i ...` and
  `id=3949639 url=http://176.65.139.160/arm6 ...`. Every other field on
  those rows (`date_added`, `last_online`, `reference`) was not given and
  is marked `SYNTHETIC` — made up to exercise the lookback window.
  Feodotracker had no real sample row in the task, so all feodo test data
  is `SYNTHETIC`. ThreatFox's `test_build_line_domain_real_sample` uses
  abuse.ch's own documented example response (`id=41`, `gaga.com`,
  `win.dridex`) from <https://threatfox.abuse.ch/api/> — marked `REAL` in
  that test file; every other ThreatFox fixture is `SYNTHETIC`.
- **CEF output and escaping are tested exactly**, not approximated: each
  `build_line()` test asserts the full literal CEF string, including the
  `dst=`/`dhost=` branch, `cs1`/`cs1Label`, and severity `5`. Escaping is
  tested both in isolation (`TestCefEscaping` in each test file, feeding
  `escape_cef_header`/`escape_cef_extension` strings containing `|`, `=`,
  `\`, and newlines) and end-to-end through `build_line()` with a row
  whose `threat`/`malware` value contains one of those characters, to
  confirm escaping actually runs in the real code path and not just in a
  unit test of the helper.
- **No parser-matching simulation remains.** An earlier version of this
  project approximated NetWitness's envision matching engine with regex to
  test the (now-deprecated) custom parser XML. That's gone along with the
  custom-parser approach — CEF parsing is handled entirely by NetWitness's
  stock parser, which this project doesn't attempt to simulate. The real
  verification is `APPLY.md` step (e) (Investigate queries against real
  forwarded test events on your Hybrid).

## Assumptions / things not verified (see APPLY.md for the full list)

- The exact Parser Mapping menu path for NetWitness 12.5 (APPLY.md step (c)).
- The CronJob object names for urlhaus/feodo (not provided to this project).
- The `device.type` values (`abuse.ch_feodo`, `abuse.ch_urlhaus`) — taken
  as given/verified by you; not re-derived here.

## Auth-Key and the `abuse-ch-key` Secret

abuse.ch keys are **account-wide**: one key from <https://auth.abuse.ch/> works
for URLhaus and ThreatFox. **Regenerating it invalidates the old one everywhere**
(this caused a URLhaus HTTP 401 on 2026-11-08 when the key was rotated for
ThreatFox but the cluster Secret kept the old value).

- Cluster: Secret `abuse-ch-key` (namespace `threat-intel`, field `AUTH_KEY`),
  injected into the CronJobs as an environment variable. URLhaus reads
  `ABUSE_CH_AUTH_KEY`; ThreatFox reads `THREATFOX_AUTH_KEY`.
- Source of truth for the key itself: the 1Password Environment
  `threat-feed-fix`. Never commit a key; `.env` is git-ignored.
- To rotate: update 1Password first, then update the Secret with `read -rs`
  (no key in shell history), then run one manual job from each CronJob.
