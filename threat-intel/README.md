# threat-feed-fix

Fixes two abuse.ch threat-feed integrations into NetWitness.

## Current approach: CEF over syslog

Both `fetch-urlhaus.py` and `fetch-feodo.py` emit [CEF](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/common-event-format-v25/common-event-format-v25.pdf)
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

URLhaus uses `dst=` for an IPv4-hosted URL and `dhost=` for a hostname-hosted
one — same `classify_host()` logic as before, just a different output field.

Only `cs1`/`cs1Label` are used for the free-text malware/tag field —
`externalId`, `cn1`, `request`, `msg`, `reason`, and any other `csNLabel`
were verified **not** to map in this NetWitness instance and are
deliberately not used.

CEF escaping implemented in both scripts (`escape_cef_header`,
`escape_cef_extension`):
- **Header fields** (vendor/product/version/signature/name): backslash
  escaped first, then pipe (`|`), since pipe is the header field separator.
- **Extension values**: backslash escaped first, then `=` (the
  key/value separator), then any newline/carriage-return.

`fetch-urlhaus.py` still only forwards rows added within `LOOKBACK_HOURS`
to avoid resending the whole feed every run — see "Lookback / schedule"
below for the current default and why it changed.

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
parsers/                  DEPRECATED — old custom-parser XML, not deployed (see above)
  urlhausfeedmsg.xml
  urlhausfeed-attr.xml
  feodotrackermsg.xml
  feodotracker-attr.xml
k8s/
  urlhaus-configmap.yaml   ConfigMap urlhaus-script (ns threat-intel, key fetch-urlhaus.py)
  feodo-configmap.yaml     ConfigMap feodo-script   (ns threat-intel, key fetch-feodo.py)
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

## Running the fetch scripts

```bash
python3 fetch-urlhaus.py --dry-run
python3 fetch-urlhaus.py --dry-run --lookback-hours 6
python3 fetch-feodo.py --dry-run
```

`--dry-run` still fetches the public CSV over HTTPS but prints the would-be
CEF syslog lines and a summary instead of sending anything over UDP.
Without `--dry-run`, both scripts send to `192.168.1.43:514` — that's the
real k3s CronJob behavior, not something to run casually from a
workstation.

## Running the tests

```bash
pip install pytest   # if not already available
python3 -m pytest tests/ -v
```

35 tests, all fixture-based — no network calls, no UDP sends, nothing that
touches `192.168.1.43` or the k3s cluster.

### Testing approach — what's real vs. approximated

- **Real fixture rows** (marked `# REAL` in the test files) are the two
  sample URLhaus rows given in the task:
  `id=3949637 url=http://219.157.238.6:35642/i ...` and
  `id=3949639 url=http://176.65.139.160/arm6 ...`. Every other field on
  those rows (`date_added`, `last_online`, `reference`) was not given and
  is marked `SYNTHETIC` — made up to exercise the lookback window.
  Feodotracker had no real sample row in the task, so all feodo test data
  is `SYNTHETIC`.
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
