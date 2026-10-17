# APPLY.md — deployment runbook

**Nothing in this file has been executed by the assistant.** It touches the
NetWitness Hybrid and the k3s cluster, both out of bounds for this session.
Run each step yourself, in order, and confirm each one worked before moving
to the next.

**Strategy change from the earlier version of this runbook:** the custom
`urlhausfeed`/`feodotracker` NetWitness parsers never extracted fields
(verified empirically). Both feeds now emit CEF over syslog instead, and
NetWitness's stock CEF parser auto-detects and parses them — no custom
parser XML is deployed. The old `parsers/*.xml` files stay in this repo for
history but are **deprecated** (see README) and are not touched by any step
below.

All commands below assume GNU coreutils (`stat -c`, `date -u`) on the Hybrid.
If the Hybrid is BSD-flavored, adjust `stat` flags accordingly (`stat -f`).

---

## Chosen schedule / lookback pairing

**Recommended and assumed by every step below: keep the existing hourly
CronJob schedule, with `fetch-urlhaus.py --lookback-hours 2`** (the
script's new default — see `fetch-urlhaus.py`). 2 hours = 1 hour cadence +
1 hour buffer for a missed run, which is enough to not drop events without
re-sending the whole feed every run.

**Alternative, not what's configured below:** a daily schedule
(`schedule: "0 6 * * *"` in the CronJob spec) with a longer lookback (e.g.
26h, the old default) also works and runs the job far less often. If you'd
rather do that, change the CronJob's `spec.schedule` and pass
`--lookback-hours 26` (or similar) in its `args` instead of leaving the
2-hour default — don't do both at once, or hourly-with-2h-lookback runs
will just resend each other's gaps unnecessarily, and daily-with-2h-lookback
will drop ~22 hours of events every run.

Feodo has no lookback filtering (unchanged, it's a small IP blocklist, not
a duplicate-flood problem) — its schedule choice doesn't interact with
`fetch-urlhaus.py`'s lookback math and isn't addressed by this section.

**Note: hourly + 2h lookback still produces ~2x duplicate events, by
design** — each row that was already sent in the previous run gets sent
again in the next one, since the 1-hour buffer deliberately overlaps the
prior run's window (that overlap is what keeps a missed run from losing
events). This is a large improvement over the original ~34k/hour full-feed
resend, but it is not zero-duplicate. Any consumer of these events (SIEM
correlation rule, downstream alerting, etc.) should dedupe on `id` (URLhaus)
rather than assume each forwarded row is unique.

---

## (a) Suspend the urlhaus CronJob

Stop new runs from firing mid-change, so the ConfigMap/parser-mapping work
below happens against a known-quiet state:

```bash
sudo k3s kubectl patch cronjob urlhaus-threat-intel -n threat-intel -p '{"spec":{"suspend":true}}'
```

## (b) Back up, then apply both ConfigMaps

Back up whatever's currently live, so there's something concrete to roll
back to in step (f)'s rollback:

```bash
mkdir -p ~/threat-feed-fix-backup-$(date -u +%Y%m%d-%H%M%S)
cd ~/threat-feed-fix-backup-$(date -u +%Y%m%d-%H%M%S)
sudo k3s kubectl get configmap urlhaus-script -n threat-intel -o yaml > urlhaus-configmap.before.yaml
sudo k3s kubectl get configmap feodo-script   -n threat-intel -o yaml > feodo-configmap.before.yaml 2>/dev/null || \
  echo "feodo-script ConfigMap doesn't exist yet — nothing to back up, it's new"
```

Then apply the new ones (from this project's directory):

```bash
sudo k3s kubectl apply -f k8s/urlhaus-configmap.yaml
sudo k3s kubectl apply -f k8s/feodo-configmap.yaml
```

This only updates ConfigMap content — it does not restart anything. The
mounted file in any already-running pod won't change until the next
CronJob-spawned Pod starts (ConfigMap volume mounts refresh on pod start,
not instantly). That's fine here since step (d) triggers fresh manual Jobs
anyway.

## (c) Delete the three Parser Mappings so the stock CEF parser auto-detects

In the NetWitness UI, remove these IP → custom-parser mappings:

| Source IP | Mapped parser (to remove) |
|---|---|
| 192.168.1.222 | urlhausfeed |
| 192.168.1.243 | urlhausfeed |
| 192.168.1.173 | feodotracker |

**Path:** Admin > Services > EndpointLogHybrid - Log Decoder > Config >
Parser Mappings tab. Removing a mapping here (rather than disabling the
parser outright) lets the stock CEF parser pick up events from these
sources by auto-detection instead. The stock CEF parser being enabled on
this Log Decoder is already verified — no need to re-check that.

Note the current mapped parser for each IP somewhere before deleting, in
case rollback needs to recreate them exactly.

## (d) Run one manual job per feed

Trigger a single on-demand run of each CronJob rather than waiting for the
schedule, so you can watch one clean test cycle:

```bash
sudo k3s kubectl create job --from=cronjob/urlhaus-threat-intel urlhaus-manual-test -n threat-intel
sudo k3s kubectl create job --from=cronjob/feodo-threat-intel   feodo-manual-test   -n threat-intel
```

Watch each job's logs to confirm it ran cleanly:

```bash
sudo k3s kubectl logs -n threat-intel job/urlhaus-manual-test
sudo k3s kubectl logs -n threat-intel job/feodo-manual-test
```

## (e) Verify in Investigate

```
device.type='abuse.ch_feodo' && ip.dst exists
device.type='abuse.ch_urlhaus' && (ip.dst exists || host.dst exists)
```

Remember retention is 7 days. If `device.type` doesn't show up as
`abuse.ch_feodo` / `abuse.ch_urlhaus` at all, the parser mapping in step
(c) likely wasn't fully removed — the stock CEF parser being enabled is
already verified, so that's not the thing to re-check here.

## (f) Unsuspend the urlhaus CronJob

```bash
sudo k3s kubectl patch cronjob urlhaus-threat-intel -n threat-intel -p '{"spec":{"suspend":false}}'
```

---

## Rollback

```bash
# 1. Restore the ConfigMaps from the backup taken in step (b)
sudo k3s kubectl apply -f ~/threat-feed-fix-backup-<timestamp>/urlhaus-configmap.before.yaml
sudo k3s kubectl apply -f ~/threat-feed-fix-backup-<timestamp>/feodo-configmap.before.yaml
# if feodo-script didn't exist before, delete it instead of applying a backup that doesn't exist:
sudo k3s kubectl delete configmap feodo-script -n threat-intel

# 2. Re-create the three Parser Mappings removed in step (c), pointing each
#    IP back at its original custom parser (whatever you noted before deleting):
#      192.168.1.222 -> urlhausfeed
#      192.168.1.243 -> urlhausfeed
#      192.168.1.173 -> feodotracker

# 3. Re-suspend/unsuspend as needed and re-run a manual job per feed to confirm
#    the old custom-parser path is back (device.type set, fields still empty,
#    same as before this change — that was the known-broken baseline).
```

---

## What is NOT verified in this change set

- **`device.type` values** (`abuse.ch_feodo`, `abuse.ch_urlhaus`) — taken
  as given/verified by you; this runbook doesn't re-derive them.

Resolved since the previous version of this runbook: CronJob object names
(`urlhaus-threat-intel`, `feodo-threat-intel`), the Parser Mappings menu
path (Admin > Services > EndpointLogHybrid - Log Decoder > Config > Parser
Mappings tab), and the stock CEF parser being enabled on this Log Decoder
are all now given/verified rather than placeholders.
