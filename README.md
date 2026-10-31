# SOC Shift Simulator

An incident-investigation training range in a box. It spins up a realistic
small-company network, replays a multi-stage intrusion buried inside a full
shift of normal activity, and hands you a query CLI. You investigate, file a
case report, and get graded against hidden ground truth.

**Everything is synthetic log data. Nothing executes any attack.**

## Why this exists

SOC L1 interviews almost always ask some version of *"walk me through an
investigation."* Reading about the kill chain isn't the same as pivoting
through 3,000 log lines, spotting the beacon in the browsing noise, and tying
an LSASS dump to a lateral move. This gives you reps: deterministic cases you
can run, solve, and re-run, with an answer key for one of them.

Built around the data a blue-teamer actually reads — Windows Security events,
Sysmon, firewall/VPN/proxy/DNS, email gateway — using the real field names
(`Image`, `CommandLine`, `ParentImage`, `TargetFilename`, `QueryName`,
`LogonType`, `IpAddress`, `TargetUserName`, ...) plus a few normalized
SIEM-style common fields (`time`, `source`, `host`, `user`) so you can pivot
across sources. Network sources use ECS-like flat names. Techniques are mapped
to **MITRE ATT&CK v20.0**.

## Quickstart

```bash
pip install -e .            # Python 3.13+, standard library only
sim start --scenario 1 --seed 1337
```

That writes `cases/s1-seed1337/` containing `logs.jsonl`, `logs.csv`, and a
`case-report.yaml` to fill in, and starts the clock. Investigate:

```bash
sim query --case cases/s1-seed1337 "source=email verdict=delivered | fields time,sender,recipient,attachment"
sim query --case cases/s1-seed1337 "source=sysmon event_id=1 host=WS-07 ParentImage~EXCEL | fields time,user,CommandLine"
sim query --case cases/s1-seed1337 "source=sysmon event_id=3 host=WS-07 | count by DestinationIp"
sim query --case cases/s1-seed1337 "source=proxy method=POST host=WS-07 | count by url"
```

Stuck? `sim hint --case cases/s1-seed1337` reveals the next step of the true
timeline, at -5 points each. Fill in `case-report.yaml`, then grade:

```bash
sim grade --case cases/s1-seed1337
```

You get a scored breakdown in the terminal (with time on case) and a
`debrief.html` showing the true attack timeline next to what you filed.

### Use it in Splunk or Elastic instead

The logs are plain JSONL/CSV. For Splunk:

```bash
sim export --case cases/s1-seed1337 --splunk
```

writes one JSON file per source plus a `props.conf` with a sourcetype each
(`socsim:sysmon`, `socsim:security`, ...). The scenario-1 queries are
translated to SPL in [`docs/walkthrough-1-spl.md`](docs/walkthrough-1-spl.md).

### Query language

Pipe-separated. A filter, then optional operators:

```
source=sysmon event_id=1 host=WS-07 time>=2026-10-20T08:00:00 | fields time,user,CommandLine
source=vpn action=fail | count by user
source=proxy method=POST | sort -bytes_out | head 10
"CommandLine~Domain Admins"            # quote a value that has spaces
```

Filter operators: `=` `!=` `~` (contains) `!~` `>=` `<=` `>` `<` (times are
compared as timestamps, numbers as numbers). Operators: `fields a,b,c`,
`count by <field>`, `sort <field>` / `sort -<field>`, `head N`. Bad syntax
gives a usage error, not a traceback.

## Scenarios

| # | Scenario | Kill chain (ATT&CK v20) |
|---|----------|--------------------------|
| 1 | Phishing to exfil | T1566.001 → T1204.002 → T1059.001 → T1071.001 → T1003.001 → T1021.002 → T1074.001 → T1567.002 |
| 2 | VPN spray to ransomware precursor | T1110.003 → T1133 → T1136.001 → T1098 → T1490 → T1486 → **T1685.005** (log clearing) |
| 3 | Web shell to DNS tunnelling | T1190 → T1505.003 → T1059.003 → T1087.002 / T1083 → T1071.004 |

> Log clearing is **T1685.005** in ATT&CK v19+ (the old `T1070.001` was
> removed). Scenario 2 uses the current ID.

A full worked answer key for scenario 1 — the actual queries that solve it — is
in [`docs/walkthrough-1.md`](docs/walkthrough-1.md).

### The attack is not separable by one filter

The benign shift deliberately contains the same event types the attacks use:
10–20 delivered partner emails with attachments, 20–40 normal network (type 3)
logons to the file server, Teams/SharePoint `POST` uploads of 50–900 KB, a
midday backup job pushing ~100 MB chunks offsite, Sysmon 3/11/22 for Chrome,
Outlook and Office temp files, and a benign HR account creation. The web server
has its own baseline: customer requests in IIS W3C format (`source=iis`:
`c_ip`, `cs_method`, `cs_uri_stem`, `cs_uri_query`, `sc_status`, ...), app-pool
recycles, an `iisreset`, ASP.NET `csc.exe`/`cvtres.exe` compiles as `w3wp.exe`
children, a scheduled `cscript`, CRL/OCSP lookups and IIS log-roll writes.
Attack timestamps have jittered seconds. Every stage needs a pivot from the
previous one (patient-zero IP, the C2 domain, a parent process), which is what
the exercise is for. Grading uses Jaccard overlap for list fields, so listing
every technique in this README scores well under half.

## The network — Khobar Logistics Co. (fictional)

AD domain `khobar.local`: 2 domain controllers, a file server, a web server,
an email gateway, firewall, VPN gateway, and 25 workstations with named staff.
Normal traffic has a daily rhythm (morning logon spike, lunch dip).

## Screenshots

Example `sim grade` output:

```
Score: 90.0 / 100  (scenario 1)
  raw 100.0 minus 10 for 2 hint(s)
  time on case: 41m 12s

  [15.0/15 ] patient_zero_host      correct
  [15.0/15 ] initial_access_time    within 0s of truth
  [15.0/15 ] compromised_accounts   found 2/2
  [10.0/10 ] c2_ip                  correct
  [10.0/10 ] c2_domain              correct
  [20.0/20 ] attack_techniques      found 8/8
  [15.0/15 ] exfil_bytes            within 0% of 4718592

Debrief written to cases/s1-seed1337/debrief.html
```

The HTML debrief is a plain dark-themed report: a scorecard table and the true
attack timeline. Open `debrief.html` in a browser after grading.

## Limits

- Logs are **emulated**, not captured from a real Sysmon/WEF pipeline. Field
  coverage is enough to investigate, not exhaustive (e.g. LSASS access is shown
  via the process-creation event, not Sysmon event ID 10; 4688 is represented
  by Sysmon event 1).
- The scenario-2 password spray (T1110.003) is visible **only in the VPN
  gateway rows** (`source=vpn action=fail`); there are no matching 4625/4771
  on the domain controllers.
- Three scenarios, one answer key (scenario 1). Grading is six fields plus
  techniques, not a free-text narrative.
- The YAML case-report reader is a tiny fixed-schema subset, not full YAML.
- Single-shift timeframe (08:00–16:00, one day). The timer uses wall-clock
  time from `sim start` to `sim grade`.

## Roadmap

- More scenarios (insider, cloud/identity, supply chain).
- Sigma rule export so trainees can write and test detections against a case.
- A detection-scoring mode (did your rule fire on the true positive without
  drowning in the noise?).
- Answer keys for scenarios 2 and 3.

## License

MIT, Abdulmohsen Alharbi. See [LICENSE](LICENSE).
