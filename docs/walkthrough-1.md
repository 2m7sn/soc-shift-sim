# Answer key — Scenario 1 (phishing → exfil)

A worked investigation of scenario 1, seed 1337. Generate the case first:

```
sim start --scenario 1 --seed 1337
```

That writes `cases/s1-seed1337/` (`logs.jsonl`, `logs.csv`, `case-report.yaml`)
and starts the timer. Run every query below with:

```
sim query --case cases/s1-seed1337 "<query>"
```

The queries here are exactly the ones `tests/test_e2e.py` runs against the
generated logs, so this walkthrough stays honest: if the generator drifts, the
test fails. Nothing below is a one-filter win; each stage needs a pivot from
the previous one, which is the point. Splunk SPL equivalents are in
[`walkthrough-1-spl.md`](walkthrough-1-spl.md).

---

## 1. Triage — any malicious email?

```
source=email verdict=delivered | fields time,sender,recipient,subject,attachment
```

Twenty-odd delivered mails from partners (aramex, dpworld, sabic, internal).
Scan the attachments: PDFs, xlsx, docx — and one macro-enabled **`.xlsm`**.
Narrow:

```
source=email attachment~xlsm | fields time,sender,recipient,subject
```

One hit at **08:14:45** to `f.alharbi@khobar.local` from
`billing@khobar-loglstics.com` — a look-alike of the company's own domain
(`loglstics`, with an L). Working hypothesis: patient-zero user is
**f.alharbi**; her workstation is **WS-07**.

→ ATT&CK **T1566.001** Spearphishing Attachment.

## 2. What did the attachment do?

```
source=sysmon event_id=1 host=WS-07 ParentImage~EXCEL | fields time,user,Image,CommandLine
```

At **08:17:43**, `EXCEL.EXE` spawns `powershell.exe -nop -w hidden -enc ...`
as f.alharbi. Office spawning PowerShell with an encoded command is the macro
firing. **Initial access time = 2026-10-20T08:17:43.** Forty seconds later a
second PowerShell runs an `IEX (New-Object Net.WebClient).DownloadString(...)`
cradle against `cdn-telemetry-sync.net`.

→ **T1204.002** User Execution: Malicious File, **T1059.001** PowerShell.

## 3. Command and control

```
source=sysmon event_id=3 host=WS-07 | count by DestinationIp
source=sysmon event_id=22 host=WS-07 | count by QueryName
```

WS-07 talks to a couple of dozen destinations today (Chrome, Outlook, Teams,
the file server) — but one IP, **185.220.101.47**, gets ~70 connections,
every ~60 seconds, from `powershell.exe`, while the DNS log shows
**cdn-telemetry-sync.net** resolved the same ~70 times. Steady, periodic, from
PowerShell: that is a beacon, not browsing.

→ **T1071.001** Application Layer Protocol: Web Protocols.

## 4. Credential access

```
source=sysmon event_id=1 CommandLine~lsass | fields time,host,user,CommandLine
```

At **08:55:58**, `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 648
C:\ProgramData\lsass.dmp full` — an LSASS memory dump to harvest credentials.

→ **T1003.001** OS Credential Dumping: LSASS Memory.

## 5. Lateral movement

Network (type 3) logons to the file server are normal all day — ~40 of them —
so filter on the patient-zero IP instead of the logon type alone:

```
source=security event_id=4624 LogonType=3 IpAddress=10.20.10.7 | fields time,host,user
```

Two rows from WS-07 (10.20.10.7): f.alharbi's own share access later in the
day, and at **09:10:22** a logon on **FS-01** as **svc_backup** — a service
account that normally only logs on locally as a service (LogonType 5 at
12:00). A service account authenticating from a user workstation right after
an LSASS dump is the dumped credential being reused. The matching Sysmon
event 3 from WS-07 to 10.20.0.20:445 via `net.exe` confirms SMB.

→ **T1021.002** Remote Services: SMB/Windows Admin Shares. Compromised
accounts: **f.alharbi, svc_backup**.

## 6. Staging and exfiltration

```
source=sysmon event_id=11 host=WS-07 TargetFilename~ProgramData | fields time,TargetFilename
```

Office writes temp files all day, but at **09:25:11** PowerShell writes
`C:\ProgramData\staging\khobar_export.7z`. Then check what WS-07 uploaded:

```
source=proxy method=POST host=WS-07 | count by url
source=proxy method=POST url~cdn-telemetry-sync | fields time,bytes_out
```

Over a hundred POSTs happen today (Teams/SharePoint uploads, the backup job's
~100 MB chunks to `backup.khobar-cloud.sa`). WS-07's POSTs are mostly Office
365 — plus **six to `https://cdn-telemetry-sync.net/upload`**, the C2 domain,
768 KiB each between 09:40 and 09:42: **4,718,592 bytes** exfiltrated.

→ **T1074.001** Local Data Staging, **T1567.002** Exfiltration to Cloud Storage.

---

## Filled case report

```yaml
scenario: 1
patient_zero_host: WS-07
initial_access_time: 2026-10-20T08:17:43
compromised_accounts:
  - f.alharbi
  - svc_backup
c2_ip: 185.220.101.47
c2_domain: cdn-telemetry-sync.net
attack_techniques:
  - T1566.001
  - T1204.002
  - T1059.001
  - T1071.001
  - T1003.001
  - T1021.002
  - T1074.001
  - T1567.002
exfil_bytes: 4718592
```

`sim grade --case cases/s1-seed1337` scores this 100/100 (minus 5 per
`sim hint` used) and writes `debrief.html`.
