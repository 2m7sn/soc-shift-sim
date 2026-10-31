# Scenario 1 in Splunk SPL

The same investigation as [`walkthrough-1.md`](walkthrough-1.md), translated
to SPL. Export the case first:

```
sim export --case cases/s1-seed1337 --splunk
```

That writes `cases/s1-seed1337/export/splunk/<source>.json` (one file per log
source) and a `props.conf` defining sourcetypes `socsim:security`,
`socsim:sysmon`, `socsim:proxy`, `socsim:dns`, `socsim:email`, `socsim:vpn`,
`socsim:firewall` (JSON extraction, `time` as the timestamp, `TZ = Asia/Riyadh`).
Add the props to an app, then upload each file with its sourcetype into one
index (below: `index=socsim`).

| Step | `sim query` | SPL |
|---|---|---|
| 1 | `source=email verdict=delivered \| fields time,sender,recipient,subject,attachment` | `index=socsim sourcetype=socsim:email verdict=delivered \| table time sender recipient subject attachment` |
| 1 | `source=email attachment~xlsm \| fields time,sender,recipient,subject` | `index=socsim sourcetype=socsim:email attachment="*xlsm*" \| table time sender recipient subject` |
| 2 | `source=sysmon event_id=1 host=WS-07 ParentImage~EXCEL \| fields time,user,Image,CommandLine` | `index=socsim sourcetype=socsim:sysmon event_id=1 host=WS-07 ParentImage="*EXCEL*" \| table time user Image CommandLine` |
| 3 | `source=sysmon event_id=3 host=WS-07 \| count by DestinationIp` | `index=socsim sourcetype=socsim:sysmon event_id=3 host=WS-07 \| stats count by DestinationIp \| sort -count` |
| 3 | `source=sysmon event_id=22 host=WS-07 \| count by QueryName` | `index=socsim sourcetype=socsim:sysmon event_id=22 host=WS-07 \| stats count by QueryName \| sort -count` |
| 4 | `source=sysmon event_id=1 CommandLine~lsass \| fields time,host,user,CommandLine` | `index=socsim sourcetype=socsim:sysmon event_id=1 CommandLine="*lsass*" \| table time host user CommandLine` |
| 5 | `source=security event_id=4624 LogonType=3 IpAddress=10.20.10.7 \| fields time,host,user` | `index=socsim sourcetype=socsim:security event_id=4624 LogonType=3 IpAddress=10.20.10.7 \| table time host user` |
| 6 | `source=sysmon event_id=11 host=WS-07 TargetFilename~ProgramData \| fields time,TargetFilename` | `index=socsim sourcetype=socsim:sysmon event_id=11 host=WS-07 TargetFilename="*ProgramData*" \| table time TargetFilename` |
| 6 | `source=proxy method=POST host=WS-07 \| count by url` | `index=socsim sourcetype=socsim:proxy method=POST host=WS-07 \| stats count by url \| sort -count` |
| 6 | `source=proxy method=POST url~cdn-telemetry-sync \| fields time,bytes_out` | `index=socsim sourcetype=socsim:proxy method=POST url="*cdn-telemetry-sync*" \| stats sum(bytes_out) AS exfil_bytes` |

Two SPL-only extras worth knowing for the interview:

```
# beacon regularity: gaps between connections to the C2 IP
index=socsim sourcetype=socsim:sysmon event_id=3 host=WS-07 DestinationIp=185.220.101.47
| sort 0 _time | delta _time AS gap | stats avg(gap) stdev(gap) count

# the whole kill chain on one timeline
index=socsim (host=WS-07 OR host=FS-01) (CommandLine="*-enc*" OR CommandLine="*lsass*"
  OR (event_id=4624 LogonType=3 IpAddress=10.20.10.7) OR url="*cdn-telemetry-sync*"
  OR TargetFilename="*staging*")
| table _time sourcetype host user CommandLine url TargetFilename | sort _time
```

Notes: `sim query`'s `~` is a case-insensitive substring; Splunk's `*wild*`
match on an indexed JSON field is also case-insensitive by default. The
simulator has no `sum` operator — in SPL use `stats sum(bytes_out)`; in `sim
query` project `bytes_out` and add the six rows.
