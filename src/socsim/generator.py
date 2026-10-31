"""Seeded, deterministic telemetry generator.

generate(scenario, seed) -> (events, truth)

events: list of flat dicts sorted by time. Common normalized keys on every
event: time (ISO seconds), source, host, and where applicable user. Source
specific fields keep their REAL names:
  sysmon   : Image, CommandLine, ParentImage, DestinationIp, DestinationPort,
             TargetFilename, TargetObject, QueryName, QueryResults
  security : LogonType, IpAddress, TargetUserName, SubjectUserName,
             ServiceName, Status
  network  : ECS-like flat names (src_ip, dest_ip, dest_port, bytes_out ...)

Determinism: identical (scenario, seed) yields byte-identical JSONL. Only the
passed Random instance is used; no wall-clock, no os randomness.

The benign noise deliberately covers every pivot the scenarios use (POST
uploads, type-3 logons to the file server, Sysmon 3/11/22, delivered emails,
large transfers) so no attack stage is separable by a single filter.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from . import environment as env
from .scenarios import build_scenario

_BASE = datetime(2026, 10, 20, 0, 0, 0)

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
TEAMS = r"C:\Program Files\Microsoft\Teams\current\Teams.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
W3WP = r"C:\Windows\System32\inetsrv\w3wp.exe"


def _iso(seconds_from_midnight: float) -> str:
    return (_BASE + timedelta(seconds=int(seconds_from_midnight))).strftime("%Y-%m-%dT%H:%M:%S")


def _shift_seconds(rng: random.Random) -> float:
    """A second-of-day inside the 08:00-16:00 shift, weighted by a daily rhythm.

    Busier at start of day and after lunch; dip around 12:00-13:00.
    """
    start = env.SHIFT_START_HOUR * 3600
    end = (env.SHIFT_START_HOUR + env.SHIFT_HOURS) * 3600
    while True:
        t = rng.uniform(start, end)
        hour = t / 3600
        w = 0.5 + 0.5 * (abs(hour - 9) < 1.5) + 0.4 * (abs(hour - 14) < 1.5)
        if 12 <= hour <= 13:
            w *= 0.3
        if rng.random() < w:
            return t


def _ext_ip(rng) -> str:
    return "52.109.%d.%d" % (rng.randint(1, 254), rng.randint(1, 254))


def _logons(rng, add):
    """Morning interactive logons (4624) plus mistyped passwords (4625), 4769 tickets."""
    for sam, _d, _dept, ws in env.STAFF:
        t = rng.uniform(7.75 * 3600, 9.25 * 3600)
        if rng.random() < 0.25:
            for _ in range(rng.randint(1, 2)):
                add(dict(time=_iso(t - rng.uniform(5, 60)), source="security", event_id=4625,
                         host=ws, user=sam, TargetUserName=sam, LogonType=2,
                         IpAddress=env.host_ip(ws), Status="0xC000006A"))
        add(dict(time=_iso(t), source="security", event_id=4624, host=ws, user=sam,
                 TargetUserName=sam, LogonType=2, IpAddress=env.host_ip(ws)))
        for _ in range(rng.randint(2, 6)):
            add(dict(time=_iso(_shift_seconds(rng)), source="security", event_id=4769,
                     host=rng.choice(env.DCS), user=sam, TargetUserName=sam,
                     ServiceName=rng.choice(["FS-01$", "WEB-01$", "krbtgt", "DC-01$"]),
                     IpAddress=env.host_ip(ws)))


def _file_server_access(rng, add):
    """Normal SMB share access: 20-40 network (type 3) logons to FS-01 with matching Sysmon 3."""
    for _ in range(rng.randint(20, 40)):
        sam = rng.choice(env.USERNAMES)
        ws = env.user_host(sam)
        t = _shift_seconds(rng)
        add(dict(time=_iso(t), source="sysmon", event_id=3, host=ws, user=sam, Image=EXPLORER,
                 DestinationIp=env.host_ip(env.FILE_SERVER), DestinationPort=445, Protocol="tcp"))
        add(dict(time=_iso(t + 1), source="security", event_id=4624, host=env.FILE_SERVER, user=sam,
                 TargetUserName=sam, LogonType=3, IpAddress=env.host_ip(ws)))


def _processes(rng, add):
    apps = [(OUTLOOK, EXPLORER), (CHROME, EXPLORER), (EXCEL, EXPLORER), (WINWORD, EXPLORER),
            (r"C:\Windows\System32\cmd.exe", EXPLORER), (TEAMS, EXPLORER),
            (r"C:\Windows\System32\notepad.exe", EXPLORER),
            (PS, EXPLORER)]  # admins and power users do open PowerShell
    for sam, _d, dept, ws in env.STAFF:
        for _ in range(rng.randint(8, 20)):
            image, parent = rng.choice(apps)
            if image == PS and dept != "IT-Admin" and rng.random() < 0.7:
                image, parent = CHROME, EXPLORER
            add(dict(time=_iso(_shift_seconds(rng)), source="sysmon", event_id=1, host=ws,
                     user=sam, Image=image, ParentImage=parent, CommandLine=f'"{image}"'))
        # Office temp files (Sysmon 11)
        for _ in range(rng.randint(2, 6)):
            app = rng.choice([WINWORD, EXCEL])
            name = rng.choice(["~$Q4_plan.xlsx", "~WRL%04d.tmp" % rng.randint(0, 9999),
                               "~$shipment_notes.docx", "%08X.tmp" % rng.randint(0, 0xFFFFFFFF)])
            add(dict(time=_iso(_shift_seconds(rng)), source="sysmon", event_id=11, host=ws,
                     user=sam, Image=app,
                     TargetFilename=rf"C:\Users\{sam}\AppData\Local\Temp\{name}"))


def _network(rng, add):
    for sam, _d, _dept, ws in env.STAFF:
        for _ in range(rng.randint(10, 25)):
            dom = rng.choice(env.BENIGN_DOMAINS)
            t = _shift_seconds(rng)
            ip = _ext_ip(rng)
            app = rng.choice([CHROME, OUTLOOK, TEAMS])
            add(dict(time=_iso(t), source="dns", host=ws, query_name=dom, query_type="A", answer=ip))
            add(dict(time=_iso(t), source="sysmon", event_id=22, host=ws, user=sam, Image=app,
                     QueryName=dom, QueryStatus=0, QueryResults=ip))
            add(dict(time=_iso(t + 1), source="sysmon", event_id=3, host=ws, user=sam, Image=app,
                     DestinationIp=ip, DestinationPort=443, Protocol="tcp"))
            add(dict(time=_iso(t + 1), source="proxy", host=ws, user=sam, url="https://" + dom + "/",
                     method="GET", status_code=200, bytes_out=rng.randint(400, 3000),
                     bytes_in=rng.randint(2000, 90000)))
            add(dict(time=_iso(t), source="firewall", action="allow", src_ip=env.host_ip(ws),
                     dest_ip=ip, dest_port=443, proto="tcp"))
        # Teams / OneDrive / SharePoint uploads: POSTs of 50-900 KB
        for _ in range(rng.randint(2, 6)):
            dom = rng.choice(["teams.microsoft.com", "khobarlogistics-my.sharepoint.com",
                              "outlook.office365.com"])
            add(dict(time=_iso(_shift_seconds(rng)), source="proxy", host=ws, user=sam,
                     url=f"https://{dom}/{rng.choice(['api/upload', 'personal/upload', 'owa/attach'])}",
                     method="POST", status_code=rng.choice([200, 201]),
                     bytes_out=rng.randint(50_000, 900_000), bytes_in=rng.randint(200, 2000)))
        if rng.random() < 0.3:
            add(dict(time=_iso(_shift_seconds(rng)), source="firewall", action="deny",
                     src_ip=env.host_ip(ws), dest_ip="203.0.113.%d" % rng.randint(1, 254),
                     dest_port=rng.choice([23, 445, 3389]), proto="tcp"))


def _vpn(rng, add):
    for sam in rng.sample(env.USERNAMES, 5):
        t = rng.uniform(7.5 * 3600, 9 * 3600)
        src = "94.207.%d.10" % rng.randint(1, 254)
        if rng.random() < 0.3:
            add(dict(time=_iso(t - 30), source="vpn", host=env.VPN_GW, user=sam, action="fail", src_ip=src))
        add(dict(time=_iso(t), source="vpn", host=env.VPN_GW, user=sam, action="success", src_ip=src))


def _email(rng, add):
    partners = ["aramex.com", "dpworld.com", "sabic.com", "almarai.com", "zakat.gov.sa",
                "bupa.com.sa", "stc.com.sa", "khobar.local"]
    subjects = ["Shipment schedule week 43", "Invoice INV-20%03d", "Customs clearance docs",
                "Updated rate card", "Q4 planning deck", "Fleet maintenance report",
                "Payroll cut-off reminder", "RE: container ETA Dammam"]
    attachments = ["", "", "schedule.pdf", "rates.xlsx", "report.docx", "invoice.pdf"]
    for _ in range(rng.randint(10, 20)):
        subj = rng.choice(subjects)
        if "%03d" in subj:
            subj = subj % rng.randint(100, 999)
        add(dict(time=_iso(_shift_seconds(rng)), source="email", host=env.MAIL_GW,
                 sender=f"{rng.choice(['ops', 'billing', 'hr', 'noreply', 'sales'])}@{rng.choice(partners)}",
                 recipient=f"{rng.choice(env.USERNAMES)}@khobar.local", subject=subj,
                 verdict="delivered", attachment=rng.choice(attachments)))
    for _ in range(rng.randint(2, 4)):
        add(dict(time=_iso(_shift_seconds(rng)), source="email", host=env.MAIL_GW,
                 sender=f"promo@{rng.choice(['dealz-now.biz', 'win-prize.top'])}",
                 recipient=f"{rng.choice(env.USERNAMES)}@khobar.local", subject="You have been selected",
                 verdict="quarantined", attachment=""))


def _scheduled_jobs(rng, add):
    """Midday backup (big offsite transfer), a benign HR account creation, patch noise."""
    add(dict(time=_iso(12 * 3600), source="security", event_id=4624, host=env.FILE_SERVER,
             user="svc_backup", TargetUserName="svc_backup", LogonType=5,
             IpAddress=env.host_ip(env.FILE_SERVER)))
    add(dict(time=_iso(12 * 3600 + 5), source="sysmon", event_id=1, host=env.FILE_SERVER,
             user="svc_backup", Image=r"C:\Windows\System32\robocopy.exe", ParentImage=SVCHOST,
             CommandLine=r"robocopy D:\Shares E:\Backup /MIR /R:1"))
    for i in range(4):  # offsite copy: several 40-120 MB POSTs
        add(dict(time=_iso(12 * 3600 + 120 + i * 90), source="proxy", host=env.FILE_SERVER,
                 user="svc_backup", url="https://backup.khobar-cloud.sa/api/v2/chunk",
                 method="POST", status_code=201, bytes_out=rng.randint(40_000_000, 120_000_000),
                 bytes_in=512))
    # HR onboarding: admin creates a normal user (benign 4720, no admin group add)
    actor = rng.choice(env.ADMINS)
    add(dict(time=_iso(rng.uniform(10 * 3600, 11 * 3600)), source="security", event_id=4720,
             host="DC-01", user=actor, SubjectUserName=actor, TargetUserName="n.sulaiman"))
    for ws in rng.sample(env.WORKSTATIONS, 8):
        add(dict(time=_iso(_shift_seconds(rng)), source="sysmon", event_id=1, host=ws, user="SYSTEM",
                 Image=r"C:\Windows\System32\wuauclt.exe", ParentImage=SVCHOST,
                 CommandLine=r"wuauclt.exe /UpdateDeploymentProvider /ClassId"))
    # mail gateway does SPF/DMARC TXT lookups for inbound mail
    for _ in range(rng.randint(8, 15)):
        dom = rng.choice(["aramex.com", "dpworld.com", "sabic.com", "almarai.com", "stc.com.sa"])
        qn = rng.choice([f"_dmarc.{dom}", dom])
        add(dict(time=_iso(_shift_seconds(rng)), source="dns", host=env.MAIL_GW, query_name=qn,
                 query_type="TXT", answer=rng.choice(["v=spf1 include:_spf.google.com ~all",
                                                      "v=DMARC1; p=reject; rua=mailto:dmarc@" + dom])))


def _web_server(rng, add):
    """Benign WEB-01 baseline so the web server is not a one-filter giveaway.

    IIS W3C-style inbound requests (source=iis), app-pool recycle, an iisreset,
    ASP.NET csc/cvtres compiles as w3wp children, scheduled cscript, CRL/update
    DNS lookups, and IIS log-roll / temp file writes.
    """
    web, ip = env.WEB_SERVER, env.host_ip(env.WEB_SERVER)
    pages = ["/portal/track.aspx", "/portal/login.aspx", "/portal/upload.aspx", "/portal/default.aspx",
             "/portal/Scripts/site.js", "/portal/Content/site.css", "/favicon.ico"]
    agents = ["Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+Chrome/129.0", "Mozilla/5.0+(iPhone;+CPU+iPhone+OS+17_5)",
              "Mozilla/5.0+(Windows+NT+10.0)+Edg/129.0", "Mozilla/5.0+(Linux;+Android+14)"]
    # inbound portal traffic from customers (public IPs), a few posts per visit
    for _ in range(rng.randint(40, 70)):
        t = _shift_seconds(rng)
        cip = "%d.%d.%d.%d" % tuple(rng.randint(1, 223) for _ in range(4))
        ua = rng.choice(agents)
        add(dict(time=_iso(t), source="firewall", action="allow", src_ip=cip, dest_ip=ip,
                 dest_port=443, proto="tcp"))
        for i in range(rng.randint(1, 4)):
            stem = rng.choice(pages)
            method = "POST" if stem.endswith(("login.aspx", "upload.aspx")) and rng.random() < 0.6 else "GET"
            add(dict(time=_iso(t + i * rng.randint(2, 20)), source="iis", host=web, c_ip=cip,
                     cs_method=method, cs_uri_stem=stem, cs_uri_query="-", s_port=443,
                     sc_status=rng.choice([200, 200, 200, 302, 404]),
                     cs_bytes=rng.randint(300, 9000) if method == "POST" else rng.randint(200, 900),
                     sc_bytes=rng.randint(800, 60000), cs_user_agent=ua))
    # app-pool recycle (WAS starts a fresh worker) and a midday iisreset by an admin
    for _ in range(rng.randint(2, 4)):
        add(dict(time=_iso(_shift_seconds(rng)), source="sysmon", event_id=1, host=web, user="svc_iis",
                 Image=W3WP, ParentImage=SVCHOST,
                 CommandLine='c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "PortalAppPool" -v "v4.0" -l "webengine4.dll" -a \\\\.\\pipe\\iisipm -h "C:\\inetpub\\temp\\apppools\\PortalAppPool\\PortalAppPool.config" -w "" -m 0'))
    admin = rng.choice(env.ADMINS)
    add(dict(time=_iso(12 * 3600 + 40 * 60 + rng.randint(0, 59)), source="sysmon", event_id=1, host=web,
             user=admin, Image=r"C:\Windows\System32\iisreset.exe", ParentImage=r"C:\Windows\System32\cmd.exe",
             CommandLine="iisreset /restart"))
    # ASP.NET dynamic compilation: w3wp spawns csc.exe (+ cvtres.exe) a few times a day
    for _ in range(rng.randint(3, 6)):
        t = _shift_seconds(rng)
        tmp = "%08x" % rng.randint(0, 0xFFFFFFFF)
        add(dict(time=_iso(t), source="sysmon", event_id=1, host=web, user="svc_iis",
                 Image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe", ParentImage=W3WP,
                 CommandLine=rf'"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\portal\{tmp}\{tmp}.cmdline"'))
        add(dict(time=_iso(t + 1), source="sysmon", event_id=1, host=web, user="svc_iis",
                 Image=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe",
                 ParentImage=r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
                 CommandLine=rf'cvtres.exe /NOLOGO /READONLY /MACHINE:AMD64 "/OUT:C:\Users\svc_iis\AppData\Local\Temp\RES{tmp[:4]}.tmp"'))
    # scheduled maintenance script (Task Scheduler -> cscript)
    for h in (9, 13):
        add(dict(time=_iso(h * 3600 + rng.randint(0, 59)), source="sysmon", event_id=1, host=web, user="SYSTEM",
                 Image=r"C:\Windows\System32\cscript.exe", ParentImage=SVCHOST,
                 CommandLine=r"cscript.exe //nologo C:\Scripts\iis-log-cleanup.vbs"))
    # CRL / OCSP / update lookups by w3wp and svchost, mirrored in the DNS log
    crl = ["crl.microsoft.com", "ocsp.digicert.com", "ctldl.windowsupdate.com", "crl3.digicert.com",
           "login.microsoftonline.com", "api.khobar-cloud.sa", "www.microsoft.com"]
    for _ in range(rng.randint(18, 26)):
        t = _shift_seconds(rng)
        dom = rng.choice(crl)
        img, usr = rng.choice([(W3WP, "svc_iis"), (SVCHOST, "SYSTEM")])
        rip = _ext_ip(rng)
        add(dict(time=_iso(t), source="sysmon", event_id=22, host=web, user=usr, Image=img,
                 QueryName=dom, QueryStatus=0, QueryResults=rip))
        add(dict(time=_iso(t), source="dns", host=web, query_name=dom, query_type="A", answer=rip))
    # IIS log roll and temp compressed files (Sysmon 11 by w3wp)
    add(dict(time=_iso(8 * 3600 + rng.randint(0, 120)), source="sysmon", event_id=11, host=web, user="svc_iis",
             Image=W3WP, TargetFilename=r"C:\inetpub\logs\LogFiles\W3SVC1\u_ex261020.log"))
    for _ in range(rng.randint(6, 12)):
        add(dict(time=_iso(_shift_seconds(rng)), source="sysmon", event_id=11, host=web, user="svc_iis",
                 Image=W3WP, TargetFilename=r"C:\inetpub\temp\IIS Temporary Compressed Files\PortalAppPool\$^_gzip_"
                 + rng.choice(["C^\\INETPUB\\WWWROOT\\PORTAL\\SCRIPTS\\SITE.JS", "C^\\INETPUB\\WWWROOT\\PORTAL\\CONTENT\\SITE.CSS"])))


def generate(scenario: int, seed: int):
    """Return (events, truth). events sorted by (time, source, event_id)."""
    rng = random.Random(f"khobar-{scenario}-{seed}")
    events: list[dict] = []
    add = events.append

    _logons(rng, add)
    _file_server_access(rng, add)
    _processes(rng, add)
    _network(rng, add)
    _vpn(rng, add)
    _email(rng, add)
    _scheduled_jobs(rng, add)
    _web_server(rng, add)

    attack_events, truth = build_scenario(scenario, rng)
    events.extend(attack_events)

    events.sort(key=lambda e: (e["time"], e.get("source", ""), e.get("event_id", 0)))
    return events, truth
