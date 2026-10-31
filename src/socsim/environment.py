"""Fictional company network: Khobar Logistics Co. (khobar.local AD domain).

Static inventory the telemetry generator and scenarios draw from. Everything
here is synthetic. No real hosts, users, or IPs.
"""
from __future__ import annotations

DOMAIN = "khobar.local"
DATE = "2026-10-20"          # the simulated shift date
SHIFT_START_HOUR = 8         # 08:00 local
SHIFT_HOURS = 8              # ends 16:00

# --- servers / infrastructure ---
DCS = ["DC-01", "DC-02"]
FILE_SERVER = "FS-01"
WEB_SERVER = "WEB-01"
MAIL_GW = "MAIL-01"
FIREWALL = "FW-01"
VPN_GW = "VPN-01"
SERVERS = DCS + [FILE_SERVER, WEB_SERVER, MAIL_GW]

INTERNAL_SUBNET = "10.20.0."   # servers 10.20.0.x
WORKSTATION_SUBNET = "10.20.10."  # WS-01 -> 10.20.10.1, etc.

# --- people (synthetic Saudi-mix staff) ---
# (sam_account_name, display, department, workstation)
STAFF = [
    ("f.alharbi", "Fahad Alharbi", "Logistics", "WS-07"),
    ("a.qahtani", "Abdullah Alqahtani", "IT-Admin", "WS-01"),
    ("m.otaibi", "Maha Alotaibi", "Finance", "WS-19"),
    ("s.dossari", "Sara Aldossari", "HR", "WS-05"),
    ("n.ghamdi", "Noura Alghamdi", "Logistics", "WS-08"),
    ("k.zahrani", "Khalid Alzahrani", "Operations", "WS-11"),
    ("r.shehri", "Reem Alshehri", "Finance", "WS-20"),
    ("y.harbi", "Yousef Alharbi", "Operations", "WS-12"),
    ("l.mutairi", "Lama Almutairi", "Marketing", "WS-14"),
    ("t.subaie", "Turki Alsubaie", "Logistics", "WS-09"),
    ("h.shammari", "Hind Alshammari", "HR", "WS-06"),
    ("o.balawi", "Omar Albalawi", "IT-Admin", "WS-02"),
    ("d.rashidi", "Dana Alrashidi", "Marketing", "WS-15"),
    ("s.amri", "Saad Alamri", "Operations", "WS-13"),
    ("j.qarni", "Joud Alqarni", "Finance", "WS-21"),
    ("b.anazi", "Bader Alanazi", "Logistics", "WS-10"),
    ("w.harthy", "Wael Alharthy", "Operations", "WS-16"),
    ("g.faifi", "Ghada Alfaifi", "HR", "WS-04"),
    ("z.malki", "Ziad Almalki", "Marketing", "WS-17"),
    ("e.juhani", "Eman Aljuhani", "Finance", "WS-22"),
    ("m.shehri", "Majed Alshehri", "Logistics", "WS-18"),
    ("r.dawsari", "Rakan Aldawsari", "Operations", "WS-23"),
    ("a.zaid", "Aisha Alzaid", "Marketing", "WS-24"),
    ("f.qahtani", "Faris Alqahtani", "IT-Admin", "WS-03"),
    ("n.harbi", "Nasser Alharbi", "Logistics", "WS-25"),
]
USERNAMES = [s[0] for s in STAFF]
WORKSTATIONS = [s[3] for s in STAFF]
ADMINS = [s[0] for s in STAFF if s[2] == "IT-Admin"]

# service accounts (non-interactive)
SVC_ACCOUNTS = ["svc_backup", "svc_sql", "svc_iis"]

# normal external destinations the staff browse (benign noise)
BENIGN_DOMAINS = [
    "www.microsoft.com", "login.microsoftonline.com", "outlook.office365.com",
    "www.google.com", "teams.microsoft.com", "salla.sa", "update.windows.com",
    "cdn.jsdelivr.net", "fonts.googleapis.com", "www.linkedin.com",
    "api.whatsapp.com", "mail.google.com", "github.com",
]


def host_ip(host: str) -> str:
    """Map a host name to its synthetic internal IP."""
    if host in SERVERS or host in (FIREWALL, VPN_GW):
        n = {"DC-01": 10, "DC-02": 11, FILE_SERVER: 20, WEB_SERVER: 30,
             MAIL_GW: 40, FIREWALL: 1, VPN_GW: 2}[host]
        return INTERNAL_SUBNET + str(n)
    if host.startswith("WS-"):
        return WORKSTATION_SUBNET + str(int(host.split("-")[1]))
    return INTERNAL_SUBNET + "99"


def user_host(username: str) -> str:
    for sam, _disp, _dept, ws in STAFF:
        if sam == username:
            return ws
    return WORKSTATIONS[0]
