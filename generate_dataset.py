#!/usr/bin/env python3
"""
Cloudora - Payroll Phish (ticket CLD-0002) dataset generator.
Seeded (seed 42) so the output is identical every run, and consistent with the
Project 1 Cloudora universe (same 40-staff roster, same reserved IP scheme,
dates AFTER the 3-10 Aug CLD-0001 window).

Produces two files in the same folder:
  cloudora_msgtrace_logs.csv   -> ingest to ADX as  CloudoraMsgTrace_CL
  cloudora_signin_logs.csv     -> ingest to ADX as  CloudoraSignIn_CL

Ingest notes (see Student Guide / query pack):
  - TimeGenerated ingests as datetime (auto).
  - In CloudoraMsgTrace_CL set CredentialsSubmitted and every *Result column to
    STRING. In CloudoraSignIn_CL set ResultType to STRING (ADX guesses number).

Safety: the lookalike domain cloudora-hr-portal.example uses the IANA-reserved
.example TLD and can never resolve. All IPs are reserved/synthetic. No real
credential-harvesting page exists - it is only described.
"""

import csv
import random

random.seed(42)

OUT_MSGTRACE = "cloudora_msgtrace_logs.csv"
OUT_SIGNIN = "cloudora_signin_logs.csv"

# ---------------------------------------------------------------------------
# Roster carried over from Project 1 (user -> home city, corporate IP, device).
# ---------------------------------------------------------------------------
ROSTER = {
    "adam.clark":   ("192.0.2.30",   "Austin",     "United States",  "macOS 14",  "Safari"),
    "alba.vega":    ("198.51.100.22", "Manchester", "United Kingdom", "macOS 14",  "Safari"),
    "amelia.frost": ("203.0.113.14", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "aria.reid":    ("203.0.113.13", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "arjun.mehta":  ("203.0.113.16", "London",     "United Kingdom", "iOS 17",    "Mobile Safari"),
    "chloe.price":  ("203.0.113.17", "London",     "United Kingdom", "Android 14", "Chrome Mobile"),
    "cole.burke":   ("192.0.2.32",   "Austin",     "United States",  "iOS 17",    "Mobile Safari"),
    "daniel.reeve": ("203.0.113.13", "London",     "United Kingdom", "Windows 11", "Edge"),
    "dean.page":    ("192.0.2.31",   "Austin",     "United States",  "macOS 14",  "Safari"),
    "dina.said":    ("203.0.113.12", "London",     "United Kingdom", "Windows 11", "Edge"),
    "emma.hayes":   ("203.0.113.12", "London",     "United Kingdom", "Windows 10", "Chrome"),
    "ethan.wells":  ("192.0.2.30",   "Austin",     "United States",  "Windows 11", "Chrome"),
    "felix.hart":   ("192.0.2.30",   "Austin",     "United States",  "Windows 10", "Chrome"),
    "finn.gale":    ("198.51.100.24", "Manchester", "United Kingdom", "iOS 17",    "Mobile Safari"),
    "freya.lynn":   ("198.51.100.20", "Manchester", "United Kingdom", "iOS 17",    "Mobile Safari"),
    "gwen.muir":    ("203.0.113.12", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "hugo.marsh":   ("198.51.100.20", "Manchester", "United Kingdom", "iOS 17",    "Mobile Safari"),
    "isla.grant":   ("203.0.113.15", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "james.holt":   ("198.51.100.20", "Manchester", "United Kingdom", "Windows 11", "Edge"),
    "joel.kerr":    ("192.0.2.31",   "Austin",     "United States",  "Windows 11", "Chrome"),
    "jude.ross":    ("203.0.113.16", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "kian.patel":   ("192.0.2.31",   "Austin",     "United States",  "iOS 17",    "Mobile Safari"),
    "leah.stone":   ("203.0.113.17", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "lena.voss":    ("192.0.2.32",   "Austin",     "United States",  "macOS 14",  "Safari"),
    "liam.doyle":   ("203.0.113.17", "London",     "United Kingdom", "Windows 10", "Chrome"),
    "lucas.ford":   ("203.0.113.10", "London",     "United Kingdom", "Android 14", "Chrome Mobile"),
    "maya.chen":    ("203.0.113.11", "London",     "United Kingdom", "Windows 11", "Edge"),
    "mira.shah":    ("192.0.2.31",   "Austin",     "United States",  "Windows 11", "Chrome"),
    "nina.cole":    ("198.51.100.22", "Manchester", "United Kingdom", "Windows 10", "Chrome"),
    "noah.bishop":  ("203.0.113.13", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "olivia.kaur":  ("203.0.113.12", "London",     "United Kingdom", "Windows 11", "Edge"),
    "omar.farah":   ("203.0.113.10", "London",     "United Kingdom", "iOS 17",    "Mobile Safari"),
    "priya.nair":   ("203.0.113.10", "London",     "United Kingdom", "Android 14", "Chrome Mobile"),
    "rhys.owen":    ("203.0.113.13", "London",     "United Kingdom", "macOS 14",  "Safari"),
    "ruth.dean":    ("192.0.2.32",   "Austin",     "United States",  "Windows 11", "Chrome"),
    "ryan.boyd":    ("203.0.113.10", "London",     "United Kingdom", "iOS 17",    "Mobile Safari"),
    "seth.lane":    ("192.0.2.32",   "Austin",     "United States",  "Windows 10", "Chrome"),
    "sofia.marino": ("203.0.113.17", "London",     "United Kingdom", "iOS 17",    "Mobile Safari"),
    "tara.kemp":    ("203.0.113.14", "London",     "United Kingdom", "Windows 10", "Chrome"),
    "zara.aziz":    ("203.0.113.16", "London",     "United Kingdom", "Windows 11", "Edge"),
}
USERS = sorted(ROSTER.keys())


def upn(u):
    return u + "@cloudora.io"


# ---------------------------------------------------------------------------
# Attacker infrastructure (all reserved / synthetic).
#   198.18.0.0/15 is the RFC2544 benchmarking range - never routed on the
#   internet - reused here as clearly-fake phishing infrastructure. Geolocated
#   in the analysis narrative to Amsterdam, NL (typical throwaway VPS).
# ---------------------------------------------------------------------------
RELAY_A = "198.18.44.10"    # variant A first wave relay + harvest host
RELAY_A2 = "198.18.44.23"   # variant A second wave (same /24 -> campaign link)
RELAY_B = "198.18.51.7"     # variant B sending relay

# Variant A went out in two waves from two relays in the same /24. The second
# wave (later in the morning, from .23) includes seth.lane and chloe.price so
# their reported copies show the pivot IP.
WAVE2_A = ["seth.lane", "chloe.price", "james.holt", "tara.kemp",
           "omar.farah", "liam.doyle", "kian.patel", "felix.hart"]
LOGIN_IP = "198.18.7.200"   # attacker sign-ins with harvested creds (Amsterdam)
ATT_OS = "Windows 11"
ATT_BROWSER = "Chrome"

INCIDENT_DATE = "2026-08-25"

# Campaign / message metadata
SUBJECT_A = "Payroll update: action required before 5pm"
SUBJECT_B = "Action required: confirm your August payroll details"
URL_A = "https://cloudora-hr-portal.example/payroll/login"
URL_B = "https://login.cloudora-hr-portal.example/verify"

# ---------------------------------------------------------------------------
# Victim design
#   Two credential submitters, both compromised:
#     freya.lynn  -> found in the walkthrough (click + anomalous sign-in)
#     ryan.boyd   -> found only in the tasks
#   Clicked the link but did NOT submit credentials (elevated risk, comms only):
#     seth.lane, chloe.price, hugo.marsh, dina.said
#   Everyone else who received but did not click = near-miss list (user comms).
# ---------------------------------------------------------------------------
CRED_SUBMIT = ["freya.lynn", "ryan.boyd"]
CLICK_NO_CRED = ["seth.lane", "chloe.price", "hugo.marsh", "dina.said"]

# Which campaign each clicker interacted with, and click details
CLICK_EVENTS = [
    # user, campaign, url, click_time, cred_submitted
    ("freya.lynn",  "A", URL_A, "2026-08-25T08:47:12Z", "Yes"),
    ("ryan.boyd",   "B", URL_B, "2026-08-25T09:05:44Z", "Yes"),
    ("seth.lane",   "A", URL_A, "2026-08-25T08:39:03Z", "No"),
    ("chloe.price", "A", URL_A, "2026-08-25T10:12:37Z", "No"),
    ("hugo.marsh",  "B", URL_B, "2026-08-25T09:58:50Z", "No"),
    ("dina.said",   "A", URL_A, "2026-08-25T11:47:19Z", "No"),
]

# Recipients who also got variant B (subset), to add a second delivery wave.
# Deterministic subset of 20.
VARIANT_B_RECIPIENTS = sorted(random.sample(USERS, 20))
# Recipients whose variant A copy was caught by EOP (Quarantined), the rest
# Delivered. Anyone who clicked variant A must have received it, so exclude the
# variant-A clickers from the quarantined set.
_click_a_users = {u for (u, c, *_rest) in CLICK_EVENTS if c == "A"}
QUARANTINED_A = set(u for u in random.sample(USERS, 8) if u not in _click_a_users)


def jitter(base_h, base_m, spread_min):
    """Return (hh, mm, ss) around base with +/- spread using seeded random."""
    total = base_h * 60 + base_m + random.randint(-spread_min, spread_min)
    total %= (24 * 60)
    hh, mm = divmod(total, 60)
    ss = random.randint(0, 59)
    return hh, mm, ss


def ts(hh, mm, ss):
    return "%sT%02d:%02d:%02dZ" % (INCIDENT_DATE, hh, mm, ss)


# ===========================================================================
# 1) MESSAGE TRACE
# ===========================================================================
msg_rows = []
mid = 1


def add_delivery(campaign, recipient):
    global mid
    if campaign == "A":
        disp = "Cloudora HR"
        sender = "payroll@cloudora.io"                 # spoofed display domain
        rp = "bounce@mail.cloudora-hr-portal.example"  # true envelope sender
        subject = SUBJECT_A
        spf, dkim, dmarc = "fail", "fail", "fail"
        action = "Quarantined" if recipient in QUARANTINED_A else "Delivered"
        if recipient in WAVE2_A:
            sip = RELAY_A2
            hh, mm, ss = jitter(8, 40, 10)
        else:
            sip = RELAY_A
            hh, mm, ss = jitter(8, 5, 12)
    else:
        disp = "Cloudora Payroll Services"
        sender = "payroll@cloudora-hr-portal.example"  # lookalike org domain
        rp = "payroll@cloudora-hr-portal.example"
        subject = SUBJECT_B
        sip = RELAY_B
        # Variant B is sent from the attacker's OWN lookalike domain, which has
        # valid SPF/DKIM/DMARC. Authentication PASSES - but for
        # cloudora-hr-portal.example, not cloudora.io. Passing auth proves the
        # domain, not the trustworthiness. This is the false-positive trap.
        spf, dkim, dmarc = "pass", "pass", "pass"
        action = "Delivered"
        hh, mm, ss = jitter(8, 50, 18)
    message_id = "<%s-%04d@%s>" % (
        "A" if campaign == "A" else "B", mid,
        "mail.cloudora-hr-portal.example")
    mid += 1
    msg_rows.append([
        ts(hh, mm, ss), "Delivery", message_id, "PayrollPhish-" + campaign,
        disp, sender, rp, upn(recipient), subject, sip,
        spf, dkim, dmarc, action, "", "", "",
    ])
    return message_id


# Deliver variant A to everyone; keep the message id per recipient for click linkage
a_msgids = {}
for u in USERS:
    a_msgids[u] = add_delivery("A", u)
# Deliver variant B to the subset
b_msgids = {}
for u in VARIANT_B_RECIPIENTS:
    b_msgids[u] = add_delivery("B", u)

# Click events (link back to the delivered message id)
for user, campaign, url, click_time, cred in CLICK_EVENTS:
    if campaign == "A":
        message_id = a_msgids[user]
    else:
        message_id = b_msgids.get(user) or add_delivery("B", user)
    click_ip = ROSTER[user][0]  # click originates from the victim's own browser/IP
    msg_rows.append([
        click_time, "Click", message_id, "PayrollPhish-" + campaign,
        "", "", "", upn(user), "", "", "", "", "", "", url, click_ip, cred,
    ])

# Sort message trace by time for readability
msg_rows.sort(key=lambda r: r[0])

with open(OUT_MSGTRACE, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow([
        "TimeGenerated", "EventType", "MessageId", "Campaign",
        "SenderDisplayName", "SenderAddress", "ReturnPath", "RecipientAddress",
        "Subject", "SenderIP", "SPFResult", "DKIMResult", "DMARCResult",
        "DeliveryAction", "Url", "ClickIP", "CredentialsSubmitted",
    ])
    w.writerows(msg_rows)


# ===========================================================================
# 2) SIGN-IN SLICE (25 Aug 2026)
# ===========================================================================
signin_rows = []


def add_signin(user, hh, mm, ss, app, ip, city, country, result, desc, os_, br):
    signin_rows.append([
        ts(hh, mm, ss), upn(user), app, ip, city, country,
        result, desc, os_, br,
    ])


def normal_day(user, n=2):
    """A couple of ordinary same-day sign-ins from the user's usual location."""
    ip, city, country, os_, br = ROSTER[user]
    apps = ["Microsoft 365", "Microsoft Teams", "Outlook Web App", "SharePoint Online"]
    base = [(8, random.randint(5, 40)), (13, random.randint(0, 55)),
            (16, random.randint(0, 50))]
    for i in range(min(n, len(base))):
        hh, mm = base[i]
        add_signin(user, hh, mm, random.randint(0, 59),
                   random.choice(apps), ip, city, country, "0", "Success", os_, br)


# Ordinary activity for a representative set of staff (context)
context_users = ["freya.lynn", "ryan.boyd", "seth.lane", "chloe.price",
                 "hugo.marsh", "dina.said", "nina.cole", "adam.clark",
                 "maya.chen", "omar.farah", "tara.kemp", "james.holt",
                 "olivia.kaur", "arjun.mehta", "emma.hayes"]
for u in context_users:
    normal_day(u, n=2)

# --- Attacker sign-ins with harvested credentials -------------------------
# freya.lynn: genuine Manchester login in the morning, attacker from Amsterdam
add_signin("freya.lynn", 10, 34, 20, "Microsoft 365", LOGIN_IP, "Amsterdam",
           "Netherlands", "0", "Success", ATT_OS, ATT_BROWSER)
add_signin("freya.lynn", 10, 36, 5, "Outlook Web App", LOGIN_IP, "Amsterdam",
           "Netherlands", "0", "Success", ATT_OS, ATT_BROWSER)
add_signin("freya.lynn", 10, 41, 48, "SharePoint Online", LOGIN_IP, "Amsterdam",
           "Netherlands", "0", "Success", ATT_OS, ATT_BROWSER)

# ryan.boyd: attacker from Amsterdam in the early afternoon (task-only find)
add_signin("ryan.boyd", 13, 22, 5, "Microsoft 365", LOGIN_IP, "Amsterdam",
           "Netherlands", "0", "Success", ATT_OS, ATT_BROWSER)
add_signin("ryan.boyd", 13, 25, 33, "Outlook Web App", LOGIN_IP, "Amsterdam",
           "Netherlands", "0", "Success", ATT_OS, ATT_BROWSER)

signin_rows.sort(key=lambda r: r[0])

with open(OUT_SIGNIN, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow([
        "TimeGenerated", "UserPrincipalName", "AppDisplayName", "IPAddress",
        "City", "Country", "ResultType", "ResultDescription", "DeviceOS",
        "Browser",
    ])
    w.writerows(signin_rows)


# ---------------------------------------------------------------------------
print("Wrote %s (%d rows) and %s (%d rows)." % (
    OUT_MSGTRACE, len(msg_rows), OUT_SIGNIN, len(signin_rows)))
print("Variant B recipients (%d):" % len(VARIANT_B_RECIPIENTS),
      ", ".join(VARIANT_B_RECIPIENTS))
print("Quarantined variant A:", ", ".join(sorted(QUARANTINED_A)))
