"""Synthetic phishing / benign email alerts with known ground truth.

Each scenario mirrors a pattern SOC analysts see daily, including hard cases
(compromised vendor accounts that pass SPF/DKIM, benign mail behind young
tracking domains) so the agent cannot score perfectly by checking one signal.
"""
import random
import string

from app.data.common import CORP_DOMAIN, GeneratedAlert

VENDORS = ["northwind-supply.com", "contoso-billing.com", "fabrikam-logistics.com", "globex-payroll.com"]
NEWSLETTERS = ["devweekly.io", "cloudnews.net", "secdigest.org"]
FREEMAIL = ["gmail.com", "outlook.com", "proton.me"]
EXECS = ["Dana Whitfield (CEO)", "Marcus Lee (CFO)", "Priya Natarajan (COO)"]
EMPLOYEES = [f"{n}@{CORP_DOMAIN}" for n in ["alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie"]]
LOOKALIKE_BASES = ["paypa1-secure", "micros0ft-login", "acme-c0rp", "docusign-review", "0kta-verify", "office365-auth"]
TLDS = [".com", ".net", ".support", ".top", ".xyz"]

SCENARIOS = [
    # name, verdict, weight
    ("internal_notice", "benign", 14),
    ("vendor_invoice_legit", "benign", 12),
    ("newsletter", "benign", 12),
    ("newsletter_young_tracker", "benign", 3),
    ("external_colleague", "benign", 8),
    ("password_reset_legit", "benign", 6),
    ("credential_harvest_lookalike", "malicious", 14),
    ("bec_reply_to_mismatch", "malicious", 9),
    ("malware_attachment", "malicious", 9),
    ("compromised_vendor", "malicious", 6),
    ("shortened_link_harvest", "malicious", 7),
]


def _rand(rng: random.Random, n: int = 6) -> str:
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _auth(spf="pass", dkim="pass", dmarc="pass") -> dict:
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc}


def generate_phishing(rng: random.Random, idx: int) -> GeneratedAlert:
    names, verdicts, weights = zip(*[(s[0], s[1], s[2]) for s in SCENARIOS])
    scenario = rng.choices(names, weights=weights)[0]
    verdict = dict(zip(names, verdicts))[scenario]
    recipient = rng.choice(EMPLOYEES)
    intel: list[tuple[str, str, dict]] = []
    attachments: list[str] = []
    urls: list[str] = []
    reply_to = None

    def domain(d: str, age: int, rep: str, cat: str = "") -> None:
        intel.append(("domain", d, {"age_days": age, "reputation": rep, "category": cat}))

    if scenario == "internal_notice":
        sender = f"it-helpdesk@{CORP_DOMAIN}"
        subject = rng.choice(["Scheduled maintenance this Saturday", "New VPN client rollout", "Quarterly security training"])
        body = "Hi team, please review the details on the intranet page linked below."
        urls = [f"https://intranet.{CORP_DOMAIN}/notices/{_rand(rng)}"]
        auth = _auth()
        domain(CORP_DOMAIN, 4100, "good", "corporate")
        domain(f"intranet.{CORP_DOMAIN}", 4100, "good", "corporate")
    elif scenario == "vendor_invoice_legit":
        v = rng.choice(VENDORS)
        sender = f"billing@{v}"
        subject = f"Invoice INV-{rng.randint(10000, 99999)} for {rng.choice(['August', 'September', 'October'])}"
        body = "Please find attached the invoice for services rendered. Payment terms net 30."
        attachments = [f"INV-{rng.randint(10000, 99999)}.pdf"]
        auth = _auth()
        domain(v, rng.randint(900, 5000), "good", "business")
    elif scenario in ("newsletter", "newsletter_young_tracker"):
        n = rng.choice(NEWSLETTERS)
        sender = f"news@{n}"
        subject = rng.choice(["This week in cloud", "Top 10 CVEs you missed", "Your weekly digest"])
        body = "Read the full stories on our site. Unsubscribe any time."
        tracker = f"click.{n}" if scenario == "newsletter" else f"trk-{_rand(rng, 4)}.mailmetrics.top"
        urls = [f"https://{tracker}/r/{_rand(rng, 10)}", f"https://{n}/unsubscribe"]
        auth = _auth()
        domain(n, rng.randint(1200, 4000), "good", "newsletter")
        if scenario == "newsletter":
            domain(tracker, rng.randint(1200, 4000), "good", "marketing")
        else:
            # Benign, but the tracking domain is brand new: a classic false-positive trap.
            domain(tracker, rng.randint(5, 25), "unknown", "marketing")
    elif scenario == "external_colleague":
        fm = rng.choice(FREEMAIL)
        sender = f"{rng.choice(['chris', 'pat', 'lee', 'robin'])}.{_rand(rng, 3)}@{fm}"
        subject = rng.choice(["Coffee next week?", "Notes from the meetup", "Following up on our call"])
        body = "Great chatting yesterday. Let me know what works for you."
        auth = _auth()
        domain(fm, 8000, "good", "freemail")
    elif scenario == "password_reset_legit":
        sender = "no-reply@okta.com"
        subject = "URGENT: Your password expires in 24 hours"
        body = "Your password will expire soon. Reset it from your Okta dashboard."
        urls = ["https://acme-corp.okta.com/reset"]
        auth = _auth()
        domain("okta.com", 6000, "good", "identity")
        domain("acme-corp.okta.com", 2500, "good", "identity")
    elif scenario == "credential_harvest_lookalike":
        d = rng.choice(LOOKALIKE_BASES) + rng.choice(TLDS)
        sender = f"security@{d}"
        subject = rng.choice(["Unusual sign-in detected: verify now", "Your account will be suspended", "Action required: confirm identity"])
        body = "We detected suspicious activity. Verify your account within 12 hours to avoid suspension."
        urls = [f"https://{d}/login?session={_rand(rng, 12)}"]
        auth = _auth(spf=rng.choice(["fail", "softfail", "none"]), dkim=rng.choice(["fail", "none"]), dmarc="fail")
        domain(d, rng.randint(1, 30), rng.choice(["unknown", "malicious"]), "uncategorized")
    elif scenario == "bec_reply_to_mismatch":
        exec_name = rng.choice(EXECS)
        if rng.random() < 0.5:
            sender_domain = rng.choice(FREEMAIL)
            domain(sender_domain, 8000, "good", "freemail")
        else:
            sender_domain = "acme-c0rp.com"
            domain(sender_domain, rng.randint(2, 20), "unknown", "uncategorized")
        sender = f"{exec_name.split()[0].lower()}.exec{rng.randint(1, 99)}@{sender_domain}"
        reply_to = f"{_rand(rng, 8)}@{rng.choice(FREEMAIL)}"
        subject = rng.choice(["Quick favour, are you at your desk?", "Confidential wire transfer today", "Gift cards for the team"])
        body = f"From {exec_name}: I need you to process a payment urgently and keep this between us."
        auth = _auth(spf="pass", dkim=rng.choice(["pass", "none"]), dmarc=rng.choice(["pass", "none"]))
    elif scenario == "malware_attachment":
        d = f"{_rand(rng, 7)}{rng.choice(TLDS)}"
        sender = f"orders@{d}"
        subject = rng.choice(["Shipping documents", "Purchase order attached", "Scanned document"])
        body = "Please open the attached document and enable content to view."
        attachments = [rng.choice(["PO_" + _rand(rng, 4) + ".docm", "scan_" + _rand(rng, 4) + ".iso", "doc_" + _rand(rng, 4) + ".html", "invoice.zip"])]
        auth = _auth(spf=rng.choice(["fail", "softfail", "none"]), dkim="none", dmarc=rng.choice(["fail", "none"]))
        domain(d, rng.randint(1, 45), rng.choice(["unknown", "malicious"]), "uncategorized")
    elif scenario == "compromised_vendor":
        # Hard case: real vendor mailbox, authentication passes, payload lives on a young domain.
        v = rng.choice(VENDORS)
        sender = f"accounts@{v}"
        subject = "Updated banking details, please review"
        body = "We have changed banks. Review the updated remittance portal before the next payment."
        payload_domain = f"{v.split('.')[0]}-portal{rng.choice(TLDS)}"
        urls = [f"https://{payload_domain}/remit/{_rand(rng, 8)}"]
        auth = _auth()
        domain(v, rng.randint(900, 5000), "good", "business")
        domain(payload_domain, rng.randint(1, 14), "unknown", "uncategorized")
    else:  # shortened_link_harvest
        d = rng.choice(LOOKALIKE_BASES) + rng.choice(TLDS)
        short = f"https://sho.rt/{_rand(rng, 6)}"
        sender = f"{rng.choice(['hr', 'payroll', 'benefits'])}.update@{rng.choice(FREEMAIL)}"
        subject = rng.choice(["Your 2026 bonus letter", "Benefits enrolment closes today"])
        body = "Open the secure link to view your document."
        urls = [short]
        auth = _auth(spf="pass", dkim="pass", dmarc=rng.choice(["pass", "none"]))
        intel.append(("url", short, {"expands_to": f"https://{d}/doc/{_rand(rng, 8)}"}))
        intel.append(("domain", "sho.rt", {"age_days": 3000, "reputation": "good", "category": "url_shortener"}))
        domain(d, rng.randint(1, 20), rng.choice(["unknown", "malicious"]), "uncategorized")
        domain(sender.split("@")[1], 8000, "good", "freemail")

    payload = {
        "source": "email_gateway",
        "recipient": recipient,
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body_excerpt": body,
        "urls": urls,
        "attachments": attachments,
        "auth_results": auth,
        "reported_by_user": rng.random() < 0.4,
    }
    return GeneratedAlert(f"PH-{idx:06d}", "phishing", payload, verdict, scenario, intel)
