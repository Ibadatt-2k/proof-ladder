"""Investigation tools. Every call is executed through the Executor so it lands on the audit trail."""
import math
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

IntelLookup = Callable[[str, str], dict | None]

RISKY_EXT = {".docm", ".xlsm", ".iso", ".img", ".html", ".htm", ".zip", ".js", ".exe", ".lnk", ".vbs"}
CUES = {
    "urgency": ["urgent", "immediately", "within 12 hours", "suspended", "expires", "today", "action required"],
    "financial": ["wire", "payment", "invoice", "bank", "gift card", "remittance", "bonus"],
    "secrecy": ["keep this between us", "confidential", "don't tell"],
    "credential": ["verify", "confirm identity", "sign-in", "login", "password"],
    "exec_impersonation": ["ceo", "cfo", "coo"],
}


def _domain_of(addr_or_url: str) -> str:
    if "@" in addr_or_url and "://" not in addr_or_url:
        return addr_or_url.split("@", 1)[1].lower()
    return (urlparse(addr_or_url).hostname or "").lower()


def _age_bucket(age: int | None) -> str:
    if age is None:
        return "unknown"
    return "new" if age < 30 else "young" if age < 365 else "aged"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class Toolbox:
    """Tools scoped to one alert. Alert-level tools take no arguments."""

    def __init__(self, alert_type: str, payload: dict, intel: IntelLookup, memory_search: Callable[[str, str], list[dict]] | None = None):
        self.alert_type = alert_type
        self.p = payload
        self.intel = intel
        self.memory_search = memory_search

    # ---------- phishing ----------
    def check_email_auth(self) -> dict:
        sender_domain = _domain_of(self.p["sender"])
        reply_to = self.p.get("reply_to")
        rt_domain = _domain_of(reply_to) if reply_to else None
        return {
            "sender": self.p["sender"], "sender_domain": sender_domain,
            "reply_to": reply_to, "reply_to_mismatch": bool(rt_domain and rt_domain != sender_domain),
            **self.p["auth_results"],
        }

    def lookup_domain(self, domain: str) -> dict:
        rec = self.intel("domain", domain.lower())
        if not rec:
            return {"domain": domain, "found": False}
        return {"domain": domain, "found": True, **rec, "age_bucket": _age_bucket(rec.get("age_days"))}

    def expand_url(self, url: str) -> dict:
        rec = self.intel("url", url)
        final = rec["expands_to"] if rec else url
        return {"url": url, "final_url": final, "final_domain": _domain_of(final), "redirected": final != url}

    def inspect_attachments(self) -> dict:
        items = []
        for name in self.p.get("attachments", []):
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            items.append({"name": name, "extension": ext, "risky": ext in RISKY_EXT})
        return {"attachments": items, "any_risky": any(i["risky"] for i in items)}

    def analyze_language(self) -> dict:
        text = f"{self.p.get('subject', '')} {self.p.get('body_excerpt', '')}".lower()
        hits = {k: [w for w in words if w in text] for k, words in CUES.items()}
        return {"cues": {k: v for k, v in hits.items() if v}}

    # ---------- login ----------
    def get_user_profile(self) -> dict:
        rec = self.intel("user_profile", self.p["user"]) or {}
        return {"user": self.p["user"], "found": bool(rec), **rec}

    def geo_velocity(self) -> dict:
        g, prev = self.p["geo"], self.p["previous_login"]
        km = haversine_km(prev["lat"], prev["lon"], g["lat"], g["lon"])
        hours = max(prev["minutes_ago"], 1) / 60
        kmh = km / hours
        return {
            "from_city": prev["city"], "to_city": g["city"], "distance_km": round(km),
            "minutes_between": prev["minutes_ago"], "implied_speed_kmh": round(kmh),
            "impossible_travel": km > 500 and kmh > 900,
        }

    def lookup_ip(self, ip: str) -> dict:
        rec = self.intel("ip", ip)
        return {"ip": ip, "found": bool(rec), **(rec or {})}

    def check_device_history(self) -> dict:
        prof = self.intel("user_profile", self.p["user"]) or {}
        return {"device_id": self.p["device_id"], "known_device": self.p["device_id"] in prof.get("known_devices", [])}

    def get_auth_details(self) -> dict:
        return {"auth_method": self.p["auth_method"], "mfa_result": self.p["mfa_result"], "user_agent": self.p["user_agent"]}

    # ---------- shared ----------
    def search_past_corrections(self) -> dict:
        sig = self.signature()
        matches = self.memory_search(self.alert_type, sig) if self.memory_search else []
        return {"signature": sig, "matches": matches}

    # ---------- deterministic feature signature (used by memory) ----------
    def signature(self) -> str:
        if self.alert_type == "phishing":
            a = self.check_email_auth()
            s = self.lookup_domain(a["sender_domain"])
            url_ages, url_reps = [], []
            for u in self.p.get("urls", []):
                d = self.expand_url(u)["final_domain"]
                rec = self.lookup_domain(d)
                url_ages.append(rec.get("age_days", 0) if rec["found"] else 0)
                url_reps.append(rec.get("reputation", "unknown") if rec["found"] else "unknown")
            rep_rank = {"malicious": 0, "unknown": 1, "good": 2}
            worst_rep = min(url_reps, key=lambda r: rep_rank.get(r, 1)) if url_reps else "none"
            min_age = _age_bucket(min(url_ages)) if url_ages else "none"
            att = self.inspect_attachments()
            att_s = "none" if not att["attachments"] else ("risky" if att["any_risky"] else "safe")
            cues = ",".join(sorted(self.analyze_language()["cues"])) or "none"
            return (f"phishing spf:{a['spf']} dmarc:{a['dmarc']} sender_rep:{s.get('reputation', 'unknown')} "
                    f"sender_age:{s.get('age_bucket', 'unknown')} sender_cat:{s.get('category', 'unknown')} "
                    f"url_rep:{worst_rep} url_age:{min_age} attach:{att_s} replyto_mismatch:{a['reply_to_mismatch']} cues:{cues}")
        v = self.geo_velocity()
        ip = self.lookup_ip(self.p["src_ip"])
        dev = self.check_device_history()
        travel = "impossible" if v["impossible_travel"] else ("moved" if v["distance_km"] > 100 else "home")
        failed = ip.get("failed_logins_24h", 0)
        fb = "many" if failed > 20 else "some" if failed > 0 else "none"
        return (f"login travel:{travel} asn_type:{ip.get('asn_type', 'unknown')} asn:{ip.get('asn_name', 'unknown').replace(' ', '_')} "
                f"device:{'known' if dev['known_device'] else 'new'} mfa:{self.p['mfa_result']} "
                f"auth:{self.p['auth_method']} ip_rep:{ip.get('reputation', 'unknown')} failed:{fb}")


# JSON schemas exposed to LLM providers.
TOOL_SPECS: dict[str, list[dict[str, Any]]] = {
    "phishing": [
        {"name": "check_email_auth", "description": "SPF/DKIM/DMARC results and sender vs reply-to alignment.", "params": {}},
        {"name": "lookup_domain", "description": "Threat intel for a domain: age in days, reputation, category.", "params": {"domain": "string"}},
        {"name": "expand_url", "description": "Follow redirects / URL shorteners to the final destination.", "params": {"url": "string"}},
        {"name": "inspect_attachments", "description": "List attachments and flag risky file types.", "params": {}},
        {"name": "analyze_language", "description": "Detect urgency, financial, secrecy, credential and exec-impersonation cues.", "params": {}},
        {"name": "search_past_corrections", "description": "Find analyst corrections on alerts with the same feature signature.", "params": {}},
    ],
    "login": [
        {"name": "get_user_profile", "description": "Directory profile: home city, known devices.", "params": {}},
        {"name": "geo_velocity", "description": "Distance and implied travel speed since the user's previous login.", "params": {}},
        {"name": "lookup_ip", "description": "ASN, network type, reputation and recent failed logins for an IP.", "params": {"ip": "string"}},
        {"name": "check_device_history", "description": "Whether the device has been seen for this user before.", "params": {}},
        {"name": "get_auth_details", "description": "Authentication method and MFA result for this sign-in.", "params": {}},
        {"name": "search_past_corrections", "description": "Find analyst corrections on alerts with the same feature signature.", "params": {}},
    ],
}


def json_schema_for(spec: dict) -> dict:
    return {"type": "object", "properties": {k: {"type": v} for k, v in spec["params"].items()}, "required": list(spec["params"])}


_SAFE_ARG = re.compile(r"^[\w.\-:/@?=&%]+$")


def call_tool(tb: Toolbox, name: str, args: dict) -> dict:
    allowed = {s["name"] for s in TOOL_SPECS[tb.alert_type]}
    if name not in allowed:
        raise ValueError(f"tool '{name}' is outside the allowed scope for {tb.alert_type}")
    for v in args.values():
        if not isinstance(v, str) or not _SAFE_ARG.match(v):
            raise ValueError("invalid tool argument")
    return getattr(tb, name)(**args)
