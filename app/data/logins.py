"""Synthetic sign-in alerts with known ground truth.

Includes the trap that keeps this alert type honest: corporate VPN egress
produces geo "impossible travel" on perfectly legitimate logins.
"""
import random
import string

from app.data.common import CITIES, GeneratedAlert

USERS = [f"user{i:02d}@acme-corp.com" for i in range(1, 31)]
HOME_CITIES = ["Vancouver", "Toronto", "Seattle", "New York", "London"]
UAS = ["Chrome 128 / macOS", "Edge 127 / Windows 11", "Safari 17 / iOS", "Firefox 130 / Ubuntu"]

SCENARIOS = [
    ("normal_login", "benign", 30),
    ("travel_legit", "benign", 8),
    ("corporate_vpn_egress", "benign", 10),
    ("new_device_legit", "benign", 10),
    ("impossible_travel_attack", "malicious", 14),
    ("password_spray_success", "malicious", 10),
    ("token_replay", "malicious", 6),
]


def _ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(11, 223)) for _ in range(4))


def _dev(rng: random.Random) -> str:
    return "dev-" + "".join(rng.choice(string.hexdigits.lower()) for _ in range(8))


def _user_profile(user: str) -> dict:
    r = random.Random(user)  # stable per user
    return {"home_city": r.choice(HOME_CITIES), "known_devices": [_dev(r), _dev(r)], "department": r.choice(["eng", "sales", "finance", "ops"])}


def generate_login(rng: random.Random, idx: int) -> GeneratedAlert:
    names, verdicts, weights = zip(*SCENARIOS)
    scenario = rng.choices(names, weights=weights)[0]
    verdict = dict(zip(names, verdicts))[scenario]
    user = rng.choice(USERS)
    profile = _user_profile(user)
    home = profile["home_city"]
    known = profile["known_devices"]
    ip = _ip(rng)
    prev_city, prev_minutes = home, rng.randint(60, 600)
    auth_method, mfa = "password+mfa", "pass"
    ip_attrs = {"asn": rng.randint(1000, 65000), "asn_name": "Shaw Communications", "asn_type": "residential", "reputation": "clean", "failed_logins_24h": 0}

    if scenario == "normal_login":
        city, device = home, rng.choice(known)
        if rng.random() < 0.4:
            ip_attrs.update(asn_name="Acme Corp HQ", asn_type="corporate")
    elif scenario == "travel_legit":
        city = rng.choice([c for c in CITIES if c != home])
        device = rng.choice(known)
        prev_minutes = rng.randint(14 * 60, 30 * 60)  # long enough to have flown
        ip_attrs.update(asn_name="Hotel WiFi Networks", asn_type="residential")
    elif scenario == "corporate_vpn_egress":
        city = rng.choice(["Frankfurt", "Amsterdam", "Singapore", "Sydney"])
        device = rng.choice(known)
        prev_minutes = rng.randint(3, 25)
        ip_attrs.update(asn_name="Zscaler Inc.", asn_type="corporate_vpn")
    elif scenario == "new_device_legit":
        city, device = home, _dev(rng)
        ip_attrs.update(asn_name="Telus", asn_type="residential")
    elif scenario == "impossible_travel_attack":
        city = rng.choice(["Lagos", "Moscow", "Sao Paulo", "Mumbai", "Singapore"])
        device = _dev(rng)
        prev_minutes = rng.randint(5, 90)
        mfa = rng.choice(["push_fatigue_pass", "pass", "fail_then_pass"])
        ip_attrs.update(asn_name=rng.choice(["M247 Ltd", "DigitalOcean", "OVH SAS"]), asn_type="hosting", reputation=rng.choice(["suspicious", "malicious", "clean"]))
    elif scenario == "password_spray_success":
        city = rng.choice(list(CITIES))
        device = _dev(rng)
        auth_method, mfa = "legacy_basic", "not_required"
        ip_attrs.update(asn_name=rng.choice(["Hetzner Online", "Choopa LLC"]), asn_type="hosting", reputation=rng.choice(["suspicious", "malicious"]), failed_logins_24h=rng.randint(40, 900))
    else:  # token_replay: hard case, looks almost normal
        city = home
        device = _dev(rng)
        mfa = "not_required"
        auth_method = "session_token"
        ip_attrs.update(asn_name="Residential Proxy Pool", asn_type="residential_proxy", reputation="clean")

    country, lat, lon = CITIES[city]
    pc, plat, plon = CITIES[prev_city]
    payload = {
        "source": "identity_provider",
        "user": user,
        "src_ip": ip,
        "geo": {"city": city, "country": country, "lat": lat, "lon": lon},
        "device_id": device,
        "user_agent": rng.choice(UAS),
        "auth_method": auth_method,
        "mfa_result": mfa,
        "previous_login": {"city": prev_city, "country": pc, "lat": plat, "lon": plon, "minutes_ago": prev_minutes},
        "detection": "risky_sign_in",
    }
    intel = [("ip", ip, ip_attrs), ("user_profile", user, profile)]
    return GeneratedAlert(f"LG-{idx:06d}", "login", payload, verdict, scenario, intel)
