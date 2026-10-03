from dataclasses import dataclass, field


@dataclass
class GeneratedAlert:
    external_id: str
    alert_type: str
    payload: dict
    human_verdict: str  # malicious | benign
    scenario: str
    intel: list[tuple[str, str, dict]] = field(default_factory=list)  # (kind, key, attrs)


CITIES = {
    "Vancouver": ("CA", 49.28, -123.12), "Toronto": ("CA", 43.65, -79.38),
    "Seattle": ("US", 47.61, -122.33), "New York": ("US", 40.71, -74.01),
    "London": ("GB", 51.51, -0.13), "Frankfurt": ("DE", 50.11, 8.68),
    "Singapore": ("SG", 1.35, 103.82), "Sydney": ("AU", -33.87, 151.21),
    "Sao Paulo": ("BR", -23.55, -46.63), "Lagos": ("NG", 6.52, 3.38),
    "Moscow": ("RU", 55.76, 37.62), "Mumbai": ("IN", 19.08, 72.88),
    "Amsterdam": ("NL", 52.37, 4.90), "Tokyo": ("JP", 35.68, 139.69),
}

CORP_DOMAIN = "acme-corp.com"
