import random
from collections.abc import Iterator

from app.data.common import GeneratedAlert
from app.data.logins import generate_login
from app.data.phishing import generate_phishing


def alert_stream(n: int, types: list[str], seed: int = 7, start_idx: int = 0) -> Iterator[GeneratedAlert]:
    rng = random.Random(seed)
    for i in range(n):
        t = rng.choice(types)
        idx = start_idx + i
        yield generate_phishing(rng, idx) if t == "phishing" else generate_login(rng, idx)
