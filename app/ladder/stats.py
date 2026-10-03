import math


def wilson_lower_bound(successes: int, n: int, z: float = 1.96) -> float:
    """Lower bound of the 95% Wilson score interval.

    98% agreement on 50 alerts and on 2,000 alerts are very different claims;
    the lower bound is what we can defend, so promotion decisions use it.
    """
    if n == 0:
        return 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (centre - margin) / denom)
