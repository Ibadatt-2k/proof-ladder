from app.ladder.stats import wilson_lower_bound


def test_wilson_zero():
    assert wilson_lower_bound(0, 0) == 0.0


def test_wilson_more_data_tighter_bound():
    small = wilson_lower_bound(49, 50)    # 98% on 50
    large = wilson_lower_bound(1960, 2000)  # 98% on 2000
    assert small < 0.90 < large < 0.98


def test_wilson_known_value():
    assert abs(wilson_lower_bound(95, 100) - 0.8882) < 0.001
