from reconator.domain_recon import detect_wildcard


def test_detect_wildcard_true() -> None:
    def resolver(_):
        return ["203.0.113.10"]

    assert detect_wildcard(resolver, "example.com", attempts=2) is True


def test_detect_wildcard_false() -> None:
    calls = {"count": 0}

    def resolver(_):
        calls["count"] += 1
        return [] if calls["count"] == 1 else ["203.0.113.10"]

    assert detect_wildcard(resolver, "example.com", attempts=2) is False
