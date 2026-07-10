from backend.app.util.semver import version_in_range


def test_open_range_matches_all():
    assert version_in_range("9.9.9", "*") is True
    assert version_in_range("1.0.0", "") is True


def test_log4shell_range():
    # CVE-2021-44228 affects >=2.0.0,<2.15.0
    assert version_in_range("2.14.1", ">=2.0.0,<2.15.0") is True
    assert version_in_range("2.17.1", ">=2.0.0,<2.15.0") is False
    assert version_in_range("1.2.17", ">=2.0.0,<2.15.0") is False


def test_upper_bound_exclusive():
    # pillow 8.2.0 should NOT match "<8.2.0" (already patched)
    assert version_in_range("8.2.0", "<8.2.0") is False
    assert version_in_range("8.1.0", "<8.2.0") is True


def test_invalid_version_is_not_matched():
    assert version_in_range("not-a-version", ">=1.0.0") is False
