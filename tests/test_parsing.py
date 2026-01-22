from pathlib import Path

import pytest

from reconator.parsing import parse_targets_file
from reconator.utils import ReconatorError, normalize_engagement_name


def test_parse_targets_file(tmp_path: Path) -> None:
    content = """
# comment
192.0.2.1
198.51.100.0/30
invalid
"""
    target_file = tmp_path / "targets.txt"
    target_file.write_text(content, encoding="utf-8")

    result = parse_targets_file(target_file, allow_cidr_expand=True, cidr_cap=10)
    assert result.targets == ["192.0.2.1", "198.51.100.1", "198.51.100.2"]
    assert "invalid" in result.skipped


def test_parse_targets_file_cidr_cap(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("198.51.100.0/29", encoding="utf-8")
    with pytest.raises(ReconatorError):
        parse_targets_file(target_file, allow_cidr_expand=True, cidr_cap=4)


def test_engagement_name_validation() -> None:
    assert normalize_engagement_name("Acme Test") == "Acme_Test"
    with pytest.raises(ReconatorError):
        normalize_engagement_name("bad/name")
