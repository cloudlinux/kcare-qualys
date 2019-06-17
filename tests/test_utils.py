import pytest

import kcare_qualys


@pytest.mark.parametrize("test_input,expected", [
    ("", []),
    ("kpatch-cve: ", []),
    ("kpatch-cve: CVE-1", ["CVE-1"]),
    ("kpatch-cve: CVE-1\nCVE-2", ["CVE-1"]),
    ("kpatch-cve: CVE-1\nkpatch-cve: CVE-2", ["CVE-1", "CVE-2"]),
    ("kpatch-cve: N/A", []),
])
def test_extract_cve(test_input, expected):
    assert kcare_qualys.extract_cve(test_input) == expected
