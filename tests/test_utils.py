import pytest
import mock
import requests

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


def test_filter_empty_quotes(tmpdir):
    infile = tmpdir.join('input.csv')
    infile.write('"test","","", "test"')
    result = list(kcare_qualys.filter_empty_quotes(str(infile)))
    assert result == ['"test",,, "test"']


def test_connection_wrapper():
    qgc = mock.Mock()
    qgc.request.side_effect = requests.exceptions.ConnectionError
    with pytest.raises(kcare_qualys.KcareQualysError):
        kcare_qualys.delete_search(qgc, 'test')
