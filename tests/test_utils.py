import collections

import pytest
import mock

import kcare_qualys


class ProxyIter(object):
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __iter__(self):
        return self

    def __next__(self):
        return next(self.wrapped)
    next = __next__


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


@mock.patch('kcare_qualys.get_assets')
@mock.patch('kcare_qualys.get_cve')
@mock.patch('kcare_qualys.create_search')
@mock.patch('kcare_qualys.delete_search')
@mock.patch('kcare_qualys.get_qid_list')
def test_get_qip_map(mock_get_qid_list, mock_delete_search, mock_create_search,
                     mock_get_cve, mock_get_assets):
    qgc = mock.Mock()
    mock_get_assets.return_value = [
        kcare_qualys.Asset("host1", "127.0.0.1", "kernel-id-1", 2),
        kcare_qualys.Asset("host2", "127.0.0.2", "kernel-id-2", 1)
    ]
    cves = frozenset(["CVE-1", "CVE-2"])
    qids = ["QID001", "QID002"]

    mock_get_cve.return_value = cves
    mock_get_qid_list.return_value = qids
    keys = ["key1", "key2"]
    assert kcare_qualys.get_qid_map(qgc, keys) == collections.defaultdict(set,
        {'127.0.0.2': set(qids), 'host2': set(qids), '127.0.0.1': set(qids), 'host1': set(qids)})


def test_get_filtered():

    qid_map = {
        "54.93.87.241": set(["123456"]),
        "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com": set(["123457"])
    }
    reader = ProxyIter(iter([
        ["QID", "IP", "DNS Name"],
        ["123456", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123457", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
    ]))
    reader.__dict__['line_num'] = 0

    result = kcare_qualys.get_filtered(reader, qid_map, False)
    assert list(result) == [
        ["QID", "IP", "DNS Name"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"]
    ]

def test_get_filtered_mark_only():

    qid_map = {
        "54.93.87.241": set(["123456"]),
        "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com": set(["123457"])
    }
    data = [
        ["QID", "IP", "DNS Name"],
        ["123456", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123457", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
    ]
    reader = ProxyIter(iter(data))
    reader.__dict__['line_num'] = 0

    reader = ProxyIter(iter(data))
    result = kcare_qualys.get_filtered(reader, qid_map, True)
    assert list(result) == [
        ["QID", "IP", "DNS Name", "KC Patched"],
        ["123456", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "yes"],
        ["123457", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "yes"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "no"],
    ]


def test_get_filtered_additional_headers():

    qid_map = {
        "54.93.87.241": set(["123456"]),
        "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com": set(["123457"])
    }
    data = [
        ['some', 'additional', 'headers'],
        ["QID", "IP", "DNS Name"],
        ["123456", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123457", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"],
    ]
    reader = ProxyIter(iter(data))
    result = kcare_qualys.get_filtered(reader, qid_map, True)

    assert list(result) == [
        ['some', 'additional', 'headers'],
        ["QID", "IP", "DNS Name", "KC Patched"],
        ["123456", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "yes"],
        ["123457", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "yes"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com", "no"],
    ]


def test_get_filtered_no_qid_column():
    reader = ProxyIter(iter([]))
    result = kcare_qualys.get_filtered(reader, {}, False)
    with pytest.raises(kcare_qualys.KcareQualysError):
        list(result)

    reader = ProxyIter(iter([["id", "name"]]))
    result = kcare_qualys.get_filtered(reader, {}, False)
    with pytest.raises(kcare_qualys.KcareQualysError):
        list(result)
