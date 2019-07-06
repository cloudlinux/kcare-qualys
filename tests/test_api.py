import os
import collections

import pytest
import mock
import responses

import kcare_qualys


@pytest.fixture
def qgc():
    return mock.Mock()


class ProxyIter(object):
    def __init__(self, wrapped):
        self.wrapped = wrapped
    def __iter__(self):
        return self
    def __next__(self):
        return next(self.wrapped)
    next = __next__


def test_exists_in_qualys(qgc):
    asset = kcare_qualys.Asset('hostname', '127.0.0.1', 'kernel-id', 1)
    qgc.request.return_value = """
    <HOST_LIST_OUTPUT >
        <RESPONSE>
            <DATETIME>2019-05-31T17:42:35Z</DATETIME>
            <ID_SET>
                <ID>123456</ID>
            </ID_SET>
        </RESPONSE>
    </HOST_LIST_OUTPUT>
    """
    assert kcare_qualys.exists_in_qualys(qgc, asset)

    qgc.request.return_value = """
    <HOST_LIST_OUTPUT >
        <RESPONSE>
            <DATETIME>2019-05-31T17:44:21Z</DATETIME>
        </RESPONSE>
    </HOST_LIST_OUTPUT>
    """
    assert not kcare_qualys.exists_in_qualys(qgc, asset)


def test_create_search(qgc):
    qgc.request.return_value = """
    <SIMPLE_RETURN >
        <RESPONSE>
            <DATETIME>2019-05-31T17:50:28Z</DATETIME>
            <TEXT>New search list created successfully</TEXT>
            <ITEM_LIST>
            <ITEM>
                <KEY>ID</KEY>
                <VALUE>3034713</VALUE>
            </ITEM>
            </ITEM_LIST>
        </RESPONSE>
    </SIMPLE_RETURN>
    """
    result = kcare_qualys.create_search(qgc, ["CVE-1", "CVE-2"])
    assert result == "3034713"


def test_get_qids_list(qgc):
    qgc.request.return_value = """
    <DYNAMIC_SEARCH_LIST_OUTPUT >
    <RESPONSE>
        <DATETIME>2019-05-31T19:03:37Z</DATETIME>
        <DYNAMIC_LISTS>
        <DYNAMIC_LIST>
            <QIDS>
            <QID>157849</QID>
            </QIDS>
        </DYNAMIC_LIST>
        </DYNAMIC_LISTS>
    </RESPONSE>
    </DYNAMIC_SEARCH_LIST_OUTPUT>
    """
    result = kcare_qualys.get_qid_list(qgc, "search_id")
    assert list(result) == ["157849"]


def test_delete_search(qgc):
    qgc.request.return_value = ""
    kcare_qualys.delete_search(qgc, "search_id")


@responses.activate
def test_get_assets():
    responses.add(
        responses.GET,
        "https://cln.cloudlinux.com/api/kcare/patchset.json?key=test_key",
        json=[{
            "ip": "127.0.0.1",
            "host": "my.example.com",
            "kernel_id": "kernel-id",
            "patch_level": 1}],
        status=200
    )
    assets = list(kcare_qualys.get_assets(["test_key"]))
    assert len(assets) == 1

    with mock.patch('kcare_qualys.CLN_INFO_URL', "http://eportal.example.com"):
        responses.add(
            responses.GET,
            "http://eportal.example.com/api/kcare/patchset/test_key",
            json={'data': [["127.0.0.1", "kernel_id", 2]]},
            status=200
        )
        assets = list(kcare_qualys.get_assets(["test_key"]))
        assert len(assets) == 1



@responses.activate
@mock.patch('kcare_qualys.extract_cve', return_value=set(["CVE1", "CVE2"]))
def test_get_cve(mock_extract_cve):
    responses.add(responses.GET, "https://patches.kernelcare.com/kernel-id/1/kpatch.info",
                  body="kpatch info", status=200)
    asset = kcare_qualys.Asset("host", "ip", "kernel-id", 1)
    cve_list = kcare_qualys.get_cve(asset)
    mock_extract_cve.assert_called_once_with("kpatch info")
    assert cve_list == set(['CVE1', 'CVE2'])


@mock.patch('kcare_qualys.get_assets')
@mock.patch('kcare_qualys.get_cve')
@mock.patch('kcare_qualys.create_search')
@mock.patch('kcare_qualys.delete_search')
@mock.patch('kcare_qualys.get_qid_list')
def test_get_qip_map(mock_get_qid_list, mock_delete_search, mock_create_search,
                     mock_get_cve, mock_get_assets, qgc):

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

    result = kcare_qualys.get_filtered(reader, qid_map)
    assert list(result) == [
        ["QID", "IP", "DNS Name"],
        ["123458", "54.93.87.241", "ec2-54-93-87-241.eu-central-1.compute.amazonaws.com"]
    ]


def test_get_filtered_no_qid_column():
    reader = ProxyIter(iter([]))
    result = kcare_qualys.get_filtered(reader, {})
    with pytest.raises(kcare_qualys.KcareQualysError):
        list(result)

    reader = ProxyIter(iter([["id", "name"]]))
    result = kcare_qualys.get_filtered(reader, {})
    with pytest.raises(kcare_qualys.KcareQualysError):
        list(result)
