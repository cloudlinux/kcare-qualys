import pytest
import mock
import responses

import kcare_qualys


@pytest.fixture
def qgc():
    return mock.Mock()


def test_exists_in_qualys(qgc):
    asset = kcare_qualys.Asset('127.0.0.1', 'kernel-id', 1)
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
    responses.add(responses.GET, "https://cln.cloudlinux.com/api/kcare/patchset/test_key",
            json={'data': [["ip", "kernel_id", 2]]}, status=200)
    assets = list(kcare_qualys.get_assets(["test_key"]))
    assert len(assets) == 1


@responses.activate
@mock.patch('kcare_qualys.extract_cve', return_value=set(["CVE1", "CVE2"]))
def test_get_cve(mock_extract_cve):
    responses.add(responses.GET, "https://patches.kernelcare.com/kernel-id/1/kpatch.info",
                  body="kpatch info", status=200)
    asset = kcare_qualys.Asset("ip", "kernel-id", 1)
    cve_list = kcare_qualys.get_cve(asset)
    mock_extract_cve.assert_called_once_with("kpatch info")
    assert cve_list == set(['CVE1', 'CVE2'])
