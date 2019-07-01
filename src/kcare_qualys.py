import os
import sys
import csv
import argparse
import logging
import configparser
import itertools
import collections
import fileinput
import hashlib

from xml.etree import ElementTree

import requests
import qualysapi

logger = logging.getLogger(__name__)


PATCHES_INFO_URL = 'https://patches.kernelcare.com'
CLN_INFO_URL = 'https://cln.cloudlinux.com/api/kcare/patchset.json'


class KcareQualysError(Exception):
    pass


Asset = collections.namedtuple('Asset', 'host ip kernel_id patch_level')


def exists_in_qualys(qgc, asset):
    call = "/api/2.0/fo/asset/host/"
    parameters = {"action": "list", "details": "None", "ips": asset.ip}
    resp = qgc.request(call, parameters)
    tree = ElementTree.fromstring(resp)
    return bool(tree.findall("./RESPONSE/ID_SET/ID"))


def get_assets(keys):
    info_source = get_info_source()
    for key in keys:
        for asset in info_source(key):
            if asset.patch_level > 0:
                yield asset


def get_info_source():
    return cln_source if 'cln.cloudlinux' in CLN_INFO_URL else eportal_source


def eportal_source(key):
    """ Eportal server info can provide only a ip as a server identifier
    """
    resp = requests.get(CLN_INFO_URL + "/api/kcare/patchset/" + key)
    resp.raise_for_status()

    data = resp.json().get('data', [])
    if not data:  # pragma: no cover
        logger.warning("There are no servers binded with '{0}' key".format(key))

    for rec in data:
        asset = Asset(*[None]+rec)
        if asset.patch_level > 0:
            yield asset


def cln_source(key):
    """ Default source
    """
    resp = requests.get(CLN_INFO_URL, {"key": key})
    resp.raise_for_status()
    for rec in resp.json():
        asset = Asset(**rec)
        yield asset


def cache_cve(clbl):
    _CACHE = {}

    def wrapper(asset):
        key = (asset.kernel_id, asset.patch_level)
        if key not in _CACHE:
            _CACHE[key] = clbl(asset)
        return _CACHE[key]
    return wrapper


@cache_cve
def get_cve(asset):
    patch_path = "/{0.kernel_id}/{0.patch_level}/kpatch.info".format(asset)
    resp = requests.get(PATCHES_INFO_URL + patch_path)
    if resp.status_code == 404:  # pragma: no cover
        logger.warning("Kernel `{0.kernel_id}` with patchlevel {0.patch_level} was not found. "
                       "Asset {0.ip} ({0.host}) skipped".format(asset))
    else:
        resp.raise_for_status()
        result = frozenset(extract_cve(resp.text))
        return result


def extract_cve(text):
    result = []
    for line in text.splitlines():
        if line.startswith("kpatch-cve: "):
            _, _, cve_raw = line.partition(": ")
            for cve in cve_raw.split():
                if cve.startswith('CVE-'):
                    result.append(cve.upper().rstrip(','))
    return result


def create_search(qgc, cve_list):
    call = "/api/2.0/fo/qid/search_list/dynamic/"
    cve_ids = ','.join(cve_list)
    search_name = "CVE-Search-" + hashlib.md5(cve_ids.encode('utf-8')).hexdigest()

    # Find already created search list
    parameters = {'action': 'list', 'show_qids': '0', 'show_option_profiles': '0',
                  'show_distribution_groups': '0', 'show_report_templates': '0',
                  'show_remediation_policies': '0'}
    resp = qgc.request(call, parameters, http_method='get')
    tree = ElementTree.fromstring(resp)
    for dlist in tree.findall('./RESPONSE/DYNAMIC_LISTS/DYNAMIC_LIST'):
        if dlist.find('./TITLE').text == search_name:
            return dlist.find('./ID').text

    # Create searchlist if it not exists
    parameters = {'action': 'create', 'title': search_name, 'global': '0',
                  'cve_ids': cve_ids}
    resp = qgc.request(call, parameters)
    tree = ElementTree.fromstring(resp)
    value = tree.find('./RESPONSE/ITEM_LIST/ITEM/VALUE')
    if value is None:
        raise KcareQualysError("Unexpected result from search_list create: {0}".format(tree))
    return value.text


def get_qid_list(qgc, search_id):
    call = "/api/2.0/fo/qid/search_list/dynamic/"
    parameters = {"action": "list", "ids": search_id}
    resp = qgc.request(call, parameters, http_method='get')
    tree = ElementTree.fromstring(resp)
    for qid in tree.findall('./RESPONSE/DYNAMIC_LISTS/DYNAMIC_LIST/QIDS/QID'):
        yield qid.text


def ignore_qid(qgc, asset_list, qid_list):
    call = "ignore_vuln.php"
    ips = ','.join(asset.ip for asset in asset_list)

    # Qualys API accepts only 10 QIP in one query
    args = [qid_list] * 10
    for chunk in itertools.zip_longest(*args):
        qids = ",".join(filter(None, chunk))
        logger.debug("QID chunk for {1}: {0}".format(qids, ips))
        parameters = {"action": "ignore", "qids": qids, "ips": ips,
                      "comments": 'Added by kernelcare'}
        qgc.request(call, parameters, api_version=1, http_method='post')


def delete_search(qgc, search_id):
    call = "/api/2.0/fo/qid/search_list/dynamic/"
    parameters = {'action': 'delete', 'id': search_id}
    qgc.request(call, parameters)


def fetch(args, qgc, keys):
    call = "/api/2.0/fo/scan/"
    for ref in args.refs:
        parameters = {
            'action': 'fetch',
            'scan_ref': ref,
            'output_format': 'csv',
        }
        report = qgc.request(call, parameters)
        report_filename = os.path.join(args.output, ref.replace('/', '-')+'.csv')
        with open(report_filename, 'w') as rf:
            rf.write(report)
        logger.info("{0} was saved".format(report_filename))


def patch(args, qgc, keys):
    """ Entrypoint for patch command.
    """
    logger.info("Started")
    files_input = fileinput.input(files=args.files if args.files else ('-', ))
    csv.register_dialect('qualys', delimiter=',', quotechar='"',
            quoting=csv.QUOTE_NONNUMERIC)

    reader = csv.reader(files_input, dialect='qualys')
    writer = csv.writer(sys.stdout, dialect='qualys')

    # Seach headers
    headers = []
    lineno = 0
    while 'QID' not in headers:
        headers = next(reader)
        lineno += 1
        writer.writerow(headers)

    if not headers:
        raise KcareQualysError("There was no QID column in a report.")

    cache = collections.defaultdict(set)
    plan = collections.defaultdict(set)
    for asset in get_assets(keys):
        logger.info("Asset {0.ip} ({0.host}) was found.".format(asset))
        cve_set = get_cve(asset)
        if cve_set:
            logger.info("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1")
            logger.info("{0} CVEs was found.".format(len(cve_set)))
            logger.info(cve_set)
            plan[cve_set].add(asset)

    for cve_set, asset_list in plan.items():
        search_id = create_search(qgc, cve_set)
        try:
            qid_list = set(get_qid_list(qgc, search_id))
            for asset in asset_list:
                cache[asset.ip] |= qid_list
                if asset.host:
                    cache[asset.host] |= qid_list
        finally:
            delete_search(qgc, search_id)
        logger.info('{0} QIDs was found for {1} assets'.format(
            len(qid_list), len(asset_list)))

    for lineno, row in enumerate(reader, lineno):
        data = dict(zip(headers, row))
        if 'QID' in data:
            qid, ip = data['QID'], data['IP']
            dns_name = data.get('DNS Name') or data.get("DNS")
            qids_to_exclude = cache[ip] | cache[dns_name]
            if qid not in qids_to_exclude:
                writer.writerow(row)
            else:
                logger.info("Line {0} was skipped [QID: {1}, ip: {2}]".format(lineno, qid, ip))
        else:
            # Malformed line write as is
            writer.writerow(row)

    logger.info("Done")


def ignore(args, qgc, keys):
    """ Entrypoint for ignore command.
    """

    plan = collections.defaultdict(set)

    # Each asset (server) should be processed individually and group it by set of CVEs
    for asset in get_assets(keys):

        if not exists_in_qualys(qgc, asset):
            logger.warning("Asset `{0}` was not found as Qualy host. Skipped".format(asset))
            continue

        logger.info("Asset founded {0}".format(asset))
        cve_set = get_cve(asset)
        if cve_set:
            logger.info("CVE was found: {0}".format(len(cve_set)))
            plan[cve_set].add(asset)

    for cve_set, asset_list in plan.items():
        search_id = create_search(qgc, cve_set)
        logger.debug("Dyanmic search list created: {0}".format(search_id))
        try:
            qid_list = get_qid_list(qgc, search_id)
            ignore_qid(qgc, asset_list, qid_list)
            logger.info("All QIDs was marked as ignored")
        finally:
            delete_search(qgc, search_id)
            logger.debug("Dyanmic search list removed: {0}".format(search_id))


def setup_logging(args):
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    verbose_level = logging.INFO if args.verbose else logging.ERROR
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(verbose_level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--configfile', default="qualys.conf",
                        help='file to read the config from')
    parser.add_argument('-q', '--quiet', action='store_true')
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")

    subparsers = parser.add_subparsers()

    parser_ignore = subparsers.add_parser('ignore')
    parser_ignore.set_defaults(func=ignore)

    parser_patch = subparsers.add_parser('patch')
    parser_patch.set_defaults(func=patch)
    parser_patch.add_argument('files', metavar='FILE', nargs='*',
                              help='reports to patch, if empty, stdin is used')

    parser_fetch = subparsers.add_parser('fetch')
    parser_fetch.add_argument('refs', metavar='REF', nargs='*',
                              help='reports to fetch')
    parser_fetch.add_argument('-O', '--output', default="")
    parser_fetch.set_defaults(func=fetch)
    return parser.parse_args(args)


def main():
    args = parse_args(sys.argv[1:])
    setup_logging(args)

    config = configparser.ConfigParser()
    config.read(args.configfile)

    # Redefine servers info endpoint id Erpotal is used
    if config.has_option("kernelcare", "cln-info"):
        global CLN_INFO_URL
        CLN_INFO_URL = config.get('kernelcare', 'cln-info').rstrip('/')

    qgc = qualysapi.connect(args.configfile)

    keys = []
    if config.has_option('kernelcare', 'keys'):
        keys.extend(config.get('kernelcare', 'keys').split(','))

    if not keys:
        logger.error("No kernelcare keys was defined.")
        exit(1)

    args.func(args, qgc=qgc, keys=keys)
