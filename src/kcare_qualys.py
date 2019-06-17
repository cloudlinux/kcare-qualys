import os
import sys
import csv
import argparse
import logging
import configparser
import itertools
import collections
import fileinput

from xml.etree import ElementTree

import requests
import qualysapi

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


PATCHES_INFO_URL = 'https://patches.kernelcare.com'
CLN_INFO_URL = 'https://cln.cloudlinux.com'


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


def exists_in_qualys(qgc, asset):
    call = "/api/2.0/fo/asset/host/"
    parameters = {"action": "list", "details": "None", "ips": "{ip}".format(**asset)}
    resp = qgc.request(call, parameters)
    tree = ElementTree.fromstring(resp)
    return bool(tree.findall("./RESPONSE/ID_SET/ID"))


def get_assets(keys):
    for key in keys:
        resp = requests.get(CLN_INFO_URL + "/api/kcare/patchset/" + key)
        resp.raise_for_status()
        for asset in resp.json()['data']:
            result = dict(zip(('ip', 'kernel_id', 'patch_level'), asset))
            result['host'] = ''
            yield result


def get_cve(asset):
    resp = requests.get(PATCHES_INFO_URL + "/{kernel_id}/{patch_level}/kpatch.info".format(**asset))
    resp.raise_for_status()
    return frozenset(extract_cve(resp.text))


def extract_cve(text):
    result = []
    for line in text.splitlines():
        if line.startswith("kpatch-cve: "):
            _, _, cve_raw = line.partition(": ")
            for cve in cve_raw.split():
                if cve.startswith('CVE-'):
                    result.append(cve.upper())
    return result


def create_search(qgc, cve_list):
    call = "/api/2.0/fo/qid/search_list/dynamic/"
    cve_ids = ','.join(cve_list)
    parameters = {'action': 'create', 'title': 'CVE-Search-Test8', 'global': '1',
                  'cve_ids': cve_ids}
    resp = qgc.request(call, parameters)
    tree = ElementTree.fromstring(resp)
    return tree.find('./RESPONSE/ITEM_LIST/ITEM/VALUE').text


def get_qid_list(qgc, search_id):
    call = "/api/2.0/fo/qid/search_list/dynamic/"
    parameters = {"action": "list", "ids": search_id}
    resp = qgc.request(call, parameters, http_method='get')
    tree = ElementTree.fromstring(resp)
    for qid in tree.findall('./RESPONSE/DYNAMIC_LISTS/DYNAMIC_LIST/QIDS/QID'):
        yield qid.text


def ignore_qid(qgc, asset_list, qid_list):
    call = "ignore_vuln.php"
    ips = ','.join(asset['ip'] for asset in asset_list)

    # Qualys API accepts only 10 QIP in one query
    args = [qid_list] * 10
    for chunk in itertools.zip_longest(*args):
        qids = ",".join(filter(None, chunk))
        logger.debug("QID chunk for {1}: {0}".format(qids, ips))
        parameters = {"action": "ignore", "qids": qids, "ips": ips, "comments": 'Added by kernelcare'}
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
    files_input = fileinput.input(files=args.files if args.files else ('-', ))
    csv.register_dialect('qualys', delimiter=',', quotechar='"',
            quoting=csv.QUOTE_NONNUMERIC)

    reader = csv.reader(files_input, dialect='qualys')
    writer = csv.writer(sys.stdout, dialect='qualys')

    headers = next(reader)
    writer.writerow(headers)
    cache = collections.defaultdict(set)
    for asset in get_assets(keys):
        cve_set = get_cve(asset)
        search_id = create_search(qgc, cve_set)
        try:
            qid_list = set(get_qid_list(qgc, search_id))
            cache[asset['ip']] = qid_list
            cache[asset['host']] = qid_list
        finally:
            delete_search(qgc, search_id)
    for row in reader:
        data = dict(zip(headers, row))
        qid = data['QID']
        qids_to_exclude = cache[data['IP']] | cache[data['DNS Name']]
        if qid not in qids_to_exclude:
            writer.writerow(row)


def ignore(args, qgc, keys):

    plan = collections.defaultdict(list)

    # Each asset (server) should be processed individually and group it by set of CVEs
    for asset in get_assets(keys):
        if not exists_in_qualys(qgc, asset):
            logger.warning("Asset {host} ({ip}) was not found as Qualy host. Skipped".format(**asset))
            continue
        logger.info("Asset founded {host}({ip})".format(**asset))
        logger.debug("Asset kernel: {kernel_id}-{patch_level}".format(**asset))
        cve_set = get_cve(asset)
        logger.info("CVE was found: {0}".format(len(cve_set)))
        logger.debug("CVE list: {0}".format(cve_set))
        plan[cve_set].append(asset)

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


def main():
    args = parse_args(sys.argv[1:])

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    config = configparser.ConfigParser()
    config.read(args.configfile)

    if config.has_option("kernelcare", "patches-info"):
        global PATCHES_INFO_URL
        PATCHES_INFO_URL = config.get('kernelcare', 'patches-info').rstrip('/')

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