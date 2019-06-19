# Kcare-qualys

[![Build Status](https://travis-ci.org/cloudlinux/kcare-qualys.svg?branch=master)](https://travis-ci.org/cloudlinux/kcare-qualys)

## Configuration

Example: qualys.conf.template

## Fetch reports

Just downloads reports defined by scan-ref and save it

    $ kcare-qualys fetch scan/1560244999.61890
    INFO:kcare_qualys:scan-1560244999.61890.csv was saved

## Patch reports

Process the report and exclude CVE that patched by kernelcare.

How to use:

Pass the report as a parameter

    kcare-qualys patch report.csv > patched_report.csv

or through pipe

    cat report.csv | kcare-qualys patch > patched_report.csv

## Ignore QIDs (alpha)

It will search all assets that registered in Kernelcare and Qualys and for each of them will perform:
 - detect all CVEs for the kernel
 - collect all QID associated with those CVEs
 - mark them as ignored

How to use:

    kcare-qualys -v ignore
