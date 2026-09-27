#!/usr/bin/env bash
# openscap-setup.sh — install the OpenSCAP scanner + SSG datastreams on
# a managed host so soc_scanner.py (oscap-ssh) can run XCCDF evals on it.
#
# The DATASTREAM itself is pushed from the SOC host by oscap-ssh — only
# the oscap binary is required on the target. Run ON THE TARGET as a
# sudo-capable user:
#   sudo bash deploy/openscap-setup.sh
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # openscap-scanner: the oscap binary; scap-security-guide: local SSG
    # datastreams (nice-to-have — oscap-ssh pushes the SOC host's copy).
    apt-get install -y -qq openscap-scanner scap-security-guide \
        || apt-get install -y -qq openscap-scanner
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y openscap-scanner scap-security-guide
elif command -v yum >/dev/null 2>&1; then
    yum install -y openscap-scanner scap-security-guide
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install openscap-scanner scap-security-guide
else
    echo "no supported package manager found (apt/dnf/yum/zypper)" >&2
    exit 1
fi

command -v oscap >/dev/null 2>&1 || { echo "oscap still missing" >&2; exit 1; }
echo "oscap ready: $(oscap --version | head -1)"
if [ -d /usr/share/xml/scap/ssg/content ]; then
    echo "local SSG content: $(ls /usr/share/xml/scap/ssg/content/*-ds.xml 2>/dev/null | wc -l) datastream(s)"
else
    echo "local SSG content: none (oscap-ssh will push the SOC host's datastream)"
fi