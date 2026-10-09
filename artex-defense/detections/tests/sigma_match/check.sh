#!/bin/sh
#
# In-container half of the ARTEX Sigma live event-matching test. run.sh launches
# this inside a Python container with the Sigma rule tree (atomic rules and the
# correlation/ subtree) mounted read-only at /sigma and this directory at /src. It
# installs a pinned pySigma, then hands off to check.py, which asserts that every
# atomic rule matches its malicious sample events and stays quiet on its benign
# ones, and that every correlation rule fires on its positive timeline and stays
# quiet on its negative ones (see check.py's header for the trust model and
# scope). pySigma does the parsing; check.py walks the compiled condition tree and
# aggregation spec and tests each sample event or timeline against it.
#
# POSIX sh (the slim image ships dash). Exits non-zero if any assertion fails.
set -eu

VERSION="${PYSIGMA_VERSION:-2.0.0}"

pip install --quiet --disable-pip-version-check "pysigma==${VERSION}" >/dev/null 2>&1

exec python3 /src/check.py
