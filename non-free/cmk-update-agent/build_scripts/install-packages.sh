#!/bin/bash

set -e -x -o pipefail

/opt/install-openssl.sh
/opt/install-python.sh "${PYTHON_VERSION}"
# shellcheck disable=SC2102 # Ranges can only match single chars (mentioned due to duplicates).
/opt/bin/python3 -m pip install --no-index --find-links="/src/pip${BITNESS_SUFFIX}" pyinstaller requests[socks] cryptography
