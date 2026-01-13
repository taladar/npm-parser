#!/bin/bash

set -e -u

# shellcheck disable=SC1090,SC1091
source "${NVM_DIR}/nvm.sh"

for version in 8 9 10 12 14 16; do
  nvm use "v${version}"
  set +e
  if [[ "${version}" != "9" ]]; then
    # nodejs9 uses old npm 5 version which does not have audit yet
    npm audit --json >"npm_audit_nodejs${version}.json"
  fi
  npm outdate --json >"npm_outdated_nodejs${version}.json"
  set -e
done
nvm use system
