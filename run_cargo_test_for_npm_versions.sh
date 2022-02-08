#!/bin/bash

set -e -u

# shellcheck disable=SC1090
source "${NVM_DIR}/nvm.sh"

for version in 8 9 10 12 14 16
do
  nvm use "v${version}"
  set +e
  if [[ "${version}" != "9" ]]; then
    # nodejs9 uses old npm 5 version which does not have audit yet
    cargo test audit
  fi
  cargo test outdated
  set -e
done
nvm use system
