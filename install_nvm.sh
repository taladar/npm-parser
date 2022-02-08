#!/bin/bash

set -e -u

echo "Installing nvm from https://github.com/nvm-sh/nvm"
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash

export NVM_DIR="$HOME/.nvm"
# shellcheck disable=SC1090
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm

echo "Installing nodejs8 via nvm"
nvm install v8
echo "Installing nodejs9 via nvm"
nvm install v9
echo "Installing nodejs10 via nvm"
nvm install v10
echo "Installing nodejs12 via nvm"
nvm install v12
echo "Installing nodejs14 via nvm"
nvm install v14
echo "Installing nodejs16 via nvm"
nvm install v16
