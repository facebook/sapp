#!/bin/bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

set -e

SCRIPTS_DIRECTORY="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "${SCRIPTS_DIRECTORY}/.."

echo '  Enumerating backend test files:'
files=$(find sapp -name '*_test.py' ! -name 'sharded_files_test.py' ! -name 'cli_test.py')
echo "${files}"
if [[ -z "${files}" ]]; then
  echo 'No test files found, exiting.'
  exit 2
fi

if [ "$1" == "--with-coverage" ]; then
  echo '  Running backend tests with coverage results:'
  echo "${files}" | sed 's/.py$//' | sed 's:/:.:g' | xargs python -m coverage run -m unittest -v
  python -m coverage report --show-missing --ignore-errors --skip-empty
else
  echo '  Running backend tests'
  echo "${files}" | sed 's/.py$//' | sed 's:/:.:g' | xargs python -m unittest -v
fi

cd "$(dirname "$0")/.." || exit 1
if [ "$1" == "--with-coverage" ]; then
  echo '  Running frontend tests with coverage results:'
  (cd sapp/ui/frontend && npm install && npm run ui-test)
else
  echo '  Running frontend tests:'
  (cd sapp/ui/frontend && npm install && npm run ui-test -- --coverage=false)
fi
