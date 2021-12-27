#! /bin/sh
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Script to publish package to PyPI. Note that version bump
# in `setup.py` is manual

set -e
set -x

cd "$(dirname "$0")/.." || exit 1

(cd sapp/ui/frontend && npm install && npm run build)

rm -rf dist
pip install wheel twine
python setup.py sdist bdist_wheel
python -m twine upload dist/*
