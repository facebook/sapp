# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from pathlib import Path

from setuptools import find_packages, setup


def _requirements():
    return Path("requirements.txt").read_text()


setup(
    name="fb-sapp",
    version="0.5.1",
    description="Static Analysis Post-Processor for processing taint analysis results.",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    install_requires=_requirements(),
    entry_points={"console_scripts": ["sapp = sapp.cli:cli"]},
    packages=find_packages(),
    url="https://github.com/facebook/sapp",
    author="Facebook",
    maintainer_email="pyre@fb.com",
    package_data={
        "sapp.ui": [
            "frontend/build/*",
            "frontend/build/static/css/*",
            "frontend/build/static/js/*",
        ],
    },
)
