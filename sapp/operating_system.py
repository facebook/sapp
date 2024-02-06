# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Operating system-related utilities.
"""

try:
    import psutil
except ImportError:
    psutil = None


def get_rss_in_gb() -> float:
    if psutil is None:
        return 0
    return psutil.Process().memory_info().rss / (1000**3)
