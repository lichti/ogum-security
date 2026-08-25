"""SPDX license id -> category mapping for the Software Inventory Licenses sub-tab (US-14.06).

Not an exhaustive SPDX license list — covers the identifiers Trivy/CycloneDX SBOMs
commonly surface for OS and language packages. Unmapped ids fall back to "unknown"
rather than a guessed category.
"""

from __future__ import annotations

_PERMISSIVE = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Unlicense",
    "Zlib",
    "Python-2.0",
}
_WEAK_COPYLEFT = {
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-1.1",
    "MPL-2.0",
    "EPL-1.0",
    "EPL-2.0",
}
_COPYLEFT = {
    "GPL-1.0-only",
    "GPL-1.0-or-later",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
}

# SPDX-deprecated bare ids, superseded by the -only/-or-later variants above.
DEPRECATED_SPDX_IDS = {
    "GPL-1.0",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "AGPL-1.0",
    "AGPL-3.0",
}

_DEPRECATED_TO_CATEGORY = {
    "GPL-1.0": "copyleft",
    "GPL-2.0": "copyleft",
    "GPL-3.0": "copyleft",
    "AGPL-1.0": "copyleft",
    "AGPL-3.0": "copyleft",
    "LGPL-2.0": "weak_copyleft",
    "LGPL-2.1": "weak_copyleft",
    "LGPL-3.0": "weak_copyleft",
}


def categorize_license(license_id: str) -> str:
    if license_id in _PERMISSIVE:
        return "permissive"
    if license_id in _WEAK_COPYLEFT:
        return "weak_copyleft"
    if license_id in _COPYLEFT:
        return "copyleft"
    if license_id in _DEPRECATED_TO_CATEGORY:
        return _DEPRECATED_TO_CATEGORY[license_id]
    return "unknown"


def is_deprecated_license(license_id: str) -> bool:
    return license_id in DEPRECATED_SPDX_IDS
