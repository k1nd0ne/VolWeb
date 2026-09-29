"""
Linux ISF (Intermediate Symbol File) resolution.

Given a kernel banner extracted from a memory image, look it up in the
community remote index (Abyss-W4tcher/volatility3-symbols) and download the
matching ISF into the VolWeb symbols directory so Volatility can use it.

When no ISF can be imported, build human-readable guidance telling the analyst
exactly which debug package to fetch and how to produce the ISF manually.
"""
import json
import logging
import os
import re
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

_REPO_RAW_BASE = "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/"
# banners_plain.json maps the *plain* banner string -> [ISF paths]. (banners.json
# is the internal --remote-isf-url format, keyed by Python bytes-repr, and must
# NOT be used for plain-string lookups.)
_BANNERS_INDEX_URL = _REPO_RAW_BASE + "banners/banners_plain.json"

# Where downloaded ISFs land — already on Volatility's symbol path (see
# volatility_engine/utils.py). Kept under a "linux" subdir by convention.
_SYMBOLS_SUBDIR = os.path.join("symbols", "linux")
_INDEX_CACHE = os.path.join("symbols", "_banners_plain_index.json")
_INDEX_TTL_SECONDS = 24 * 3600


def _abs(media_relpath):
    return os.path.join(settings.MEDIA_ROOT, media_relpath)


def _fetch_index():
    """Return the banner->ISF-paths mapping, cached locally with a TTL."""
    cache_path = _abs(_INDEX_CACHE)
    fresh = (
        os.path.exists(cache_path)
        and (time.time() - os.path.getmtime(cache_path)) < _INDEX_TTL_SECONDS
    )
    if not fresh:
        try:
            os.makedirs(os.path.dirname(cache_path), exist_ok=True)
            resp = requests.get(_BANNERS_INDEX_URL, timeout=120)
            resp.raise_for_status()
            with open(cache_path, "wb") as fh:
                fh.write(resp.content)
        except Exception as e:
            logger.warning(f"Failed to refresh remote ISF index: {e}")
            if not os.path.exists(cache_path):
                return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:
        logger.warning(f"Failed to read cached ISF index: {e}")
        return {}


def _normalize(banner):
    return (banner or "").strip().strip("\x00").strip()


def _match_index(index, banner):
    """
    Return the best ISF path for ``banner`` from the index, or None.

    Tries an exact (normalized) match first, then a looser match on the kernel
    version + build id — our extracted banner may differ slightly from the
    index key, but Volatility re-checks the banner exactly during verification,
    so a version/build match is safe for *selecting* the ISF to download.
    """
    # 1. Exact match (fast path).
    if index.get(banner):
        return index[banner][0]
    target = _normalize(banner)
    for key, paths in index.items():
        if paths and _normalize(key) == target:
            return paths[0]

    # 2. Version + build fallback.
    vm = re.search(r"Linux version (\S+)", banner or "")
    if not vm:
        return None
    version = vm.group(1)                     # e.g. 6.5.0-41-generic
    bm = re.search(r"(#\S+)", banner or "")
    build = bm.group(1) if bm else None       # e.g. #41~22.04.2-Ubuntu
    for key, paths in index.items():
        if paths and version in key and (build is None or build in key):
            return paths[0]
    return None


def resolve_isf_remote(banner):
    """
    Look up ``banner`` in the remote index and download the matching ISF.

    Returns the saved path relative to MEDIA_ROOT, or None if not found.
    """
    index = _fetch_index()
    if not index:
        return None

    rel = _match_index(index, banner)
    if not rel:
        return None

    url = _REPO_RAW_BASE + rel
    filename = os.path.basename(rel)
    dest_rel = os.path.join(_SYMBOLS_SUBDIR, filename)
    dest_abs = _abs(dest_rel)
    os.makedirs(os.path.dirname(dest_abs), exist_ok=True)

    try:
        with requests.get(url, stream=True, timeout=300) as resp:
            resp.raise_for_status()
            with open(dest_abs, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    fh.write(chunk)
    except Exception as e:
        logger.warning(f"Failed to download ISF {url}: {e}")
        return None

    logger.info(f"Downloaded ISF for banner to {dest_rel}")
    return dest_rel


def parse_banner(banner):
    """Extract (kernel_version, distro) best-effort from a banner string."""
    kernel = None
    m = re.search(r"Linux version (\S+)", banner or "")
    if m:
        kernel = m.group(1)

    distro = "unknown"
    low = (banner or "").lower()
    if "ubuntu" in low:
        distro = "ubuntu"
    elif "debian" in low:
        distro = "debian"
    elif "kali" in low:
        distro = "kali"
    elif "red hat" in low or "redhat" in low or ".el" in low:
        distro = "rhel"
    elif "almalinux" in low or ".alma" in low:
        distro = "almalinux"
    elif "rocky" in low:
        distro = "rocky"
    elif "arch" in low:
        distro = "arch"
    elif "suse" in low:
        distro = "suse"
    return kernel, distro


def _arch_from_banner(banner):
    low = (banner or "").lower()
    if "x86_64" in low or "amd64" in low:
        return "amd64"
    if "aarch64" in low or "arm64" in low:
        return "arm64"
    return "i386"


def build_manual_guidance(banner):
    """
    Produce structured guidance for building the ISF by hand when it could not
    be imported automatically. Returned to the frontend for display.

    Ubuntu/Kali guidance is made precise using the same banner parsing as
    Abyss-W4tcher/volatility3-symbols' ubuntu_symbols_finder: it derives the
    exact dbgsym package name and .ddeb filename from the banner.
    """
    kernel, distro = parse_banner(banner)
    arch = _arch_from_banner(banner)
    package = None
    where = None

    ubuntu_m = re.search(
        r"Linux version (\d+\.\d+\.\d+-\d+-\S+).+\(Ubuntu (\d+\.\d+\.\d+-\d+\.\d+)",
        banner or "",
    )
    if distro in ("ubuntu", "kali") and ubuntu_m:
        short, extended = ubuntu_m.group(1), ubuntu_m.group(2)  # 5.15.0-79-generic / 5.15.0-79.86
        package = f"linux-image-unsigned-{short}-dbgsym  (version {extended})"
        ddeb = f"linux-image-unsigned-{short}-dbgsym_{extended}_{arch}.ddeb"
        where = (
            f"https://launchpad.net/ubuntu/+source/linux "
            f"(package linux-image-unsigned-{short}-dbgsym, version {extended}) "
            f"— or http://ddebs.ubuntu.com/pool/main/l/linux/{ddeb}"
        )
    elif distro in ("ubuntu", "kali"):
        package = f"linux-image-{kernel}-dbgsym (or linux-image-unsigned-{kernel}-dbgsym)"
        where = "http://ddebs.ubuntu.com/pool/main/l/linux/"
    elif distro == "debian":
        package = f"linux-image-{kernel}-dbg"
        where = "debian-debug archive (https://deb.debian.org/debian-debug/)"
    elif distro in ("rhel", "almalinux", "rocky"):
        package = f"kernel-debuginfo matching {kernel}"
        where = "the distribution debuginfo repo (e.g. debuginfo.centos.org, vault, or subscription)"
    else:
        package = f"the kernel debug symbols (vmlinux with DWARF) for {kernel or 'this kernel'}"
        where = "the debug-symbols repository of the distribution"

    steps = [
        f"Download the debug package: {package} from {where}.",
        "Extract the unstripped vmlinux: `dpkg-deb -x <pkg>.ddeb out/` → out/usr/lib/debug/boot/vmlinux-*.",
        "Build the ISF with dwarf2json (github.com/volatilityfoundation/dwarf2json): "
        "`dwarf2json linux --elf out/usr/lib/debug/boot/vmlinux-... > isf.json`.",
        "Optionally compress: `xz -9e isf.json`.",
        "Upload isf.json(.xz) in the Symbols page. VolWeb re-verifies it against this banner and, if it matches, unlocks the analysis.",
    ]

    return {
        "banner": banner,
        "kernel": kernel,
        "distro": distro,
        "arch": arch,
        "package": package,
        "where": where,
        "steps": steps,
    }
