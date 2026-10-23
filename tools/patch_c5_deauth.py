#!/usr/bin/env python3
"""Apply the ESP32-C5 deauthentication patch to ESP-IDF's libnet80211.a.

Stock ESP-IDF rejects raw deauthentication frames from esp_wifi_80211_tx()
with ESP_ERR_INVALID_ARG.  The check lives in
ieee80211_raw_frame_sanity_check() inside ieee80211_output.o.  The sanity
check accepts frame control 0xD0 (action) but not 0xC0 (deauth).  This patch
changes one immediate in that function so 0xC0 is accepted as well.

This is a local, unsupported patch.  It is legal only on networks you own or
have explicit permission to test.  Keep the runtime authorization gate.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SECTION = ".text.ieee80211_raw_frame_sanity_check"
STOCK = bytes.fromhex("9306000d")     # li a3, 208 (0xD0)
PATCHED = bytes.fromhex("9306000c")   # li a3, 192 (0xC0)
OBJ = "ieee80211_output.o"


def default_idf() -> Path:
    env = os.environ.get("IDF_PATH")
    if env:
        return Path(env)
    return Path.home() / "esp" / "esp-idf"


def default_lib() -> Path:
    return default_idf() / "components" / "esp_wifi" / "lib" / "esp32c5" / "libnet80211.a"


def c_string(data: bytes, offset: int) -> str:
    end = data.index(0, offset)
    return data[offset:end].decode("ascii", "replace")


def find_section(data: bytes, name: str) -> tuple[int, int]:
    """Return (file_offset, size) for an ELF32 little-endian section."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise SystemExit("not an ELF32 little-endian object")
    e_shoff = struct.unpack_from("<I", data, 0x20)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
    e_shnum = struct.unpack_from("<H", data, 0x30)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]
    if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
        raise SystemExit("object has no section headers")
    shstr = struct.unpack_from("<IIIIII", data, e_shoff + e_shstrndx * e_shentsize)
    shstr_off = shstr[4]
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _flags, _addr, sh_offset, sh_size = struct.unpack_from(
            "<IIIIII", data, off
        )
        if c_string(data, shstr_off + sh_name) == name:
            return sh_offset, sh_size
    raise SystemExit(f"section {name} not found")


def read_archive_object(lib: Path) -> bytes:
    ar = shutil.which("ar") or shutil.which("riscv32-esp-elf-ar")
    if not ar:
        raise SystemExit("ar not found; source the ESP-IDF export script first")
    out = subprocess.run(
        [ar, "p", str(lib), OBJ], check=True, stdout=subprocess.PIPE
    ).stdout
    if not out:
        raise SystemExit(f"{OBJ} not found in {lib}")
    return out


def state(lib: Path) -> tuple[str, int]:
    obj = read_archive_object(lib)
    off, size = find_section(obj, SECTION)
    sec = obj[off:off + size]
    stock = sec.count(STOCK)
    patched = sec.count(PATCHED)
    if stock == 1 and patched == 0:
        return "stock", sec.index(STOCK)
    if patched == 1 and stock == 0:
        return "patched", sec.index(PATCHED)
    return "unknown", -1


def run_ar(args: list[str], cwd: Path | None = None) -> None:
    ar = shutil.which("ar") or shutil.which("riscv32-esp-elf-ar")
    if not ar:
        raise SystemExit("ar not found; source the ESP-IDF export script first")
    subprocess.run([ar, *args], check=True, cwd=cwd)


def run_ranlib(path: Path) -> None:
    ranlib = shutil.which("ranlib") or shutil.which("riscv32-esp-elf-ranlib")
    if not ranlib:
        raise SystemExit("ranlib not found; source the ESP-IDF export script first")
    subprocess.run([ranlib, str(path)], check=True)


def check(lib: Path) -> int:
    st, _ = state(lib)
    label = {
        "stock": "STOCK (deauth frames will be rejected)",
        "patched": "PATCHED (deauth frames accepted)",
        "unknown": "UNKNOWN (unexpected bytes in the sanity-check function)",
    }[st]
    print(f"{lib}: {label}")
    return 0 if st == "patched" else 1


def apply(lib: Path) -> int:
    st, _ = state(lib)
    if st == "patched":
        print(f"{lib}: already patched")
        return 0
    if st != "stock":
        print(f"{lib}: unexpected sanity-check bytes; refusing to patch", file=sys.stderr)
        return 2

    backup = lib.with_name(lib.name + ".stock")
    if not backup.exists():
        shutil.copy2(lib, backup)
        print(f"backup: {backup}")
    else:
        print(f"backup already exists: {backup}")

    with tempfile.TemporaryDirectory(prefix="c5-deauth-") as tmp:
        tmpdir = Path(tmp)
        obj = bytearray(read_archive_object(lib))
        off, size = find_section(obj, SECTION)
        sec = bytes(obj[off:off + size])
        pos = sec.index(STOCK)
        obj[off + pos:off + pos + len(STOCK)] = PATCHED
        obj_path = tmpdir / OBJ
        obj_path.write_bytes(obj)
        run_ar(["r", str(lib), OBJ], cwd=tmpdir)
        run_ranlib(lib)

    st, _ = state(lib)
    if st != "patched":
        print("patch did not verify", file=sys.stderr)
        return 3
    print(f"{lib}: patched")
    print("run `idf.py fullclean && idf.py build` before flashing")
    return 0


def restore(lib: Path) -> int:
    backup = lib.with_name(lib.name + ".stock")
    if not backup.exists():
        print(f"no backup at {backup}; reinstall ESP-IDF or restore manually", file=sys.stderr)
        return 2
    shutil.copy2(backup, lib)
    print(f"{lib}: restored from {backup}")
    print("run `idf.py fullclean && idf.py build` before flashing")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, default=default_lib(),
                        help=f"libnet80211.a path (default: {default_lib()})")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="report patch state")
    group.add_argument("--apply", action="store_true", help="apply the patch")
    group.add_argument("--restore", action="store_true", help="restore the stock library")
    args = parser.parse_args()
    lib = args.lib.expanduser().resolve()
    if not lib.exists():
        print(f"not found: {lib}", file=sys.stderr)
        return 2
    if args.apply:
        return apply(lib)
    if args.restore:
        return restore(lib)
    return check(lib)


if __name__ == "__main__":
    raise SystemExit(main())
