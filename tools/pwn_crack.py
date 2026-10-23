#!/usr/bin/env python3
"""PWNI PCAP cracker — device-aware GUI and CLI.

The tool finds the ESP32-C5 on the LAN, reads the handshake list and saved
PCAPs from the web API, downloads selected captures, and runs aircrack-ng
against a wordlist.

Examples:
    python3 tools/pwn_crack.py --watch
    python3 tools/pwn_crack.py --ip <device-ip>
    python3 tools/pwn_crack.py --list
    python3 tools/pwn_crack.py --crack /tmp/hs.pcap --bssid AA:BB:CC:DD:EE:FF \
        --wordlist /tmp/words.txt

Only use captures from networks you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except Exception:  # pragma: no cover - CLI still works without Tk
    tk = None

ROOT = Path(__file__).resolve().parent
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "pwni-crack" / "pcaps"
CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "pwni-crack.json"
COMMON_WORDLIST = ROOT / "wordlists" / "common.txt"
KNOWN_IPS: list[str] = []
USB_HINTS = ["/dev/ttyACM0", "/dev/ttyACM1"]

SECLIST_FILES = (
    "Passwords/Leaked-Databases/rockyou.txt",
    "Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
    "Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    "Passwords/Common-Credentials/10k-most-common.txt",
)


def find_wordlists() -> list[Path]:
    """Prefer rockyou, then SecLists, then the small bundled common list."""
    candidates: list[Path] = []
    for p in (
        ROOT / "wordlists" / "rockyou.txt",
        Path.home() / "rockyou.txt",
        Path.home() / "Downloads" / "rockyou.txt",
        Path("/usr/share/wordlists/rockyou.txt"),
    ):
        if p.is_file() and p.stat().st_size > 0:
            candidates.append(p)

    for base in (
        ROOT / "wordlists",
        ROOT / "wordlists" / "SecLists",
        Path.home() / "SecLists",
        Path.home() / "seclists",
        Path("/usr/share/seclists"),
        Path("/usr/share/SecLists"),
    ):
        for rel in SECLIST_FILES:
            p = base / rel
            if p.is_file() and p.stat().st_size > 0:
                candidates.append(p)

    if COMMON_WORDLIST.is_file() and COMMON_WORDLIST.stat().st_size > 0:
        candidates.append(COMMON_WORDLIST)

    seen: set[str] = set()
    out: list[Path] = []
    for p in candidates:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def default_wordlist() -> Path:
    lists = find_wordlists()
    return lists[0] if lists else COMMON_WORDLIST


# ---------------------------------------------------------------------------
# Device discovery / API
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except Exception:
        return {}


def _save_config(cfg: dict) -> None:
    try:
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps(cfg, indent=2))
    except Exception:
        pass


def api_json(ip: str, path: str, timeout: float = 2.0) -> dict:
    url = f"http://{ip}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "pwni-crack/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data.decode("utf-8", "replace"))


def probe(ip: str, timeout: float = 1.5) -> bool:
    try:
        st = api_json(ip, "/api/status", timeout)
        return bool(st.get("fw") or st.get("build", {}).get("version"))
    except Exception:
        return False


def _local_networks() -> list[ipaddress.IPv4Network]:
    """Return /24 networks around local IPv4 addresses, excluding virtual links."""
    nets: list[ipaddress.IPv4Network] = []
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "up"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except Exception:
        return nets
    for line in out.splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        addr = ipaddress.ip_address(m.group(1))
        if addr.is_loopback or addr.is_link_local:
            continue
        if str(addr).startswith("100.") or str(addr).startswith("172.17."):
            continue
        if line.split()[1] in ("docker0", "br-", "tailscale0"):
            continue
        try:
            net = ipaddress.ip_network(f"{addr}/24", strict=False)
        except Exception:
            continue
        if net not in nets:
            nets.append(net)
    return nets


def discover(initial: str | None = None, scan: bool = True) -> str | None:
    cfg = _load_config()
    candidates: list[str] = []
    for ip in [initial, cfg.get("ip"), *KNOWN_IPS]:
        if ip and ip not in candidates:
            candidates.append(ip)
    for ip in candidates:
        if probe(ip):
            cfg["ip"] = ip
            _save_config(cfg)
            return ip
    if not scan:
        return None

    for net in _local_networks():
        # probe a /24 around each local address
        hosts = [str(h) for h in net.hosts()]
        with ThreadPoolExecutor(max_workers=64) as ex:
            futs = {ex.submit(probe, h): h for h in hosts}
            for fut in as_completed(futs):
                try:
                    if fut.result():
                        ip = futs[fut]
                        cfg["ip"] = ip
                        _save_config(cfg)
                        return ip
                except Exception:
                    pass
    return None


def fetch_device(ip: str) -> tuple[dict, dict]:
    return api_json(ip, "/api/status"), api_json(ip, "/api/hs")


def download_pcap(ip: str, name: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    safe = Path(name).name
    dest = CACHE / safe
    url = f"http://{ip}/api/pcap?name={urllib.parse.quote(name, safe='')}"
    req = urllib.request.Request(url, headers={"User-Agent": "pwni-crack/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        data = r.read()
    if not data:
        raise RuntimeError("empty PCAP response")
    if data[:1] == b"<":
        raise RuntimeError("server returned HTML instead of a PCAP")
    dest.write_bytes(data)
    return dest


def file_bssid(name: str) -> str:
    m = re.search(r"_([0-9a-fA-F]{12})\.pcap$", name)
    if not m:
        return ""
    h = m.group(1).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def file_ssid(name: str) -> str:
    m = re.match(r"(.+)_[0-9a-fA-F]{12}\.pcap$", name)
    return m.group(1) if m else ""


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def clean_line(text: str) -> str:
    return ANSI_RE.sub("", text).replace("\r", "")


# ---------------------------------------------------------------------------
# aircrack-ng
# ---------------------------------------------------------------------------

def aircrack(pcap: Path, bssid: str, wordlist: Path,
             essid: str = "", on_line=None) -> tuple[bool, str, str]:
    """Run aircrack-ng. Returns (found, key, full_output)."""
    exe = shutil.which("aircrack-ng")
    if not exe:
        raise RuntimeError("aircrack-ng is not installed (apt install aircrack-ng)")
    if not pcap.exists():
        raise RuntimeError(f"PCAP not found: {pcap}")
    if not wordlist.exists():
        raise RuntimeError(f"wordlist not found: {wordlist}")

    cmd = [exe, "-w", str(wordlist)]
    if bssid:
        cmd += ["-b", bssid]
    if essid:
        cmd += ["-e", essid]
    cmd.append(str(pcap))
    use_auto_target = not bssid

    lines: list[str] = []
    key = ""
    found = False
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if use_auto_target else subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    if use_auto_target and proc.stdin:
        try:
            proc.stdin.write("1\n")
            proc.stdin.flush()
            proc.stdin.close()
        except Exception:
            pass
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = clean_line(raw).strip("\r\n")
        lines.append(line)
        if on_line:
            on_line(line)
        m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", line)
        if m:
            found = True
            key = m.group(1)
    proc.wait()
    return found, key, "\n".join(lines)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App:
    def __init__(self, initial_ip: str | None = None, watch: bool = False, scan: bool = True):
        if tk is None:
            raise RuntimeError("tkinter is not available")
        self.root = tk.Tk()
        self.root.title("PWNI PCAP Cracker")
        self.root.geometry("1040x680")
        self.root.minsize(820, 520)
        self.watch = watch
        self.scan = scan
        self.initial_ip = initial_ip
        self.device_ip: str | None = None
        self.status: dict = {}
        self.hs: dict = {}
        self.rows: list[dict] = []
        self.local_paths: list[Path] = []
        self.msgq: queue.Queue = queue.Queue()
        self.busy = False

        self.dev_var = tk.StringVar(value="searching for PWNI...")
        self.sd_var = tk.StringVar(value="SD: --")
        self.result_var = tk.StringVar(value="No key yet.")
        self.wordlists = find_wordlists()
        self.wordlist_var = tk.StringVar(
            value=str(self.wordlists[0]) if self.wordlists else ""
        )
        self.ip_var = tk.StringVar(
            value=initial_ip or str(_load_config().get("ip", ""))
        )
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._drain)
        if watch:
            self.root.withdraw()
            threading.Thread(target=self._watch_loop, daemon=True).start()
        else:
            self._connect_async()

    # -- layout ----------------------------------------------------------
    def _build(self) -> None:
        pad = {"padx": 8, "pady": 4}
        top = ttk.Frame(self.root)
        top.pack(fill="x", **pad)
        ttk.Label(top, text="PWNI", font=("TkDefaultFont", 16, "bold")).pack(side="left")
        ttk.Label(top, textvariable=self.dev_var).pack(side="left", padx=12)
        ttk.Label(top, textvariable=self.sd_var).pack(side="left", padx=12)
        ttk.Button(top, text="Refresh", command=self._connect_async).pack(side="right", padx=2)
        ttk.Button(top, text="Open cache", command=self._open_cache).pack(side="right", padx=2)
        ttk.Button(top, text="Connect", command=self._connect_ip).pack(side="right", padx=2)
        ttk.Entry(top, textvariable=self.ip_var, width=15).pack(side="right", padx=2)
        ttk.Label(top, text="IP").pack(side="right")

        cols = ("kind", "ssid", "bssid", "state", "file", "size", "pmkid")
        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=12)
        heads = {
            "kind": ("Type", 90), "ssid": ("SSID", 160), "bssid": ("BSSID", 140),
            "state": ("State", 110), "file": ("File", 260), "size": ("Size", 80),
            "pmkid": ("PMKID", 60),
        }
        for c in cols:
            text, width = heads[c]
            self.tree.heading(c, text=text)
            self.tree.column(c, width=width, anchor="w")
        vs = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self._crack_selected())

        actions = ttk.Frame(self.root)
        actions.pack(fill="x", **pad)
        self.crack_btn = ttk.Button(actions, text="Crack selected", command=self._crack_selected)
        self.crack_btn.pack(side="left", padx=2)
        ttk.Button(actions, text="Download PCAP", command=self._download_selected).pack(side="left", padx=2)
        ttk.Button(actions, text="Add local PCAP...", command=self._add_local).pack(side="left", padx=2)
        ttk.Button(actions, text="Test SD", command=self._test_sd).pack(side="left", padx=2)

        wl = ttk.Frame(self.root)
        wl.pack(fill="x", **pad)
        ttk.Label(wl, text="Wordlist:").pack(side="left")
        self.wordlist_combo = ttk.Combobox(
            wl, textvariable=self.wordlist_var,
            values=[str(p) for p in self.wordlists], width=72,
        )
        self.wordlist_combo.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(wl, text="Browse...", command=self._browse_wordlist).pack(side="left")
        ttk.Button(wl, text="Rescan", command=self._refresh_wordlists).pack(side="left", padx=4)
        ttk.Button(wl, text="Copy key", command=self._copy_key).pack(side="left", padx=4)

        res = ttk.Frame(self.root)
        res.pack(fill="x", **pad)
        ttk.Label(res, textvariable=self.result_var, foreground="#1a7f37",
                  font=("TkDefaultFont", 11, "bold")).pack(side="left")

        self.logbox = scrolledtext.ScrolledText(self.root, height=14, wrap="none")
        self.logbox.pack(fill="both", expand=True, **pad)
        self.logbox.configure(state="disabled")

    # -- helpers ---------------------------------------------------------
    def _log(self, text: str) -> None:
        self.logbox.configure(state="normal")
        self.logbox.insert("end", text + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _drain(self) -> None:
        try:
            while True:
                kind, payload = self.msgq.get_nowait()
                if kind == "log":
                    self._log(str(payload))
                elif kind == "device":
                    self._on_device(payload)
                elif kind == "status":
                    self.dev_var.set(str(payload))
                elif kind == "result":
                    self.result_var.set(str(payload))
                elif kind == "busy":
                    self.busy = bool(payload)
                    self.crack_btn.configure(state="disabled" if self.busy else "normal")
                elif kind == "show":
                    self._show()
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _connect_async(self) -> None:
        self.dev_var.set("searching for PWNI...")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _connect_ip(self) -> None:
        ip = self.ip_var.get().strip()
        if not ip:
            return
        self.initial_ip = ip
        self._connect_async()

    def _connect_worker(self) -> None:
        ip = discover(self.initial_ip or self.device_ip, self.scan)
        if not ip:
            self.msgq.put(("status", "device not found (USB detected)" if self._usb_present() else "device not found"))
            return
        try:
            st, hs = fetch_device(ip)
        except Exception as exc:
            self.msgq.put(("status", f"found {ip}, API error: {exc}"))
            return
        self.msgq.put(("device", (ip, st, hs)))

    @staticmethod
    def _usb_present() -> bool:
        return any(Path(p).exists() for p in USB_HINTS)

    def _watch_loop(self) -> None:
        while True:
            ip = discover(self.initial_ip or self.device_ip, self.scan)
            if ip:
                try:
                    st, hs = fetch_device(ip)
                    self.msgq.put(("device", (ip, st, hs)))
                    # keep polling for IP changes but do not repopulate every 3 s
                    while discover(ip, False) == ip:
                        time.sleep(3)
                except Exception:
                    pass
                self.device_ip = None
                self.msgq.put(("status", "device disconnected; waiting..."))
            else:
                if self._usb_present():
                    self.msgq.put(("status", "USB detected; waiting for web IP..."))
                    self.msgq.put(("show", None))
                else:
                    self.msgq.put(("status", "waiting for PWNI device..."))
            time.sleep(3)

    def _show(self) -> None:
        self.root.deiconify()
        self.root.lift()

    def _on_device(self, payload) -> None:
        ip, st, hs = payload
        self.device_ip = ip
        self.status, self.hs = st, hs
        self.ip_var.set(ip)
        ssid = st.get("ssid") or "-"
        sd = "ready" if st.get("sd") else "NOT MOUNTED"
        self.dev_var.set(f"{ip}  {ssid}  ch {st.get('channel', '?')}  {'unlocked' if st.get('authorized') else 'locked'}")
        self.sd_var.set(f"SD: {sd}  files: {len(hs.get('files', []))}")
        if not st.get("sd"):
            self.msgq.put(("log", "WARNING: device reports SD not mounted. Live handshakes stay in RAM; saved PCAPs may be unavailable."))
        self._populate()
        self.root.after(0, self._show)

    def _populate(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.rows = []
        hs = self.hs.get("hs", [])
        files = self.hs.get("files", [])
        by_file = {h.get("file"): h for h in hs if h.get("file")}

        # Live/saved handshake slots first; complete before partial.
        seen_files: set[str] = set()
        for h in sorted(hs, key=lambda x: (not x.get("complete"), not x.get("saved"))):
            file = h.get("file") or ""
            if file and file in seen_files:
                continue
            if file:
                seen_files.add(file)
            kind = "handshake" if file else "live"
            state = "saved" if h.get("saved") else ("complete (RAM)" if h.get("complete") else "partial (RAM)")
            size = ""
            if file:
                for f in files:
                    if f.get("name") == file:
                        size = _fmt_size(f.get("size", 0))
                        break
            self._add_row(kind, h.get("ssid") or "", h.get("bssid") or "",
                          state, file, size, "yes" if h.get("pmkid") else "")

        for f in files:
            name = f.get("name", "")
            if name in by_file:
                continue
            self._add_row("saved", file_ssid(name), file_bssid(name), "saved", name,
                          _fmt_size(f.get("size", 0)), "")

        for path in self.local_paths:
            self._add_row("local", "", file_bssid(path.name), "local", str(path),
                          _fmt_size(path.stat().st_size if path.exists() else 0), "")

    def _add_row(self, kind, ssid, bssid, state, file, size, pmkid) -> None:
        iid = str(len(self.rows))
        self.rows.append({
            "kind": kind, "ssid": ssid, "bssid": bssid, "state": state,
            "file": file, "size": size, "pmkid": pmkid,
        })
        self.tree.insert("", "end", iid=iid, values=(kind, ssid, bssid, state, file, size, pmkid))

    def _selected(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("PWNI", "Select a handshake or saved PCAP first.")
            return None
        return self.rows[int(sel[0])]

    def _download_selected(self) -> None:
        row = self._selected()
        if not row:
            return
        if row["kind"] == "local":
            messagebox.showinfo("PWNI", row["file"])
            return
        if not row["file"]:
            messagebox.showinfo("PWNI", "This handshake is RAM-only (SD not saved). Wait for a complete handshake or fix the SD card.")
            return
        if row["kind"] == "live":
            messagebox.showinfo("PWNI", "This capture has no saved PCAP file yet.")
            return
        try:
            path = download_pcap(self.device_ip, row["file"])
            self._log(f"downloaded {path} ({_fmt_size(path.stat().st_size)})")
        except Exception as exc:
            messagebox.showerror("PWNI", str(exc))

    def _crack_selected(self) -> None:
        if self.busy:
            return
        row = self._selected()
        if not row:
            return
        wl = Path(self.wordlist_var.get().strip())
        if not wl.exists():
            messagebox.showerror("PWNI", f"Wordlist not found:\n{wl}\nChoose a wordlist (rockyou.txt or similar).")
            return
        if row["kind"] in ("live", "handshake") and not row["file"]:
            messagebox.showerror("PWNI", "This handshake has no saved PCAP. It is RAM-only; wait for the device to save a complete handshake.")
            return
        if row["kind"] == "local":
            pcap = Path(row["file"])
        else:
            try:
                pcap = download_pcap(self.device_ip, row["file"])
            except Exception as exc:
                messagebox.showerror("PWNI", f"download failed: {exc}")
                return
        bssid = row["bssid"]
        essid = row["ssid"]
        self.msgq.put(("busy", True))
        self.msgq.put(("result", "Cracking..."))
        self.msgq.put(("log", f"aircrack-ng {'-b '+bssid if bssid else '(auto target)'} "
                              f"{'-e '+essid if essid else ''} -w {wl} {pcap}"))
        threading.Thread(target=self._crack_worker, args=(pcap, bssid, essid, wl), daemon=True).start()

    def _crack_worker(self, pcap: Path, bssid: str, essid: str, wordlist: Path) -> None:
        try:
            found, key, output = aircrack(
                pcap, bssid, wordlist, essid,
                on_line=lambda line: self.msgq.put(("log", line)),
            )
            if found:
                self.msgq.put(("result", f"KEY FOUND: {key}"))
                self.msgq.put(("log", f"KEY FOUND! [{key}]"))
            else:
                self.msgq.put(("result", "No key found with this wordlist."))
                self.msgq.put(("log", "No key found with this wordlist."))
        except Exception as exc:
            self.msgq.put(("log", f"ERROR: {exc}"))
            self.msgq.put(("result", f"ERROR: {exc}"))
        finally:
            self.msgq.put(("busy", False))

    def _add_local(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Add local PCAP(s)",
            filetypes=[("PCAP", "*.pcap *.pcapng *.cap"), ("All files", "*")],
        )
        for p in paths:
            path = Path(p)
            if path not in self.local_paths:
                self.local_paths.append(path)
        self._populate()

    def _browse_wordlist(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose wordlist",
            filetypes=[("Text", "*.txt *.lst"), ("All files", "*")],
        )
        if path:
            self.wordlist_var.set(path)

    def _refresh_wordlists(self) -> None:
        self.wordlists = find_wordlists()
        self.wordlist_combo.configure(values=[str(p) for p in self.wordlists])
        if self.wordlists:
            self.wordlist_var.set(str(self.wordlists[0]))
        self._log("wordlists: " + ", ".join(str(p) for p in self.wordlists))

    def _copy_key(self) -> None:
        text = self.result_var.get()
        m = re.search(r"KEY FOUND:\s*(.+)", text)
        if not m:
            messagebox.showinfo("PWNI", "No key to copy yet.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(m.group(1))
        self._log("key copied to clipboard")

    def _open_cache(self) -> None:
        CACHE.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["xdg-open", str(CACHE)])

    def _test_sd(self) -> None:
        if not self.device_ip:
            messagebox.showinfo("PWNI", "No device connected.")
            return
        try:
            st, hs = fetch_device(self.device_ip)
            files = hs.get("files", [])
            if not st.get("sd"):
                messagebox.showerror("PWNI", "Device reports SD not mounted. Check the card and reboot.")
                return
            if not files:
                messagebox.showinfo("PWNI", "SD is mounted but no PCAPs found yet.")
                return
            newest = max(files, key=lambda f: f.get("size", 0))
            path = download_pcap(self.device_ip, newest["name"])
            name = path.name
            magic = path.read_bytes()[:4]
            ok = magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                           b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            self._log(f"SD test: sd={st.get('sd')} files={len(files)} "
                      f"downloaded={name} bytes={path.stat().st_size} pcap={ok}")
            messagebox.showinfo("PWNI", f"SD read OK\n{len(files)} PCAP(s)\nDownloaded {name} ({path.stat().st_size} bytes)")
        except Exception as exc:
            messagebox.showerror("PWNI", f"SD test failed: {exc}")

    def _close(self) -> None:
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def _fmt_size(n: int | float) -> str:
    n = int(n or 0)
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n} B"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list(ip: str | None, scan: bool) -> int:
    found = discover(ip, scan)
    if not found:
        print("device not found", file=sys.stderr)
        return 2
    st, hs = fetch_device(found)
    print(f"device   http://{found}/  {st.get('ssid', '-')}  "
          f"ch {st.get('channel', '?')}  sd={'ready' if st.get('sd') else 'MISSING'}")
    print(f"handshakes: {len(hs.get('hs', []))}  files: {len(hs.get('files', []))}")
    seen_files: set[str] = set()
    for h in hs.get("hs", []):
        f = h.get("file") or ""
        if f and f in seen_files:
            continue
        if f:
            seen_files.add(f)
        state = "complete" if h.get("complete") else "partial"
        print(f"  {state:8} {h.get('ssid',''):24} {h.get('bssid','')} "
              f"{'PMKID' if h.get('pmkid') else ''} {f or '(RAM)'}")
    for f in hs.get("files", []):
        print(f"  file     {f.get('name')}  {_fmt_size(f.get('size', 0))}")
    return 0


def cmd_crack(pcap: str, bssid: str, essid: str, wordlist: str) -> int:
    found, key, output = aircrack(Path(pcap), bssid, Path(wordlist), essid,
                                  on_line=lambda line: print(line, flush=True))
    if found:
        print(f"\nKEY FOUND: {key}")
        return 0
    print("\nNo key found.")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ip", help="initial device IP")
    ap.add_argument("--watch", action="store_true",
                    help="stay hidden and open when the device appears")
    ap.add_argument("--no-watch", action="store_true", help="show the GUI immediately")
    ap.add_argument("--no-scan", action="store_true", help="do not scan the LAN")
    ap.add_argument("--list", action="store_true", help="print device handshakes and exit")
    ap.add_argument("--wordlists", action="store_true", help="print discovered wordlists and exit")
    ap.add_argument("--crack", metavar="PCAP", help="crack a local PCAP and exit")
    ap.add_argument("--bssid", default="", help="BSSID for --crack")
    ap.add_argument("--essid", default="", help="ESSID for --crack (PCAPs from the device have no beacons)")
    ap.add_argument("--wordlist", default=None,
                    help="wordlist for --crack (default: best discovered, preferably rockyou)")
    args = ap.parse_args(argv)

    if args.list:
        return cmd_list(args.ip, not args.no_scan)
    if args.wordlists:
        for p in find_wordlists():
            print(p)
        return 0
    if args.crack:
        wordlist = args.wordlist or str(default_wordlist())
        return cmd_crack(args.crack, args.bssid, args.essid, wordlist)

    if tk is None:
        print("tkinter is not available; use --list or --crack", file=sys.stderr)
        return 2
    watch = args.watch and not args.no_watch
    try:
        app = App(initial_ip=args.ip, watch=watch, scan=not args.no_scan)
        app.run()
    except Exception as exc:
        print(f"GUI error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
