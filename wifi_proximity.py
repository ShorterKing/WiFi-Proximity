#!/usr/bin/env python3
"""
wifi_proximity.py -- Passive Wi-Fi station proximity + recon tool.

Watches client devices ("stations") on the air using a monitor-mode Wi-Fi
adapter, ranks them by signal strength (RSSI) so the physically closest device
floats to the top of a live list, and enriches each one with as much info as
can be gathered from what is already on the air (and, optionally, from your own
host's view of the network).

This tool is PASSIVE by default. It only listens. It never transmits deauth
frames, never injects packets, and never attempts to crack keys. Use it only on
networks and devices you own or are explicitly authorized to test.

Hard dependency:  scapy        (pip install scapy)   -- packet capture/parse
Optional:         rich         (pip install rich)    -- prettier live UI
                                                         (falls back to a plain
                                                          ANSI renderer if absent)

Run  python3 wifi_proximity.py --help   for usage.
Run  python3 wifi_proximity.py --selftest   to validate the pure logic with no
hardware and no dependencies installed.
"""

import argparse
import csv
import json
import os
import re
import signal
import subprocess
import sys
import math
import statistics
import threading

__version__ = "2026.09.08-reactive"  # signal-first ranking + fast reaction
import time
from collections import deque
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# scapy and rich are imported LAZILY (inside the functions that need them) so
# that --help, --selftest, and all the pure logic below work even when those
# packages are not installed.
# ---------------------------------------------------------------------------


# ===========================================================================
# Pure helpers (no scapy / rich needed -- these are what --selftest exercises)
# ===========================================================================

# Common OUI prefixes so *something* useful shows even with no OUI file/scapy.
# (First 3 MAC octets, upper-hex, no separators -> vendor.)
_BUILTIN_OUI = {
    "FCFBFB": "Cisco", "000C29": "VMware", "005056": "VMware",
    "001C42": "Parallels", "080027": "VirtualBox", "0050F2": "Microsoft",
    "3C5AB4": "Google", "A47733": "Google", "F4F5D8": "Google",
    "DCA632": "RaspberryPi", "B827EB": "RaspberryPi", "E45F01": "RaspberryPi",
    "D83ADD": "RaspberryPi", "2CCF67": "RaspberryPi",
    "F0D1A9": "Apple", "3C0754": "Apple", "A85C2C": "Apple", "AC87A3": "Apple",
    "F0189E": "Apple", "D0817A": "Apple", "8866A5": "Apple", "BCD074": "Apple",
    "001A11": "Google", "94EB2C": "Samsung", "5CF7E6": "Samsung",
    "F8E61A": "Samsung", "347E5C": "Sonos", "B8E937": "Sonos",
    "D052A8": "Roku", "CC6DA0": "Roku", "B0A737": "Roku",
    "18B430": "Nest", "641666": "Nest", "44650D": "Amazon",
    "FCA183": "Amazon", "68370E": "Amazon", "0C47C9": "Amazon",
    "EC1BBD": "AzureWave", "60A4B7": "Intel", "8C1645": "Intel",
    "A0C589": "Intel", "9CB6D0": "Intel", "34415D": "Intel",
    "TPLINK": "TP-Link",  # placeholder guard, never matched (6-hex keys only)
}


def normalize_mac(mac):
    """Lower-case colon-separated MAC, or None if it doesn't look like one."""
    if not mac:
        return None
    m = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(m) != 12:
        return None
    m = m.lower()
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def valid_ipv4(ip):
    """Reject junk/implausible IPs so a misparse can't inject a bogus address."""
    if not ip or not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if any(x < 0 or x > 255 for x in o):
        return False
    if o[0] == 0 or o[0] >= 224:            # "this network" / multicast / reserved
        return False
    if ip == "255.255.255.255":
        return False
    return True


def mac_is_multicast(mac):
    """True for broadcast/multicast MACs (least-significant bit of 1st octet)."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    try:
        return bool(int(mac[0:2], 16) & 0x01)
    except ValueError:
        return False


def mac_is_locally_administered(mac):
    """True if the U/L bit is set -- i.e. a randomized/private MAC."""
    mac = normalize_mac(mac)
    if not mac:
        return False
    try:
        return bool(int(mac[0:2], 16) & 0x02)
    except ValueError:
        return False


def oui_key(mac):
    """First 3 octets as upper hex, no separators (e.g. 'B827EB'). None if bad."""
    mac = normalize_mac(mac)
    if not mac:
        return None
    return mac.replace(":", "")[:6].upper()


def freq_to_channel(freq_mhz):
    """Convert a Wi-Fi center frequency (MHz) to a channel number. None if N/A."""
    if not freq_mhz:
        return None
    f = int(freq_mhz)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2412) // 5 + 1
    if 5160 <= f <= 5885:            # 5 GHz
        return (f - 5000) // 5
    if 5955 <= f <= 7115:            # 6 GHz (Wi-Fi 6E)
        return (f - 5950) // 5
    return None


def channel_to_freq(ch):
    """Channel number -> centre frequency in MHz (2.4 / 5 / 6 GHz)."""
    if ch is None:
        return None
    ch = int(ch)
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    if 32 <= ch <= 196:
        return 5000 + 5 * ch
    return None


def width_iw_args(iface, ch, width=None, center_ch=None, ht_offset=None):
    """
    Build the `iw` argument list to tune to a channel AT THE RIGHT WIDTH.

    This matters enormously: `iw set channel N` gives a 20 MHz no-HT capture,
    which decodes beacons but NOT the 40/80/160 MHz HT/VHT data frames modern
    APs actually carry traffic on. Getting the width right is the difference
    between seeing only beacons and seeing real client traffic.
    """
    freq = channel_to_freq(ch)
    if freq is None:
        return None
    if width in (80, 160) and center_ch:
        cfreq = channel_to_freq(center_ch)
        if cfreq:
            return ["iw", "dev", iface, "set", "freq", str(freq),
                    str(width), str(cfreq)]
    if width == 40 and ht_offset in ("+", "-"):
        return ["iw", "dev", iface, "set", "channel", str(ch),
                "HT40" + ht_offset]
    return ["iw", "dev", iface, "set", "channel", str(ch)]


_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values, width=12):
    """Unicode sparkline from a list of numbers (higher value -> taller bar)."""
    vals = [v for v in values if v is not None]
    if not vals:
        return " " * width
    vals = vals[-width:]
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    out = []
    for v in vals:
        idx = int(round((v - lo) / span * (len(_SPARK_CHARS) - 1)))
        out.append(_SPARK_CHARS[idx])
    return "".join(out).rjust(width)


def frame_is_protected(fc):
    """True if the 802.11 Protected/WEP flag is set (payload is encrypted)."""
    try:
        return bool(int(fc) & 0x40)
    except Exception:
        return False


def infer_association(to_ds, from_ds, a1, a2, a3, is_known_bssid=None):
    """
    Work out, for a data frame, which address is the AP (BSSID) and which is the
    client station.

    Standard 802.11 addressing:
      to-DS=1, from-DS=0  (station -> AP):  a1=BSSID, a2=station,  a3=dest
      to-DS=0, from-DS=1  (AP -> station):  a1=station, a2=BSSID,  a3=source
      to-DS=0, from-DS=0  (IBSS/ad-hoc):    a3=BSSID
      both set            (WDS/mesh):       a1=receiver

    The DS bits can be unreliable to read, so when we already know a BSSID from
    a beacon we use that to verify/repair the guess. Returns
    (bssid, station_mac, transmitter_is_ap).
    """
    if to_ds and not from_ds:
        bssid = a1
    elif from_ds and not to_ds:
        bssid = a2
    elif not to_ds and not from_ds:
        bssid = a3
    else:
        bssid = a1

    # Verify against BSSIDs learned from beacons; repair if it doesn't match.
    if is_known_bssid is not None:
        if not (bssid and is_known_bssid(bssid)):
            for cand in (a1, a2, a3):
                if cand and is_known_bssid(cand):
                    bssid = cand
                    break

    nb = normalize_mac(bssid) if bssid else None
    station = None
    if nb:
        if a2 and normalize_mac(a2) != nb:
            station = a2
        elif a1 and normalize_mac(a1) != nb:
            station = a1
    transmitter_is_ap = bool(nb and a2 and normalize_mac(a2) == nb)
    return bssid, station, transmitter_is_ap


def _percentile(values, pct):
    """Linear-interpolated percentile of a list (pct in 0..100). None if empty."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return float(vals[0])
    k = (len(vals) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    frac = k - lo
    return vals[lo] * (1 - frac) + vals[hi] * frac


def estimate_distance_m(rssi, tx_power=-40, path_loss_n=2.5):
    """
    Very rough free-space-ish distance estimate from RSSI (dBm).
    tx_power = expected RSSI at 1 m. This is NOISY -- treat as an order of
    magnitude only. Returns metres (float) or None.
    """
    if rssi is None:
        return None
    try:
        return round(10 ** ((tx_power - rssi) / (10.0 * path_loss_n)), 1)
    except Exception:
        return None


def parse_ip_neigh(text):
    """
    Parse `ip neigh` output into {mac: ip}. Lines look like:
      192.168.1.20 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    Skips entries with no lladdr or in FAILED/INCOMPLETE state.
    """
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or "lladdr" not in parts:
            continue
        ip = parts[0]
        try:
            mac = normalize_mac(parts[parts.index("lladdr") + 1])
        except (ValueError, IndexError):
            continue
        state = parts[-1].upper()
        if mac and state not in ("FAILED", "INCOMPLETE"):
            out[mac] = ip
    return out


def parse_arp_a(text):
    """Parse BSD/macOS/Linux `arp -a` output into {mac: ip}."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?.*?"
                      r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", line)
        if m:
            mac = normalize_mac(m.group(2))
            if mac:
                out[mac] = m.group(1)
    return out


class OuiResolver:
    """
    Resolve a MAC to a vendor. Tries, in order:
      1. an OUI/manuf file the user supplied (--oui-file),
      2. scapy's bundled manufacturer DB (only when scapy is loaded),
      3. a small built-in table of common vendors.
    """

    def __init__(self):
        self._file_map = {}
        self._scapy_db = None
        self._cache = {}

    def load_file(self, path):
        """
        Parse a Wireshark 'manuf' file or an IEEE 'oui.txt'. Returns count loaded.
        manuf:   00:00:0C   Cisco            (also supports  /36 masks, we take /24)
        oui.txt: 00-00-0C   (hex)  CISCO SYSTEMS, INC.
        """
        n = 0
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # find a MAC-prefix-looking token at the start
                m = re.match(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]"
                             r"[0-9a-fA-F]{2})", line)
                if not m:
                    continue
                key = oui_key(m.group(1) + ":00:00:00")
                rest = line[m.end():]
                rest = re.sub(r"^\s*/\d+", "", rest)          # drop /36 mask
                rest = re.sub(r"\(hex\)", "", rest, flags=re.I)
                vendor = rest.strip().split("\t")[0].strip()
                vendor = re.split(r"\s{2,}", vendor)[0].strip()
                if key and vendor:
                    self._file_map[key] = vendor
                    n += 1
        return n

    def attach_scapy(self, scapy_conf):
        self._scapy_db = scapy_conf

    def lookup(self, mac):
        if mac_is_locally_administered(mac):
            return "(randomized MAC)"
        key = oui_key(mac)
        if not key:
            return "?"
        if key in self._cache:
            return self._cache[key]
        vendor = self._file_map.get(key)
        if not vendor and self._scapy_db is not None:
            try:
                v = self._scapy_db.manufdb._get_manuf(mac)
                if v and v not in ("UnknownVendor", mac):
                    vendor = v
            except Exception:
                pass
        if not vendor:
            vendor = _BUILTIN_OUI.get(key)
        vendor = vendor or "?"
        self._cache[key] = vendor
        return vendor


# ===========================================================================
# Station model + thread-safe tracker
# ===========================================================================

class Station:
    """One tracked transmitter (client station, or an AP if --show-aps)."""

    __slots__ = ("mac", "ema_rssi", "last_rssi", "recent", "samples",
                 "first_seen", "last_seen", "packets", "channels", "bssid",
                 "ssids", "is_ap", "vendor", "ip", "hostname", "fingerprint",
                 "network",
                 # --- richer passive enrichment (open-network freebies) ---
                 "os_hint", "model", "services", "dhcp_fp", "nbios",
                 "domains", "user_agent",
                 # --- radio params learned from beacons (HT/VHT operation) ---
                 "width", "center_ch", "ht_offset", "security", "lock")

    def __init__(self, mac, ema_alpha_placeholder=None, lock=None):
        # Shared with the Tracker so the capture thread (writing samples) and
        # the UI thread (reading them) can never touch the deque at once.
        self.lock = lock or threading.RLock()
        self.mac = mac
        self.ema_rssi = None
        self.last_rssi = None
        self.recent = deque(maxlen=40)
        self.samples = deque(maxlen=600)   # (timestamp, rssi) for robust stats
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.packets = 0
        self.channels = set()
        self.bssid = None
        self.ssids = set()          # probed / associated SSIDs
        self.is_ap = False
        self.vendor = None
        self.ip = None
        self.hostname = None
        self.fingerprint = None     # e.g. OS/device hint
        self.network = None         # SSID string for display
        self.os_hint = None         # DHCP vendor-class / SSDP server / WPS mfr
        self.model = None           # mDNS TXT model / WPS model / SSDP device
        self.services = set()       # mDNS/SSDP service types (airplay, cast…)
        self.dhcp_fp = None         # DHCP option-55 parameter-request signature
        self.nbios = None           # NetBIOS (Windows) name
        self.domains = set()        # DNS queries + TLS SNI (who it talks to)
        self.user_agent = None      # plaintext HTTP User-Agent
        self.width = None           # 20/40/80/160 MHz (APs, from beacon IEs)
        self.center_ch = None       # VHT center channel
        self.ht_offset = None       # '+' or '-' for HT40
        self.security = None        # OPEN / OWE / WPA2 / WPA3 … (APs)

    def best_device(self):
        """One short human label for the DEVICE column."""
        if self.model:
            return self.model
        if self.os_hint:
            return self.os_hint
        if self.services:
            return "+".join(sorted(self.services)[:2])
        if self.nbios:
            return self.nbios
        return ""

    def update_rssi(self, rssi, alpha):
        if rssi is None:
            return
        with self.lock:
            self.last_rssi = rssi
            self.recent.append(rssi)
            self.samples.append((time.time(), rssi))
            if self.ema_rssi is None:
                self.ema_rssi = float(rssi)
            else:
                self.ema_rssi = alpha * rssi + (1 - alpha) * self.ema_rssi

    def _recent(self, window_s):
        # MUST hold the lock: the capture thread appends here while the UI
        # thread reads, and a bounded deque drops from the left as it appends
        # -> "deque mutated during iteration" without this.
        with self.lock:
            if not self.samples:
                return []
            if not window_s:
                return [r for _, r in self.samples]
            cutoff = time.time() - window_s
            vals = [r for t, r in self.samples if t >= cutoff]
            return vals if vals else [self.samples[-1][1]]  # never fully empty

    def recent_list(self):
        """Thread-safe copy of the recent RSSI values (for the sparkline)."""
        with self.lock:
            return list(self.recent)

    def channels_list(self):
        with self.lock:
            return sorted(self.channels)

    def ssids_list(self):
        with self.lock:
            return sorted(self.ssids)

    def services_list(self):
        with self.lock:
            return sorted(self.services)

    def domains_list(self):
        with self.lock:
            return sorted(self.domains)

    def sample_count(self, window_s=None):
        return len(self._recent(window_s))

    def best_device_safe(self):
        with self.lock:
            return self.best_device()

    def rank_value(self, kind="median", window_s=None):
        """Robust proximity estimate (dBm). Higher = closer."""
        vals = self._recent(window_s)
        if not vals:
            return None
        if kind == "ema":
            return self.ema_rssi
        if kind == "mean":
            return sum(vals) / len(vals)
        if kind == "max":
            return max(vals)
        if kind == "p80":
            return _percentile(vals, 80)
        return statistics.median(vals)          # default: median (robust)

    def spread(self, window_s=None):
        """RSSI spread (p90-p10) in dB — a stability / confidence indicator."""
        vals = self._recent(window_s)
        if len(vals) < 3:
            return None
        return _percentile(vals, 90) - _percentile(vals, 10)

    def weighted_rssi(self, half_life=6.0):
        """
        Recency-weighted mean RSSI: recent samples count more (exponential
        decay, `half_life` seconds). Reacts within a few seconds when a device
        moves, while still averaging out per-packet noise — the sweet spot
        between a raw last-reading (jumpy) and a long median (sluggish).
        """
        with self.lock:
            if not self.samples:
                return None
            now = time.time()
            tau = (half_life / 0.6931471805599453) if half_life and half_life > 0 else None
            num = den = 0.0
            for t, r in self.samples:
                w = math.exp(-(now - t) / tau) if tau else 1.0
                num += w * r
                den += w
            return (num / den) if den > 0 else None

    def estimate(self, rank_by, window_s, half_life):
        """The value used for BOTH ranking and the RSSI column, so they agree."""
        if rank_by == "weighted":
            return self.weighted_rssi(half_life)
        return self.rank_value(rank_by, window_s)

    def touch(self, channel=None):
        with self.lock:
            self.last_seen = time.time()
            self.packets += 1
            if channel:
                self.channels.add(channel)

    @property
    def age(self):
        return time.time() - self.last_seen


class Tracker:
    """Holds all stations. Every public method is safe to call from threads."""

    def __init__(self, alpha=0.3, rank_by="weighted", window_s=30,
                 min_samples=4, half_life=6.0):
        self.alpha = alpha
        self.rank_by = rank_by      # weighted (default) / median / ema / p80 / max
        self.window_s = window_s    # window for median/mean/spread/sample-count
        self.half_life = half_life  # recency half-life (s) for 'weighted'
        self.min_samples = min_samples   # below this, RSSI shows a '?' (display only)
        self._lock = threading.RLock()
        self.stations = {}          # mac -> Station
        self.bssid_ssid = {}        # bssid -> ssid  (from beacons)
        self.ip_to_host = {}        # ip -> hostname (from any source)
        self.total_frames = 0
        self.start = time.time()
        self.errors = []           # capture-thread errors, surfaced on exit
        self.lock_info = None      # (bssid, channel, rssi) when locked to an AP
        self.ftypes = {0: 0, 1: 0, 2: 0}   # mgmt / control / DATA frame counts
        self.bssid_data = {}               # bssid -> data-frame count (activity)
        self.diag = {"tods": 0, "fromds": 0, "wds": 0,   # data-frame X-ray
                     "cli_uni": 0, "cli_mc": 0, "cli_target": 0}

    def note_data(self, bssid):
        """Count a data frame seen on an AP — a proxy for client activity."""
        b = normalize_mac(bssid) if bssid else None
        if b:
            with self._lock:
                self.bssid_data[b] = self.bssid_data.get(b, 0) + 1

    def set_radio(self, mac, width=None, center_ch=None, ht_offset=None):
        """Record an AP's channel width so we can capture at the right width."""
        mac = normalize_mac(mac)
        with self._lock:
            st = self.stations.get(mac)
            if not st:
                return
            if width:
                st.width = width
            if center_ch:
                st.center_ch = center_ch
            if ht_offset:
                st.ht_offset = ht_offset

    def set_security(self, mac, sec):
        mac = normalize_mac(mac)
        with self._lock:
            st = self.stations.get(mac)
            if st and sec:
                st.security = sec

    def security_for_ssid(self, ssid):
        """Best-known security label across the APs advertising this SSID."""
        with self._lock:
            for b in self.bssids_for_ssid(ssid):
                st = self.stations.get(b)
                if st and st.security:
                    return st.security
        return None

    def radio_for(self, mac):
        """(width, center_ch, ht_offset) for an AP, or (None, None, None)."""
        mac = normalize_mac(mac)
        with self._lock:
            st = self.stations.get(mac)
            if not st:
                return (None, None, None)
            return (st.width, st.center_ch, st.ht_offset)

    def _get(self, mac):
        st = self.stations.get(mac)
        if st is None:
            # share the tracker's RLock so readers/writers can't race
            st = Station(mac, lock=self._lock)
            self.stations[mac] = st
        return st

    def observe(self, mac, rssi=None, channel=None, is_ap=None,
                bssid=None, ssid=None):
        mac = normalize_mac(mac)
        if not mac or mac_is_multicast(mac):
            return
        with self._lock:
            self.total_frames += 1
            st = self._get(mac)
            st.update_rssi(rssi, self.alpha)
            st.touch(channel)
            if is_ap is True:
                st.is_ap = True
            if bssid:
                b = normalize_mac(bssid)
                if b and not mac_is_multicast(b):
                    st.bssid = b
                    if b in self.bssid_ssid:
                        st.network = self.bssid_ssid[b]
            if ssid:
                st.ssids.add(ssid)
                if not st.network:
                    st.network = ssid

    def bssids_for_ssid(self, ssid):
        """All BSSIDs (APs, incl. mesh/repeaters) advertising this SSID
        (case-insensitive, whitespace-trimmed)."""
        want = (ssid or "").strip().casefold()
        with self._lock:
            return {b for b, s in self.bssid_ssid.items()
                    if (s or "").strip().casefold() == want}

    def channels_for_ssid(self, ssid):
        """Channels those APs live on — used to narrow (speed up) the sweep."""
        want = (ssid or "").strip().casefold()
        with self._lock:
            chans = set()
            for b, s in self.bssid_ssid.items():
                if (s or "").strip().casefold() == want:
                    st = self.stations.get(b)
                    if st:
                        chans |= st.channels
            return chans

    def strongest_ap_for_ssid(self, ssid):
        """
        The AP of this network we hear best = the one we're physically nearest.
        Returns (bssid, channel, rssi) or None. Used to lock the radio to that
        channel, which is where the devices near us will be.
        """
        best = None
        with self._lock:
            for b in self.bssids_for_ssid(ssid):
                st = self.stations.get(b)
                if not st or not st.channels:
                    continue
                rv = st.rank_value(self.rank_by, self.window_s)
                if rv is None:
                    continue
                ch = sorted(st.channels)[-1]
                if best is None or rv > best[2]:
                    best = (b, ch, rv)
        return best

    def best_ap_for_ssid(self, ssid):
        """
        Pick the AP to camp on: prefer the one with the MOST client data
        (that's where devices actually are), breaking ties by signal. Falls back
        to the strongest AP when nobody's transmitting yet. Returns
        (bssid, channel, rssi, data_count) or None.
        """
        best = None
        best_key = None
        with self._lock:
            for b in self.bssids_for_ssid(ssid):
                st = self.stations.get(b)
                if not st or not st.channels:
                    continue
                rv = st.rank_value(self.rank_by, self.window_s)
                dc = self.bssid_data.get(b, 0)
                ch = sorted(st.channels)[-1]
                key = (dc, rv if rv is not None else -999)
                if best_key is None or key > best_key:
                    best_key = key
                    best = (b, ch, rv if rv is not None else -999, dc)
        return best

    def count_associated(self, ssid):
        """How many client stations we've confirmed are on this network."""
        targets = self.bssids_for_ssid(ssid)
        with self._lock:
            return sum(1 for s in self.stations.values()
                       if not s.is_ap and s.bssid in targets)

    def is_known_bssid(self, mac):
        """True if we've seen a beacon/probe-response from this MAC."""
        mac = normalize_mac(mac)
        if not mac:
            return False
        with self._lock:
            return mac in self.bssid_ssid

    def seen_ssids(self):
        """All non-hidden network names seen in beacons (for diagnostics)."""
        with self._lock:
            return sorted({s for s in self.bssid_ssid.values() if s})

    def register_bssid(self, bssid, ssid):
        bssid = normalize_mac(bssid)
        if bssid and ssid:
            with self._lock:
                self.bssid_ssid[bssid] = ssid
                # backfill any stations already associated to this BSSID
                for st in self.stations.values():
                    if st.bssid == bssid and not st.network:
                        st.network = ssid

    def set_info(self, mac=None, ip=None, hostname=None, os_hint=None,
                 model=None, service=None, dhcp_fp=None, nbios=None,
                 domain=None, user_agent=None):
        """
        Attach anything learned about a device (by MAC when known, else by IP)
        to the right station. Scalar fields only fill if empty (first/best wins,
        except hostname/model which upgrade to a better value); set-valued
        fields accumulate.
        """
        # drop implausible IPs so a misparse can't inject a bogus address
        if ip and not valid_ipv4(ip):
            ip = None
        with self._lock:
            if ip and hostname:
                self.ip_to_host[ip] = hostname
            mac = normalize_mac(mac) if mac else None
            st = None
            if mac and mac in self.stations:
                st = self.stations[mac]
            elif ip:
                for s in self.stations.values():
                    if s.ip == ip:
                        st = s
                        break
            if st is None:
                return
            if ip:
                st.ip = ip
                if not hostname and ip in self.ip_to_host:
                    hostname = self.ip_to_host[ip]
            # hostname/model: prefer a more descriptive value over a bare one
            if hostname and (not st.hostname or len(hostname) > len(st.hostname)):
                st.hostname = hostname
            if model and (not st.model or len(model) > len(st.model)):
                st.model = model
            if os_hint and not st.os_hint:
                st.os_hint = os_hint
            if dhcp_fp and not st.dhcp_fp:
                st.dhcp_fp = dhcp_fp
            if nbios and not st.nbios:
                st.nbios = nbios
            if user_agent and not st.user_agent:
                st.user_agent = user_agent
            if service:
                st.services.add(service)
            if domain and len(st.domains) < 40:
                st.domains.add(domain)

    # backwards-compatible alias used by the local (on-host) enricher
    def set_l3(self, mac=None, ip=None, hostname=None):
        self.set_info(mac=mac, ip=ip, hostname=hostname)

    def set_fingerprint(self, mac, hint):
        mac = normalize_mac(mac)
        with self._lock:
            if mac and mac in self.stations and hint:
                self.stations[mac].fingerprint = hint

    def snapshot(self, include_aps=False, max_age=None, only_bssids=None):
        """Return a ranked list (closest first) of station dicts for display."""
        with self._lock:
            rows = []
            for st in self.stations.values():
                if st.is_ap and not include_aps:
                    continue
                if max_age is not None and st.age > max_age:
                    continue
                if only_bssids and st.bssid not in only_bssids:
                    continue
                rows.append(st)

            # Rank by SIGNAL STRENGTH, strongest first — a device with a
            # stronger signal is physically closer, full stop, so it belongs at
            # the top even if it only just appeared. The only devices pushed to
            # the bottom are ones with no usable estimate yet (0-1 samples). A
            # low sample count no longer demotes a strong device; it's shown as
            # a '?' in the display instead. This is what makes the list track
            # reality quickly as you move devices around.
            def key(s):
                rv = s.estimate(self.rank_by, self.window_s, self.half_life)
                usable = rv is not None and s.sample_count(None) >= 2
                return (not usable, -(rv if rv is not None else -999))
            rows.sort(key=key)
            return rows

    def stats(self):
        with self._lock:
            return {
                "frames": self.total_frames,
                "stations": sum(1 for s in self.stations.values()
                                if not s.is_ap),
                "aps": sum(1 for s in self.stations.values() if s.is_ap),
                "elapsed": time.time() - self.start,
                "mgmt": self.ftypes.get(0, 0),
                "data": self.ftypes.get(2, 0),
            }


# ===========================================================================
# Capture (scapy) -- lazy import lives here
# ===========================================================================

def run_capture(tracker, iface, oui, stop_event, args):
    """Blocking sniff loop. Runs in its own thread."""
    try:
        from scapy.all import (sniff, conf, RadioTap, Dot11, Dot11Beacon,
                               Dot11ProbeReq, Dot11ProbeResp, Dot11Elt)
        from scapy.all import ARP  # noqa
        try:
            from scapy.all import DHCP, BOOTP  # noqa
        except Exception:
            DHCP = BOOTP = None
        try:
            from scapy.all import DNS, DNSRR, DNSQR  # noqa
        except Exception:
            DNS = DNSRR = DNSQR = None
    except Exception as e:
        tracker.errors.append(f"scapy import failed: {e}")
        stop_event.set()
        return

    oui.attach_scapy(conf)

    def get_rssi(pkt):
        try:
            return int(pkt[RadioTap].dBm_AntSignal)
        except Exception:
            return None

    def get_channel(pkt):
        try:
            return freq_to_channel(int(pkt[RadioTap].ChannelFrequency))
        except Exception:
            return None

    def get_ssid(pkt):
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if elt.ID == 0:
                    ssid = bytes(elt.info)
                    if ssid and all(32 <= b < 127 for b in ssid):
                        return ssid.decode("utf-8", "replace")
                    return None
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return None

    def handler(pkt):
        if stop_event.is_set():
            return
        if not pkt.haslayer(Dot11):
            return
        d = pkt[Dot11]
        rssi = get_rssi(pkt)
        chan = get_channel(pkt)
        ftype, fsub = d.type, d.subtype
        a1, a2, a3 = d.addr1, d.addr2, d.addr3
        try:
            tracker.ftypes[ftype] = tracker.ftypes.get(ftype, 0) + 1
        except Exception:
            pass

        # --- management frames -------------------------------------------
        if ftype == 0:
            if pkt.haslayer(Dot11Beacon) or fsub == 8:
                ssid = get_ssid(pkt)
                if a2:
                    tracker.observe(a2, rssi=rssi, channel=chan,
                                    is_ap=True, ssid=ssid)
                    if ssid:
                        tracker.register_bssid(a2, ssid)
                    # learn the AP's real channel width so we can capture wide
                    w, cc, off = _parse_ht_vht(pkt, Dot11Elt)
                    if w or cc or off:
                        tracker.set_radio(a2, w, cc, off)
                    # classify security (open vs OWE vs WPA) once
                    if a2 and tracker.stations[normalize_mac(a2)].security is None:
                        tracker.set_security(a2, _beacon_security(
                            pkt, Dot11Elt, Dot11Beacon))
                return
            if pkt.haslayer(Dot11ProbeResp) or fsub == 5:
                ssid = get_ssid(pkt)
                if a2:
                    tracker.observe(a2, rssi=rssi, channel=chan,
                                    is_ap=True, ssid=ssid)
                    if ssid:
                        tracker.register_bssid(a2, ssid)
                return
            if pkt.haslayer(Dot11ProbeReq) or fsub == 4:
                ssid = get_ssid(pkt)              # SSID the client is seeking
                tracker.observe(a2, rssi=rssi, channel=chan, ssid=ssid)
                if args.enrich_passive:          # WPS name/model works here too
                    _parse_wps(pkt, tracker, a2, Dot11Elt)
                return
            # assoc / auth / etc: a2 is usually the station
            tracker.observe(a2, rssi=rssi, channel=chan, bssid=a3)
            if args.enrich_passive and fsub in (0, 2):   # (re)assoc request
                _parse_wps(pkt, tracker, a2, Dot11Elt)
            return

        # --- control frames (ACK/RTS/CTS): often no a2, skip cheaply -----
        if ftype == 1:
            if a2:
                tracker.observe(a2, rssi=rssi, channel=chan)
            return

        # --- data frames --------------------------------------------------
        if ftype == 2:
            # NOTE: FCfield is a scapy FlagValue, not a plain int -- coerce it
            # with int() before masking, or the DS bits read wrong and every
            # frame looks like WDS (which silently loses all associations).
            try:
                fc = int(d.FCfield)
            except Exception:
                fc = 0
            to_ds = bool(fc & 0x1)
            from_ds = bool(fc & 0x2)
            protected = frame_is_protected(fc)  # WEP/CCMP/TKIP -> encrypted
            bssid, station, tx_is_ap = infer_association(
                to_ds, from_ds, a1, a2, a3, tracker.is_known_bssid)
            # X-ray: where do data frames go? (helps distinguish "all broadcast"
            # from a real association bug)
            dg = tracker.diag
            if to_ds and not from_ds:
                dg["tods"] += 1
            elif from_ds and not to_ds:
                dg["fromds"] += 1
            else:
                dg["wds"] += 1
            if station and normalize_mac(station) and not mac_is_multicast(station):
                dg["cli_uni"] += 1
                if bssid and tracker.is_known_bssid(bssid):
                    dg["cli_target"] += 1
            else:
                dg["cli_mc"] += 1
            # RSSI always belongs to the transmitter (a2).
            if tx_is_ap:                          # AP -> station
                tracker.observe(a2, rssi=rssi, channel=chan, is_ap=True)
                if station:
                    tracker.observe(station, channel=chan, bssid=bssid)
            else:                                 # station -> AP (what we want)
                tracker.observe(a2, rssi=rssi, channel=chan, bssid=bssid)
            if bssid:
                tracker.note_data(bssid)          # track per-AP client activity

            # opportunistic plaintext L3 (open networks / unencrypted only).
            # CRITICAL: never parse a PROTECTED frame's payload — it's encrypted
            # ciphertext, and scapy will occasionally misread it as a bogus
            # ARP/DHCP/DNS packet and invent a wrong IP/hostname. Headers stay
            # cleartext, so association above still works; only L3 is skipped.
            if args.enrich_passive and not protected:
                if to_ds and not from_ds:
                    station_mac = a2      # frame sent BY the client
                elif from_ds and not to_ds:
                    station_mac = a1      # frame sent TO the client
                else:
                    station_mac = a2
                _passive_l3(pkt, tracker, station_mac,
                            ARP, DHCP, BOOTP, DNS)
            return

    def _sniff():
        try:
            sniff(iface=iface, prn=handler, store=False,
                  stop_filter=lambda p: stop_event.is_set())
        except PermissionError:
            tracker.errors.append("need root to capture — re-run with sudo.")
            stop_event.set()
        except OSError as e:
            tracker.errors.append(
                f"could not open '{iface}': {e}. Is it really in monitor "
                f"mode? (check: iw dev {iface} info). If the name is wrong, "
                f"list interfaces with: iw dev")
            stop_event.set()
        except Exception as e:
            tracker.errors.append(f"capture error ({type(e).__name__}): {e}")
            stop_event.set()

    _sniff()


def _s(v):
    """Bytes/str -> clean str."""
    if v is None:
        return None
    if isinstance(v, bytes):
        v = v.decode("utf-8", "replace")
    return str(v).strip().strip(".") or None


def _mdns_friendly(name):
    """
    'Akshats-iPhone._companion-link._tcp.local' -> ('Akshats-iPhone',
    'companion-link'). Returns (instance, service) best-effort.
    """
    name = _s(name) or ""
    m = re.match(r"^(.*?)\._([a-zA-Z0-9-]+)\._(?:tcp|udp)\b", name)
    if m:
        return m.group(1), m.group(2)
    return None, None


# short, friendly names for the noisiest mDNS/SSDP service types
_SERVICE_NAMES = {
    "airplay": "airplay", "raop": "airplay", "airport": "airport",
    "companion-link": "apple", "apple-mobdev2": "apple", "sleep-proxy": "apple",
    "googlecast": "chromecast", "googlezone": "google", "spotify-connect": "spotify",
    "printer": "printer", "ipp": "printer", "ipps": "printer", "pdl-datastream": "printer",
    "smb": "fileshare", "afpovertcp": "fileshare", "ssh": "ssh", "sftp-ssh": "ssh",
    "homekit": "homekit", "hap": "homekit", "matter": "matter", "hue": "hue",
    "workstation": "workstation", "device-info": None, "http": None, "https": None,
}


def _passive_l3(pkt, tracker, station_mac, ARP, DHCP, BOOTP, DNS):
    """
    Extract everything a device leaks in the clear (open/unencrypted networks):
    IP (ARP/DHCP), hostname + OS + fingerprint (DHCP), friendly name/model/
    services (mDNS), device type/OS (SSDP/UPnP), Windows name (NetBIOS),
    domains it talks to (DNS + TLS SNI), and HTTP User-Agent.
    """
    smac = normalize_mac(station_mac)
    try:
        # ---- ARP: MAC <-> IP (authoritative) --------------------------------
        if ARP is not None and pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.hwsrc and arp.psrc and arp.psrc not in ("0.0.0.0", None):
                tracker.set_info(mac=arp.hwsrc, ip=arp.psrc)

        # ---- DHCP: hostname, vendor-class(OS), fingerprint, requested IP -----
        if DHCP is not None and pkt.haslayer(DHCP):
            hostname = os_hint = req_ip = fp = None
            for opt in pkt[DHCP].options:
                if not isinstance(opt, tuple):
                    continue
                k = opt[0]
                if k == "hostname":
                    hostname = _s(opt[1])
                elif k in ("vendor_class_id", "vendor_class_identifier"):
                    os_hint = _dhcp_vendor_os(_s(opt[1]))
                elif k in ("requested_addr", "requested_address"):
                    req_ip = _s(opt[1])
                elif k in ("param_req_list", "parameter_request_list"):
                    try:
                        vals = opt[1] if isinstance(opt[1], (list, tuple)) \
                            else list(bytes(opt[1]))
                        fp = ",".join(str(int(x)) for x in vals)
                    except Exception:
                        fp = None
            climac = smac
            if BOOTP is not None and pkt.haslayer(BOOTP):
                try:
                    ch = pkt[BOOTP].chaddr
                    m = normalize_mac(ch[:6].hex()) if ch else None
                    if m:
                        climac = m
                except Exception:
                    pass
            if any((hostname, os_hint, req_ip, fp)):
                tracker.set_info(mac=climac, hostname=hostname, os_hint=os_hint,
                                 ip=req_ip, dhcp_fp=fp)

        # ---- UDP-based protocols (mDNS / SSDP / NetBIOS / LLMNR / DNS) -------
        udp = pkt.getlayer("UDP")
        if udp is not None:
            sport, dport = int(udp.sport), int(udp.dport)
            payload = bytes(udp.payload) if udp.payload else b""

            # mDNS / LLMNR (DNS wire format)
            if DNS is not None and (5353 in (sport, dport)
                                    or 5355 in (sport, dport)) \
                    and pkt.haslayer(DNS):
                _parse_mdns(pkt[DNS], tracker, smac)

            # regular DNS queries -> domains it talks to
            elif DNS is not None and dport == 53 and pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]
                    if dns.qd is not None and int(getattr(dns, "qr", 0)) == 0:
                        qn = _s(dns.qd.qname)
                        if qn and not qn.endswith(".arpa"):
                            tracker.set_info(mac=smac, domain=qn)
                except Exception:
                    pass

            # SSDP / UPnP (HTTP-over-UDP on 1900)
            elif 1900 in (sport, dport) and payload:
                _parse_ssdp(payload, tracker, smac)

            # NetBIOS Name Service (Windows names)
            elif 137 in (sport, dport) and payload:
                name = _parse_netbios(payload)
                if name:
                    tracker.set_info(mac=smac, nbios=name, hostname=name)

        # ---- TCP: HTTP User-Agent, TLS SNI ----------------------------------
        tcp = pkt.getlayer("TCP")
        if tcp is not None and tcp.payload:
            data = bytes(tcp.payload)
            dport = int(tcp.dport)
            if dport == 80 or data[:3] in (b"GET", b"POS", b"HEA", b"PUT"):
                ua = _http_header(data, b"User-Agent")
                host = _http_header(data, b"Host")
                if ua or host:
                    tracker.set_info(mac=smac, user_agent=ua, domain=host)
            elif dport == 443:
                sni = _tls_sni(data)
                if sni:
                    tracker.set_info(mac=smac, domain=sni)
    except Exception:
        pass


def _dhcp_vendor_os(vci):
    """Map a DHCP vendor-class-identifier to a friendly OS hint."""
    if not vci:
        return None
    low = vci.lower()
    table = [("android", "Android"), ("msft", "Windows"), ("dhcpcd", "Linux"),
             ("udhcp", "Linux/embedded"), ("ccc", "Apple"), ("aap", "Apple"),
             ("darwin", "macOS/iOS"), ("iphone", "iPhone"), ("ipad", "iPad"),
             ("linux", "Linux"), ("roku", "Roku"), ("amazon", "Amazon"),
             ("nintendo", "Nintendo"), ("sonos", "Sonos"), ("dhcp", None)]
    for key, name in table:
        if key in low and name:
            return name
    return vci[:20]


def _parse_mdns(dns, tracker, smac):
    """Walk mDNS records for friendly name, model, services, and A records."""
    try:
        for attr, count in (("an", "ancount"), ("ns", "nscount"),
                            ("ar", "arcount"), ("qd", "qdcount")):
            rr = getattr(dns, attr, None)
            n = int(getattr(dns, count, 0) or 0)
            for _ in range(min(n, 32)):
                if rr is None:
                    break
                try:
                    rtype = int(getattr(rr, "type", 0))
                    rname = _s(getattr(rr, "rrname", None))
                    if rtype == 1:                       # A -> hostname<->ip
                        ip = _s(getattr(rr, "rdata", None))
                        host = (rname or "").replace(".local", "")
                        if ip:
                            tracker.set_info(mac=smac, ip=ip, hostname=host or None)
                    elif rtype == 12:                    # PTR -> service+instance
                        inst, svc = _mdns_friendly(_s(getattr(rr, "rdata", None)))
                        if not svc:
                            _, svc = _mdns_friendly(rname)
                        if svc:
                            fs = _SERVICE_NAMES.get(svc, svc)
                            if fs:
                                tracker.set_info(mac=smac, service=fs)
                        if inst:
                            tracker.set_info(mac=smac, hostname=inst)
                    elif rtype == 16:                    # TXT -> model=
                        txt = getattr(rr, "rdata", None)
                        model = _txt_model(txt)
                        if model:
                            tracker.set_info(mac=smac, model=model)
                    elif rtype == 33:                    # SRV -> target host
                        tgt = _s(getattr(rr, "target", None))
                        if tgt:
                            tracker.set_info(mac=smac,
                                             hostname=tgt.replace(".local", ""))
                except Exception:
                    pass
                rr = getattr(rr, "payload", None)
    except Exception:
        pass


def _txt_model(txt):
    """Pull a model/name out of an mDNS TXT record (model=, md=, ty=)."""
    try:
        items = txt if isinstance(txt, list) else [txt]
        for it in items:
            s = it.decode("utf-8", "replace") if isinstance(it, bytes) else str(it)
            for key in ("model=", "md=", "ty=", "am=", "product="):
                m = re.search(re.escape(key) + r"([^\x00;,]+)", s, re.I)
                if m:
                    val = m.group(1).strip()
                    if val and val.lower() not in ("unknown",):
                        return val[:24]
    except Exception:
        pass
    return None


def _parse_ssdp(payload, tracker, smac):
    """SSDP/UPnP NOTIFY/M-SEARCH: SERVER (OS) + device type."""
    try:
        text = payload.decode("utf-8", "replace")
        server = re.search(r"^SERVER:\s*(.+)$", text, re.I | re.M)
        if server:
            tracker.set_info(mac=smac, os_hint=server.group(1).strip()[:24])
        for hdr in ("NT", "ST"):
            m = re.search(r"^%s:\s*urn:[^:]+:device:([^:]+):" % hdr,
                          text, re.I | re.M)
            if m:
                tracker.set_info(mac=smac, service="upnp:" + m.group(1).lower())
    except Exception:
        pass


def _parse_netbios(payload):
    """Decode the first NetBIOS name from an NBNS packet (best-effort)."""
    try:
        # NBNS: 12-byte header, then a name: 1 length byte (0x20) + 32 encoded
        if len(payload) < 46 or payload[12] != 0x20:
            return None
        enc = payload[13:45]
        out = []
        for i in range(0, 32, 2):
            hi = enc[i] - 0x41
            lo = enc[i + 1] - 0x41
            if hi < 0 or lo < 0 or hi > 15 or lo > 15:
                return None
            out.append((hi << 4) | lo)
        name = bytes(out).decode("ascii", "replace").strip().strip("\x00")
        name = name.rstrip()
        return name or None
    except Exception:
        return None


def _http_header(data, name):
    """Extract a header value from a raw HTTP request."""
    try:
        m = re.search(re.escape(name) + rb":\s*([^\r\n]+)", data, re.I)
        if m:
            return m.group(1).decode("utf-8", "replace").strip()[:80]
    except Exception:
        pass
    return None


def _tls_sni(data):
    """Best-effort SNI extraction from a TLS ClientHello (raw bytes)."""
    try:
        # TLS record: 0x16 (handshake), then ... handshake type 0x01 (ClientHello)
        if len(data) < 45 or data[0] != 0x16:
            return None
        # find server_name extension (type 0x0000) heuristically
        i = data.find(b"\x00\x00")   # extension type 0 appears before name
        # more robust: scan for the SNI structure: 00 00 <len2> 00 <len2> 00 <len2> host
        m = re.search(rb"\x00\x00..\x00..\x00(..)([a-z0-9.\-]{3,})", data, re.I)
        if m:
            host = m.group(2).decode("ascii", "replace")
            if "." in host and not host.startswith("."):
                return host[:60]
    except Exception:
        pass
    return None


def classify_security(privacy, akm_types, has_wpa_ie=False):
    """
    Decide a network's security from its beacon. THE key distinction for a
    passive sniffer: only 'OPEN' leaves payloads readable over the air. 'OWE'
    (Enhanced Open) looks password-free to users but encrypts per client, so an
    off-network capture sees only MACs/sizes/timing — same as WPA.

    akm_types = AKM suite selector bytes from the RSN element (00-0F-AC:X):
        1=802.1X(Enterprise) 2=PSK 8=SAE(WPA3) 18=OWE 5/6=FT ...
    """
    if akm_types:
        if 8 in akm_types or 24 in akm_types:
            return "WPA3-SAE"
        if 18 in akm_types:
            return "OWE"
        if 1 in akm_types or 3 in akm_types or 11 in akm_types:
            return "WPA2-Ent"
        if 2 in akm_types:
            return "WPA2-PSK"
        return "WPA2"
    if has_wpa_ie:
        return "WPA"
    # A privacy bit with no RSN/WPA on a modern AP is almost always OWE-transition
    # or a vendor quirk, NOT real WEP (which is extinct). airodump confirms these
    # campus SSIDs are OPN, so don't scare the user off with a false "encrypted".
    return "OPEN"


def _rsn_akms(info):
    """Extract AKM suite type bytes from an RSN (802.11i) element body."""
    try:
        i = 2 + 4                       # version(2) + group cipher(4)
        pc = info[i] | (info[i + 1] << 8)
        i += 2 + 4 * pc                 # pairwise count + pairwise suites
        ac = info[i] | (info[i + 1] << 8)
        i += 2
        akms = []
        for _ in range(ac):
            suite = info[i:i + 4]
            if len(suite) < 4:
                break
            akms.append(suite[3])
            i += 4
        return akms
    except Exception:
        return []


def _beacon_security(pkt, Dot11Elt, Dot11Beacon):
    """Classify a beacon/probe-response's network security. Returns a label."""
    privacy = False
    try:
        cap = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else 0
        privacy = bool(int(cap) & 0x10)      # capability bit 4 = Privacy
    except Exception:
        pass
    akms = []
    has_wpa = False
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            try:
                eid = int(elt.ID)
                info = bytes(elt.info)
                if eid == 48:                        # RSN
                    akms = _rsn_akms(info)
                elif eid == 221 and info[:4] == b"\x00\x50\xf2\x01":
                    has_wpa = True                   # WPA1 vendor IE
            except Exception:
                pass
            nxt = elt.payload
            elt = nxt.getlayer(Dot11Elt) if nxt else None
    except Exception:
        pass
    return classify_security(privacy, akms, has_wpa)


def _parse_ht_vht(pkt, Dot11Elt):
    """
    Read the HT Operation (IE 61) and VHT Operation (IE 192) elements from a
    beacon to learn the AP's actual channel width. Returns
    (width_mhz, center_channel, ht_offset).
    """
    width = center = offset = None
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            try:
                eid = int(elt.ID)
                info = bytes(elt.info)
                if eid == 61 and len(info) >= 2:          # HT Operation
                    sec = info[1] & 0x03
                    if sec == 1:
                        offset = "+"
                    elif sec == 3:
                        offset = "-"
                    if offset and (info[1] & 0x04):
                        width = max(width or 0, 40)
                elif eid == 192 and len(info) >= 2:        # VHT Operation
                    w = info[0]
                    if w == 1:
                        width, center = 80, info[1]
                    elif w == 2:
                        width, center = 160, info[1]
                    elif w == 3:
                        width, center = 80, info[1]
            except Exception:
                pass
            nxt = elt.payload
            elt = nxt.getlayer(Dot11Elt) if nxt else None
    except Exception:
        pass
    return width, center, offset


def _parse_wps(pkt, tracker, mac, Dot11Elt):
    """
    Parse WPS info elements (device name / manufacturer / model) from a probe
    request or association request. Works even on ENCRYPTED networks, since
    these are management frames. Best-effort.
    """
    smac = normalize_mac(mac)
    if not smac:
        return
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if int(elt.ID) == 221:
                info = bytes(elt.info)
                # WPS vendor IE: OUI 00:50:F2, type 0x04
                if info[:4] == b"\x00\x50\xf2\x04":
                    _parse_wps_tlvs(info[4:], tracker, smac)
            nxt = elt.payload
            elt = nxt.getlayer(Dot11Elt) if nxt else None
    except Exception:
        pass


def _parse_wps_tlvs(data, tracker, smac):
    # WPS attributes are 2-byte type, 2-byte len, value
    fields = {0x1011: "device_name", 0x1021: "manufacturer",
              0x1023: "model_name", 0x1024: "model_number"}
    try:
        i = 0
        found = {}
        while i + 4 <= len(data):
            t = (data[i] << 8) | data[i + 1]
            ln = (data[i + 2] << 8) | data[i + 3]
            val = data[i + 4:i + 4 + ln]
            if t in fields:
                found[fields[t]] = val.decode("utf-8", "replace").strip()
            i += 4 + ln
        if found.get("device_name"):
            tracker.set_info(mac=smac, hostname=found["device_name"])
        model = " ".join(x for x in (found.get("manufacturer"),
                                     found.get("model_name")) if x).strip()
        if model:
            tracker.set_info(mac=smac, model=model[:24])
    except Exception:
        pass


# ===========================================================================
# Channel hopping
# ===========================================================================

def _set_channel(iface, ch, width=None, center_ch=None, ht_offset=None):
    """Tune to a channel; when width info is known, capture at that width so
    HT/VHT data frames actually decode (not just legacy-rate beacons)."""
    cmd = width_iw_args(iface, ch, width, center_ch, ht_offset)
    if not cmd:
        return False
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2.0)
        if r.returncode == 0:
            return True
        # wide tune failed (driver/regdom) -> fall back to plain 20 MHz
        if len(cmd) > 6:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2.0)
    except Exception:
        pass
    return False


def channel_hopper(iface, channels, stop_event, dwell=0.20,
                   tracker=None, ssid=None, rescan_every=12,
                   lock_strongest=False, lock_after=20.0, relock_every=90.0,
                   force_width=None):
    """
    Cycle channels with `iw`. When a target SSID is given, once we've found the
    channels that network's APs live on we sweep ONLY those channels — much
    faster than the full band. Every `rescan_every` sweeps we do a full-band pass
    to catch new/roaming APs.

    With `lock_strongest`, after `lock_after` seconds we pick the target
    network's AP with the STRONGEST signal (i.e. the one we're standing nearest)
    and park the radio on its channel. On a big multi-AP network this is the only
    way to get enough samples per device: 100% of the time on one channel instead
    of ~8% across a dozen. Every `relock_every` seconds we re-sweep briefly and
    re-pick, so walking to a different AP still works.
    """
    sweeps = 0
    started = time.time()
    locked_ch = None
    last_relock = 0.0

    while not stop_event.is_set():
        now = time.time()
        if (lock_strongest and tracker is not None and ssid
                and (now - started) >= lock_after):
            # time to (re)choose the nearest AP?
            if locked_ch is None or (now - last_relock) >= relock_every:
                if locked_ch is not None:
                    # brief re-scan of the network's channels before re-picking
                    for ch in sorted(tracker.channels_for_ssid(ssid)) or channels:
                        if stop_event.is_set():
                            break
                        _set_channel(iface, ch)
                        stop_event.wait(dwell)
                # camp where the CLIENTS are (most data), not just the loudest
                # beacon — a strong-beacon AP with no client traffic is useless.
                best = tracker.best_ap_for_ssid(ssid)
                if best:
                    locked_ch = best[1]
                    # capture at the AP's REAL width, else we only decode
                    # legacy-rate beacons and miss all HT/VHT client data
                    w, cc, off = tracker.radio_for(best[0])
                    if force_width:
                        w = force_width
                    _set_channel(iface, locked_ch, w, cc, off)
                    tracker.lock_info = (best[0], locked_ch, best[2], w)
                last_relock = time.time()
            if locked_ch is not None:
                # already tuned; just idle (re-tuning constantly resets the RX
                # path on some drivers and costs us packets)
                stop_event.wait(2.0)
                continue

        hop_set = channels
        if tracker is not None and ssid:
            focus = tracker.channels_for_ssid(ssid)
            if focus and (sweeps % rescan_every != 0):
                hop_set = sorted(focus)          # fast, focused sweep
        for ch in hop_set:
            if stop_event.is_set():
                break
            _set_channel(iface, ch)
            stop_event.wait(dwell)
        sweeps += 1


# ===========================================================================
# Local (on-host) enrichment: ip neigh + reverse DNS + mDNS
# ===========================================================================

def local_enricher(tracker, stop_event, interval=8.0):
    """
    Periodically read the host's neighbour table (works even on WPA networks,
    because the info comes from your own network stack, not the air) and resolve
    hostnames via reverse DNS / avahi. Correlates to stations by MAC.
    """
    import socket
    have_avahi = _which("avahi-resolve")
    while not stop_event.is_set():
        mac_ip = {}
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True,
                                 text=True, timeout=4)
            if out.returncode == 0:
                mac_ip = parse_ip_neigh(out.stdout)
        except Exception:
            try:
                out = subprocess.run(["arp", "-a"], capture_output=True,
                                     text=True, timeout=4)
                mac_ip = parse_arp_a(out.stdout)
            except Exception:
                mac_ip = {}

        for mac, ip in mac_ip.items():
            tracker.set_l3(mac=mac, ip=ip)
            hostname = None
            if have_avahi:
                try:
                    r = subprocess.run(["avahi-resolve", "-a", ip],
                                       capture_output=True, text=True, timeout=3)
                    if r.returncode == 0 and "\t" in r.stdout:
                        hostname = r.stdout.strip().split("\t")[-1]
                except Exception:
                    pass
            if not hostname:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = None
            if hostname:
                tracker.set_l3(mac=mac, ip=ip, hostname=hostname)

        stop_event.wait(interval)


def _which(prog):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        f = os.path.join(p, prog)
        if os.path.isfile(f) and os.access(f, os.X_OK):
            return f
    return None


# ===========================================================================
# Interface / monitor-mode management (folds setup_monitor.sh into this script)
# ===========================================================================

def iface_is_monitor(iface):
    """True/False if we can tell, None if `iw` unavailable or iface missing."""
    if not _which("iw"):
        return None
    try:
        out = subprocess.run(["iw", "dev", iface, "info"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return None
        return "type monitor" in out.stdout
    except Exception:
        return None


def enable_monitor(iface, do_kill=False):
    """Put iface into monitor mode with iw. Returns (ok, message)."""
    if not _which("iw"):
        return False, "'iw' not installed (try: sudo apt install iw)"
    if do_kill and _which("airmon-ng"):
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    # Try the BROADEST capture flags first. 'otherbss' is the key one: without
    # it many drivers hardware-filter out unicast frames not addressed to this
    # interface — which looks exactly like "only broadcast is captured".
    tried = None
    for flags in (["otherbss", "control"], ["otherbss"], ["control"], None):
        if flags is None:
            cmd = ["iw", "dev", iface, "set", "type", "monitor"]
        else:
            cmd = ["iw", "dev", iface, "set", "monitor"] + flags
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            tried = flags or ["(type monitor)"]
            break
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    if iface_is_monitor(iface) is False:
        return False, "interface did not switch to monitor mode"
    return True, f"monitor mode enabled (flags: {' '.join(tried or [])})"


def restore_managed(iface):
    """Return iface to managed mode (best-effort)."""
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)


def pip_install(pkgs):
    """Best-effort install of dependencies for the CURRENT interpreter."""
    cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages",
           *pkgs]
    print("running:", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
        # retry without the flag (older pip doesn't know it)
        cmd = [sys.executable, "-m", "pip", "install", *pkgs]
        print("retrying:", " ".join(cmd))
        r = subprocess.run(cmd)
    return r.returncode == 0


# ===========================================================================
# Rendering
# ===========================================================================

def _fmt_age(sec):
    if sec < 60:
        return f"{int(sec)}s"
    if sec < 3600:
        return f"{int(sec // 60)}m"
    return f"{int(sec // 3600)}h"


def _row_fields(st, oui, args, rank):
    vendor = st.vendor or oui.lookup(st.mac)
    st.vendor = vendor
    win = getattr(args, "window", None)
    hl = getattr(args, "half_life", 6.0)
    rb = getattr(args, "rank_by", "weighted")
    # Hold the station lock for the whole read: the capture thread is appending
    # samples / adding channels / SSIDs concurrently, and iterating any of those
    # unlocked crashes with "deque mutated during iteration".
    with st.lock:
        rv = st.estimate(rb, win, hl)          # same value used for ranking
        n = st.sample_count(win)
        confident = n >= getattr(args, "min_samples", 3)
        # "?" flags a device with too few samples to trust its ranking yet
        rssi = "—" if rv is None else (f"{rv:5.1f}" + ("" if confident else "?"))
        sp = st.spread(win)
        spread = "—" if sp is None else f"{sp:4.1f}"
        ssids = sorted(st.ssids)
        net = st.network or (ssids[0] if ssids else "")
        if len(net) > 16:
            net = net[:15] + "…"
        host = st.hostname or ""
        if len(host) > 20:
            host = host[:19] + "…"
        device = st.best_device()
        if len(device) > 18:
            device = device[:17] + "…"
        ap = ""
        if st.bssid:
            ap = ":".join(st.bssid.split(":")[-2:])   # last 2 octets = the AP
        fields = {
            "rank": str(rank),
            "rssi": rssi,
            "spread": spread,
            "n": str(n),
            "trend": sparkline(list(st.recent), 10),
            "mac": st.mac,
            "vendor": (vendor or "")[:14],
            "host": host,
            "device": device,
            "ip": st.ip or "",
            "ap": ap,
            "net": net,
            "ch": ",".join(str(c) for c in sorted(st.channels)) or "?",
            "age": _fmt_age(st.age),
        }
    if args.estimate_distance:
        d = estimate_distance_m(rv, args.tx_power, args.path_loss)
        fields["dist"] = "—" if d is None else f"~{d}m"
    return fields


# spread = RSSI variability (dB); N = samples in the window; "?" on RSSI = low
# confidence (fewer than --min-samples samples so far).
_COL = {
    "rank": ("#", 3), "rssi": ("RSSI", 7), "spread": ("±dB", 5),
    "n": ("N", 4), "trend": ("TREND", 10), "mac": ("MAC", 17),
    "vendor": ("VENDOR", 14), "host": ("HOSTNAME", 20),
    "device": ("DEVICE / OS", 18), "ip": ("IP", 15), "ap": ("AP", 6),
    "net": ("NETWORK", 16), "ch": ("CH", 6), "age": ("SEEN", 5),
    "dist": ("~DIST", 8),
}


def _columns(args):
    """Build the column list; AP column when focusing an SSID, else NETWORK."""
    keys = ["rank", "rssi", "spread", "n", "trend", "mac", "vendor",
            "host", "device", "ip"]
    if args.estimate_distance:
        keys.insert(2, "dist")
    keys += (["ap"] if args.ssid else ["net"]) + ["ch", "age"]
    return [(k, _COL[k][0], _COL[k][1]) for k in keys]


def render_plain(tracker, oui, args):
    """Pure-stdlib ANSI renderer (used when rich is not installed)."""
    cols = _columns(args)
    rows = tracker.snapshot(include_aps=args.show_aps, max_age=args.max_age,
                            only_bssids=args.only_bssids)
    rows = rows[:args.top]
    s = tracker.stats()
    sys.stdout.write("\033[2J\033[H")  # clear + home
    hop = "hopping" if args.hop else f"ch {args.channel or 'lock'}"
    rankdesc = (f"weighted/{args.half_life:g}s" if args.rank_by == "weighted"
                else f"{args.rank_by}/{'all' if not args.window else str(int(args.window)) + 's'}")
    print(f"  wifi_proximity v{__version__}  iface={args.iface}  {hop}  "
          f"rank={rankdesc}  "
          f"stations={s['stations']}  aps={s['aps']}  "
          f"frames={s['frames']}  data={s['data']}  "
          f"up={_fmt_age(s['elapsed'])}   "
          f"(Ctrl-C to stop)")
    header = "  " + "  ".join(h.ljust(w) for _, h, w in cols)
    print("\033[1m" + header + "\033[0m")
    print("  " + "-" * (len(header) - 2))
    fstat = focus_status(tracker, args)
    if fstat:
        print("  \033[93m" + fstat + "\033[0m")
    dline = diag_line(tracker, args)
    if dline:
        print("  \033[90m" + dline + "\033[0m")
    if not rows and not fstat:
        print("  (listening… no stations yet — "
              "move the adapter or enable --hop)")
    for i, st in enumerate(rows, 1):
        f = _row_fields(st, oui, args, i)
        line = "  " + "  ".join(str(f.get(k, "")).ljust(w) for k, _, w in cols)
        # highlight the closest device
        if i == 1:
            line = "\033[92m" + line + "\033[0m"
        print(line)
    sys.stdout.flush()


def focus_status(tracker, args):
    """
    When --ssid is set, explain what's happening so a blank list is never a
    silent mystery: is the network found, how many APs, are any devices
    connected, and — if not found — which networks ARE visible.
    """
    if not args.ssid:
        return None
    targets = tracker.bssids_for_ssid(args.ssid)
    if not targets:
        seen = tracker.seen_ssids()
        if not seen:
            return (f"looking for '{args.ssid}' … no beacons decoded yet "
                    f"(hopping to find APs — give it a few seconds)")
        shown = ", ".join(seen[:12]) + ("…" if len(seen) > 12 else "")
        return (f"network '{args.ssid}' NOT seen yet. Networks visible now: "
                f"{shown}  ·  (check spelling/case, or it may be on a band "
                f"your adapter can't hear)")
    sec = tracker.security_for_ssid(args.ssid)
    sec_note = ""
    if sec == "OPEN":
        sec_note = " [OPEN — payloads readable: IP/host/DNS/HTTP work]"
    elif sec == "OWE":
        sec_note = " [OWE/Enhanced-Open — payloads ENCRYPTED, no L3 enrich]"
    elif sec:
        sec_note = f" [{sec} — payloads encrypted; use --enrich-local]"
    chans = sorted(tracker.channels_for_ssid(args.ssid))
    assoc = tracker.count_associated(args.ssid)
    total = tracker.stats()["stations"]
    if tracker.lock_info:
        b, ch, rv = tracker.lock_info[0], tracker.lock_info[1], tracker.lock_info[2]
        w = tracker.lock_info[3] if len(tracker.lock_info) > 3 else None
        apdata = tracker.bssid_data.get(b, 0)
        msg = (f"target '{args.ssid}': {len(targets)} APs · LOCKED to busiest "
               f"AP {b} ch {ch}@{w or 20}MHz ({rv:.0f} dBm, {apdata} data) · "
               f"{assoc} device(s) confirmed")
        if apdata < 5:
            msg += ("  ·  this AP has almost no client traffic — few/no devices "
                    "are active on it right now (nothing to rank; not a bug)")
        return msg + sec_note
    base = (f"target '{args.ssid}': {len(targets)} AP(s) on ch "
            f"{','.join(map(str, chans)) or '?'} · {assoc} confirmed on it "
            f"({total} stations heard in total)")
    if assoc == 0 and len(chans) > 2:
        base += ("  ·  spread thin across many channels — add "
                 "--lock-strongest (or --channel N) to park on the nearest AP")
    return base + sec_note


def diag_line(tracker, args):
    """Data-frame X-ray, shown under the status line when focusing an SSID."""
    if not args.ssid:
        return None
    d = tracker.diag
    return (f"[x-ray] data dir: up={d['tods']} down={d['fromds']} "
            f"wds/other={d['wds']} · client-addr: unicast={d['cli_uni']} "
            f"group={d['cli_mc']} · unicast-clients-on-target-AP={d['cli_target']}")


def run_ui_plain(tracker, oui, args, stop_event):
    try:
        while not stop_event.is_set():
            render_plain(tracker, oui, args)
            stop_event.wait(args.refresh)
    except KeyboardInterrupt:
        stop_event.set()


def run_ui_rich(tracker, oui, args, stop_event):
    from rich.live import Live
    from rich.table import Table
    from rich.console import Console

    console = Console()
    cols = _columns(args)

    def build():
        s = tracker.stats()
        hop = "hopping" if args.hop else f"ch {args.channel or 'lock'}"
        rankdesc = (f"weighted/{args.half_life:g}s" if args.rank_by == "weighted"
                    else f"{args.rank_by}/{'all' if not args.window else str(int(args.window)) + 's'}")
        title = (f"wifi_proximity v{__version__} · {args.iface} · {hop} · "
                 f"rank={rankdesc} · "
                 f"stations={s['stations']} aps={s['aps']} "
                 f"frames={s['frames']} data={s['data']} "
                 f"up={_fmt_age(s['elapsed'])}")
        table = Table(title=title, expand=False, header_style="bold cyan")
        for _, head, _w in cols:
            justify = "right" if head in ("RSSI", "N", "#", "~DIST", "±dB") \
                else "left"
            table.add_column(head, justify=justify, no_wrap=True)
        rows = tracker.snapshot(include_aps=args.show_aps,
                                max_age=args.max_age,
                                only_bssids=args.only_bssids)[:args.top]
        for i, st in enumerate(rows, 1):
            f = _row_fields(st, oui, args, i)
            style = "bold green" if i == 1 else None
            table.add_row(*[f.get(k, "") for k, _, _ in cols], style=style)
        fstat = focus_status(tracker, args)
        dline = diag_line(tracker, args)
        cap = " ".join(x for x in (fstat, dline) if x)
        if cap:
            table.caption = cap
        elif not rows:
            table.caption = "listening… no stations yet"
        return table

    try:
        with Live(build(), console=console, refresh_per_second=4,
                  screen=True) as live:
            while not stop_event.is_set():
                live.update(build())
                stop_event.wait(args.refresh)
    except KeyboardInterrupt:
        stop_event.set()


# ===========================================================================
# Reporting
# ===========================================================================

def export_report(tracker, oui, args):
    rows = tracker.snapshot(include_aps=args.show_aps,
                            only_bssids=args.only_bssids)
    records = []
    for i, st in enumerate(rows, 1):
      with st.lock:      # capture thread may still be writing to this station
        records.append({
            "rank": i,
            "mac": st.mac,
            "vendor": st.vendor or oui.lookup(st.mac),
            "ema_rssi_dbm": None if st.ema_rssi is None else round(st.ema_rssi, 1),
            "last_rssi_dbm": st.last_rssi,
            "hostname": st.hostname,
            "ip": st.ip,
            "os_hint": st.os_hint,
            "model": st.model,
            "services": sorted(st.services),
            "nbios_name": st.nbios,
            "dhcp_fingerprint": st.dhcp_fp,
            "user_agent": st.user_agent,
            "talks_to": sorted(st.domains),
            "network": st.network,
            "bssid": st.bssid,
            "probed_ssids": sorted(st.ssids),
            "channels": sorted(st.channels),
            "packets": st.packets,
            "is_ap": st.is_ap,
            "fingerprint": st.fingerprint,
            "first_seen": datetime.fromtimestamp(
                st.first_seen, timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(
                st.last_seen, timezone.utc).isoformat(),
        })
    path = args.output
    if path.endswith(".csv"):
        flat = [dict(r, probed_ssids="|".join(r["probed_ssids"]),
                     channels="|".join(map(str, r["channels"])),
                     services="|".join(r["services"]),
                     talks_to="|".join(r["talks_to"])) for r in records]
        with open(path, "w", newline="") as fh:
            if flat:
                w = csv.DictWriter(fh, fieldnames=list(flat[0].keys()))
                w.writeheader()
                w.writerows(flat)
    else:
        with open(path, "w") as fh:
            json.dump({"generated": datetime.now(timezone.utc).isoformat(),
                       "interface": args.iface, "stations": records},
                      fh, indent=2)
    print(f"\nWrote report for {len(records)} devices -> {path}")


# ===========================================================================
# Self-test (no scapy / rich / hardware needed)
# ===========================================================================

def selftest():
    ok = 0
    fail = 0

    def check(name, cond):
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  PASS  {name}")
        else:
            fail += 1
            print(f"  FAIL  {name}")

    print("Running self-test (pure logic, no hardware)…\n")

    # MAC helpers
    check("normalize_mac", normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff")
    check("normalize_mac bad", normalize_mac("nope") is None)
    check("multicast detect", mac_is_multicast("01:00:5e:00:00:fb") is True)
    check("unicast detect", mac_is_multicast("b8:27:eb:12:34:56") is False)
    check("randomized MAC (U/L bit)", mac_is_locally_administered("b2:27:eb:00:00:01") is True)
    check("global MAC", mac_is_locally_administered("b8:27:eb:00:00:01") is False)
    check("oui_key", oui_key("b8:27:eb:12:34:56") == "B827EB")

    # channel math
    check("chan 2.4GHz #6", freq_to_channel(2437) == 6)
    check("chan 2.4GHz #1", freq_to_channel(2412) == 1)
    check("chan 14", freq_to_channel(2484) == 14)
    check("chan 5GHz #36", freq_to_channel(5180) == 36)
    check("chan 6GHz", freq_to_channel(5955) == 1)

    # sparkline
    sp = sparkline([-90, -80, -70, -60, -50], 5)
    check("sparkline width", len(sp) == 5)
    check("sparkline monotone", sp[0] == "▁" and sp[-1] == "█")

    # distance estimate monotonic (stronger RSSI -> closer)
    near = estimate_distance_m(-40)
    far = estimate_distance_m(-80)
    check("distance monotonic", near < far)

    # ip neigh parsing
    neigh = parse_ip_neigh(
        "192.168.1.20 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.99 dev wlan0  FAILED\n"
        "192.168.1.5 dev wlan0 lladdr 11:22:33:44:55:66 STALE\n")
    check("ip neigh parse count", len(neigh) == 2)
    check("ip neigh mapping", neigh.get("aa:bb:cc:dd:ee:ff") == "192.168.1.20")
    check("ip neigh drops FAILED", "192.168.1.99" not in neigh.values())

    # arp -a parsing
    arp = parse_arp_a("router (192.168.1.1) at 00:11:22:33:44:55 [ether] on wlan0")
    check("arp -a parse", arp.get("00:11:22:33:44:55") == "192.168.1.1")

    # OUI resolver: file parse + lookup + built-in + randomized
    tmp = "/tmp/_manuf_test.txt"
    with open(tmp, "w") as fh:
        fh.write("# comment\n")
        fh.write("00:11:22\tAcmeCorp\tAcme Corporation Inc\n")
        fh.write("B8:27:EB/24\tRaspberryPiFile\n")
    oui = OuiResolver()
    n = oui.load_file(tmp)
    check("oui file loaded", n == 2)
    check("oui file lookup", oui.lookup("00:11:22:aa:bb:cc") == "AcmeCorp")
    check("oui file beats builtin", oui.lookup("b8:27:eb:00:00:01") == "RaspberryPiFile")
    check("oui builtin fallback", OuiResolver().lookup("08:00:27:00:00:01") == "VirtualBox")
    check("oui randomized note", "randomized" in OuiResolver().lookup("b2:27:eb:00:00:01"))
    os.remove(tmp)

    # Tracker: RSSI attribution, EMA, ranking, backfill, L3 correlation
    tr = Tracker(alpha=0.5)
    tr.register_bssid("de:ad:be:ef:00:01", "HomeNet")
    tr.observe("aa:aa:aa:aa:aa:aa", rssi=-70, channel=6, bssid="de:ad:be:ef:00:01")
    tr.observe("aa:aa:aa:aa:aa:aa", rssi=-50, channel=6)   # got closer
    tr.observe("12:34:56:78:9a:bc", rssi=-80, channel=6)   # a farther station
    tr.observe("01:00:5e:00:00:01", rssi=-40)              # multicast -> ignored
    snap = tr.snapshot()
    check("multicast ignored", all(s.mac != "01:00:5e:00:00:01" for s in snap))
    check("two stations tracked", len(snap) == 2)
    check("closest ranked first", snap[0].mac == "aa:aa:aa:aa:aa:aa")
    check("EMA between samples", -70 < snap[0].ema_rssi < -50)
    check("bssid->ssid backfill", snap[0].network == "HomeNet")
    tr.set_l3(mac="aa:aa:aa:aa:aa:aa", ip="192.168.1.20", hostname="my-phone")
    snap = tr.snapshot()
    check("L3 ip attach", snap[0].ip == "192.168.1.20")
    check("L3 hostname attach", snap[0].hostname == "my-phone")

    # AP hidden unless requested
    tr.observe("cc:cc:cc:cc:cc:cc", rssi=-30, is_ap=True)
    check("AP hidden by default", all(not s.is_ap for s in tr.snapshot()))
    check("AP shown when asked",
          any(s.is_ap for s in tr.snapshot(include_aps=True)))
    # even though AP has strongest RSSI, it must not steal rank #1 of stations
    check("AP excluded from station ranking",
          tr.snapshot()[0].mac == "aa:aa:aa:aa:aa:aa")

    # --- association inference (the bug that produced "0 confirmed") -------
    AP = "5c:e9:31:4b:5a:61"
    CL = "de:ad:00:00:00:07"
    known = lambda m: normalize_mac(m) == AP          # noqa: E731
    b, stn, txap = infer_association(True, False, AP, CL, "ff:ff:ff:ff:ff:ff", known)
    check("to-DS: bssid=a1, station=a2", b == AP and stn == CL and not txap)
    b, stn, txap = infer_association(False, True, CL, AP, "00:11:22:33:44:55", known)
    check("from-DS: bssid=a2, station=a1", b == AP and stn == CL and txap)
    # the real-world failure: DS bits misread so BOTH look set (WDS-ish).
    # The beacon-verified fallback must still recover the association.
    b, stn, txap = infer_association(True, True, AP, CL, "00:11:22:33:44:55", known)
    check("garbled DS bits still resolve via known BSSID",
          b == AP and stn == CL and not txap)
    # with no beacon knowledge we still fall back to the DS-bit reading
    b, stn, txap = infer_association(True, False, AP, CL, "00:11:22:33:44:55", None)
    check("no beacon knowledge -> DS bits used", b == AP and stn == CL)
    # protected-frame guard (don't parse encrypted payloads as L3)
    check("protected bit set -> True", frame_is_protected(0x41) is True)
    check("unprotected -> False", frame_is_protected(0x01) is False)
    check("valid ipv4", valid_ipv4("192.168.1.20") is True)
    check("reject 0.x ip", valid_ipv4("0.1.2.3") is False)
    check("reject multicast ip", valid_ipv4("224.0.0.251") is False)
    check("reject junk ip", valid_ipv4("not.an.ip.x") is False)
    # set_info must drop a bogus IP rather than attaching it
    tb = Tracker()
    tb.observe("de:ee:ee:ee:ee:01", rssi=-50)
    tb.set_info(mac="de:ee:ee:ee:ee:01", ip="999.1.2.3")
    check("bogus IP dropped", tb.stations["de:ee:ee:ee:ee:01"].ip is None)

    # end-to-end: a client's uplink frame must register as associated
    ta = Tracker()
    ta.observe(AP, rssi=-36, channel=149, is_ap=True)
    ta.register_bssid(AP, "Amity-wifi")
    b, stn, txap = infer_association(True, True, AP, CL, "ff:ff:ff:ff:ff:ff",
                                     ta.is_known_bssid)
    ta.observe(stn, rssi=-58, channel=149, bssid=b)
    check("client confirmed on target network",
          ta.count_associated("Amity-wifi") == 1)

    # --- security classification (open vs OWE vs WPA) ---------------------
    check("sec OPEN (no privacy, no RSN)", classify_security(False, []) == "OPEN")
    check("sec privacy-only treated as OPEN (not WEP)",
          classify_security(True, []) == "OPEN")
    check("sec OWE (akm 18)", classify_security(False, [18]) == "OWE")
    check("sec WPA3 (akm 8)", classify_security(True, [8]) == "WPA3-SAE")
    check("sec WPA2-PSK (akm 2)", classify_security(True, [2]) == "WPA2-PSK")
    check("sec WPA2-Ent (akm 1)", classify_security(True, [1]) == "WPA2-Ent")
    check("sec WPA1 vendor IE", classify_security(True, [], True) == "WPA")
    # RSN element AKM extraction: ver + group + 1 pairwise + 1 akm(PSK)
    rsn = (b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" +
           b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x02")
    check("RSN AKM parse -> PSK", _rsn_akms(rsn) == [2])
    ts = Tracker()
    ts.observe("aa:00:00:00:00:31", rssi=-40, channel=6, is_ap=True)
    ts.register_bssid("aa:00:00:00:00:31", "FreeWiFi")
    ts.set_security("aa:00:00:00:00:31", "OPEN")
    check("security_for_ssid", ts.security_for_ssid("FreeWiFi") == "OPEN")

    # --- channel width / frequency tuning (decoding HT/VHT data frames) ----
    check("chan->freq 2.4", channel_to_freq(6) == 2437)
    check("chan->freq 5G ch149", channel_to_freq(149) == 5745)
    check("chan->freq ch36", channel_to_freq(36) == 5180)
    check("width 80 uses set freq",
          width_iw_args("wlan0", 149, 80, 155) ==
          ["iw", "dev", "wlan0", "set", "freq", "5745", "80", "5775"])
    check("width 40 uses HT40+",
          width_iw_args("wlan0", 36, 40, None, "+")[-1] == "HT40+")
    check("width 20 falls back to set channel",
          width_iw_args("wlan0", 6) ==
          ["iw", "dev", "wlan0", "set", "channel", "6"])
    check("unknown channel -> None", width_iw_args("wlan0", 999) is None)

    # radio params recorded per-AP and read back for tuning
    trw = Tracker()
    trw.observe("aa:00:00:00:00:21", rssi=-40, channel=149, is_ap=True)
    trw.set_radio("aa:00:00:00:00:21", 80, 155, None)
    check("radio width stored", trw.radio_for("aa:00:00:00:00:21") == (80, 155, None))

    # --- nearest-AP lock + association counting (multi-AP accuracy) --------
    tl = Tracker(rank_by="median", window_s=None, min_samples=1)
    tl.register_bssid("aa:00:00:00:00:11", "Campus")
    tl.register_bssid("aa:00:00:00:00:12", "Campus")
    for v in (-70, -71, -70):                       # far AP on ch 1
        tl.observe("aa:00:00:00:00:11", rssi=v, channel=1, is_ap=True)
    for v in (-42, -41, -43):                       # NEAR AP on ch 36
        tl.observe("aa:00:00:00:00:12", rssi=v, channel=36, is_ap=True)
    best = tl.strongest_ap_for_ssid("Campus")
    check("strongest AP picked", best is not None and best[0] == "aa:00:00:00:00:12")
    check("lock channel = nearest AP's", best[1] == 36)
    # busiest-AP lock: the FAR AP (ch1) has all the client data, so camp there
    for _ in range(30):
        tl.note_data("aa:00:00:00:00:11")          # 30 data frames on far AP
    b2 = tl.best_ap_for_ssid("Campus")
    check("busiest AP beats strongest when it has the clients",
          b2[0] == "aa:00:00:00:00:11" and b2[1] == 1 and b2[3] == 30)
    # with zero data anywhere, best_ap falls back to strongest signal
    tl2 = Tracker()
    tl2.register_bssid("aa:00:00:00:00:41", "Q")
    tl2.register_bssid("aa:00:00:00:00:42", "Q")
    tl2.observe("aa:00:00:00:00:41", rssi=-70, channel=1, is_ap=True)
    tl2.observe("aa:00:00:00:00:42", rssi=-40, channel=6, is_ap=True)
    check("no-data fallback = strongest",
          tl2.best_ap_for_ssid("Q")[0] == "aa:00:00:00:00:42")
    tl.observe("de:00:00:00:00:91", rssi=-55, channel=36, bssid="aa:00:00:00:00:12")
    check("associated count", tl.count_associated("Campus") == 1)
    tl.observe("de:00:00:00:00:92", rssi=-50, channel=36)   # no bssid -> not assoc
    check("unassociated not counted", tl.count_associated("Campus") == 1)

    # --- SSID focus: multiple APs (mesh), connected-only, channel narrowing --
    tf = Tracker()
    tf.register_bssid("aa:00:00:00:00:01", "HomeNet")   # AP 1
    tf.register_bssid("aa:00:00:00:00:02", "HomeNet")   # AP 2 (mesh, 5 GHz)
    tf.register_bssid("ac:00:00:00:00:03", "OtherNet")  # a different network
    tf.observe("aa:00:00:00:00:01", rssi=-40, channel=6, is_ap=True)
    tf.observe("aa:00:00:00:00:02", rssi=-45, channel=36, is_ap=True)
    tf.observe("ac:00:00:00:00:03", rssi=-50, channel=11, is_ap=True)
    tf.observe("de:00:00:00:00:aa", rssi=-55, channel=6, bssid="aa:00:00:00:00:01")
    tf.observe("de:00:00:00:00:bb", rssi=-60, channel=36, bssid="aa:00:00:00:00:02")
    tf.observe("de:00:00:00:00:cc", rssi=-52, channel=11, bssid="ac:00:00:00:00:03")
    tf.observe("de:00:00:00:00:dd", rssi=-58, channel=6, ssid="HomeNet")  # only probed
    targets = tf.bssids_for_ssid("HomeNet")
    check("ssid->bssids (mesh set)",
          targets == {"aa:00:00:00:00:01", "aa:00:00:00:00:02"})
    check("ssid->channels (sweep narrowing)",
          tf.channels_for_ssid("HomeNet") == {6, 36})
    macs = {s.mac for s in tf.snapshot() if s.bssid in targets}
    check("ssid filter keeps both mesh clients",
          {"de:00:00:00:00:aa", "de:00:00:00:00:bb"} <= macs)
    check("ssid filter drops other network", "de:00:00:00:00:cc" not in macs)
    check("ssid filter drops probe-only (not connected)",
          "de:00:00:00:00:dd" not in macs)

    # --- richer enrichment parsers (pure) --------------------------------
    inst, svc = _mdns_friendly("Akshats-iPhone._companion-link._tcp.local")
    check("mdns friendly name", inst == "Akshats-iPhone" and svc == "companion-link")
    check("dhcp vendor->OS (android)", _dhcp_vendor_os("android-dhcp-13") == "Android")
    check("dhcp vendor->OS (msft)", _dhcp_vendor_os("MSFT 5.0") == "Windows")
    check("txt model=", _txt_model([b"md=Chromecast", b"ic=/setup"]) == "Chromecast")
    check("http header UA",
          _http_header(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Dalvik/2.1\r\n\r\n",
                       b"User-Agent") == "Dalvik/2.1")

    # NetBIOS name encode/decode round-trip ("PC" -> encoded -> back)
    def nb_encode(name):
        name = name.ljust(16)[:16]
        enc = bytearray()
        for ch in name.encode("ascii"):
            enc.append(0x41 + (ch >> 4))
            enc.append(0x41 + (ch & 0x0F))
        return bytes(12) + bytes([0x20]) + bytes(enc) + b"\x00"
    check("netbios decode", (_parse_netbios(nb_encode("LAPTOP")) or "").startswith("LAPTOP"))

    # WPS TLV parse (device name + manufacturer/model)
    def wps(t, v):
        return bytes([t >> 8, t & 0xFF, 0, len(v)]) + v
    blob = (wps(0x1011, b"Akshat-PC") + wps(0x1021, b"Dell")
            + wps(0x1023, b"XPS13"))
    tw = Tracker()
    tw.observe("de:11:11:11:11:11", rssi=-40)
    _parse_wps_tlvs(blob, tw, "de:11:11:11:11:11")
    ws = tw.stations["de:11:11:11:11:11"]
    check("wps device name", ws.hostname == "Akshat-PC")
    check("wps model", "Dell" in (ws.model or "") and "XPS13" in (ws.model or ""))

    # set_info merges: services accumulate, best_device picks model
    tm = Tracker()
    tm.observe("de:22:22:22:22:22", rssi=-55)
    tm.set_info(mac="de:22:22:22:22:22", service="airplay")
    tm.set_info(mac="de:22:22:22:22:22", service="chromecast", model="AppleTV6,2")
    ms = tm.stations["de:22:22:22:22:22"]
    check("services accumulate", ms.services == {"airplay", "chromecast"})
    check("best_device prefers model", ms.best_device() == "AppleTV6,2")
    tm.set_info(mac="de:22:22:22:22:22", domain="spotify.com")
    check("domains captured", "spotify.com" in ms.domains)

    # --- robust ranking + confidence (accuracy) --------------------------
    check("percentile median", _percentile([1, 2, 3, 4, 5], 50) == 3)
    check("percentile p80", abs(_percentile([-90, -80, -70, -60, -50], 80)
                                 - (-58.0)) < 0.001)
    rk = Tracker(rank_by="median", window_s=None, min_samples=5)
    # A: many samples, median ~ -60 (steady, close). B: one lucky -30 spike.
    for v in (-62, -60, -61, -59, -60, -60, -61):
        rk.observe("de:aa:aa:aa:aa:a1", rssi=v)
    rk.observe("de:bb:bb:bb:bb:b2", rssi=-30)          # single strong outlier
    ordered = rk.snapshot()
    check("robust rank beats lucky spike",
          ordered[0].mac == "de:aa:aa:aa:aa:a1")
    stA = rk.stations["de:aa:aa:aa:aa:a1"]
    check("median rank_value", -62 <= stA.rank_value("median", None) <= -59)
    check("confident has enough samples", stA.sample_count() >= 5)
    check("spike marked low-confidence",
          rk.stations["de:bb:bb:bb:bb:b2"].sample_count() < 5)
    check("max stat picks strongest",
          stA.rank_value("max", None) == -59)

    # --- signal-first ranking + reactivity (the fix for laptop->last) ------
    # A strong device with only a FEW samples must outrank a weak device with
    # many samples (physically closer = top), as long as it has >=2 samples.
    rs = Tracker(rank_by="weighted", half_life=6.0)
    for _ in range(50):
        rs.observe("de:00:00:00:00:f0", rssi=-70)      # far, well-sampled
    rs.observe("de:00:00:00:00:f1", rssi=-20)          # near, only...
    rs.observe("de:00:00:00:00:f1", rssi=-21)          # ...2 samples
    order = rs.snapshot()
    check("strong few-sample device ranks above weak many-sample",
          order[0].mac == "de:00:00:00:00:f1")
    # a single-sample device is still parked at the bottom (anti-fluke)
    rs.observe("de:00:00:00:00:f2", rssi=-5)           # 1 sample only
    order = rs.snapshot()
    check("single-sample fluke stays last", order[-1].mac == "de:00:00:00:00:f2")

    # weighted estimate reacts: old far readings + fresh near readings should
    # pull the estimate toward 'near', unlike a plain median.
    react = Station("de:00:00:00:00:f3", lock=threading.RLock())
    now = time.time()
    with react.lock:
        for k in range(20):
            react.samples.append((now - 20 + k * 0.2, -75))   # older: far
        for k in range(6):
            react.samples.append((now - 1 + k * 0.1, -35))    # last ~1s: near
    w = react.weighted_rssi(3.0)
    med = react.rank_value("median", None)
    check("weighted reacts toward recent", w > med and w > -60)

    # --- concurrency: capture thread writing while UI thread reads ---------
    # This reproduces the "deque mutated during iteration" crash. With the
    # shared lock it must run clean.
    class _A:   # minimal args stand-in for _row_fields
        window = 5
        rank_by = "median"
        min_samples = 3
        estimate_distance = False
        ssid = None
    tcc = Tracker(window_s=5)
    stop = threading.Event()
    errbox = []

    def _writer():
        i = 0
        while not stop.is_set():
            tcc.observe("de:cc:cc:cc:cc:0%d" % (i % 6), rssi=-40 - (i % 30),
                        channel=(i % 11) + 1, bssid="aa:bb:cc:dd:ee:0%d" % (i % 3))
            i += 1

    def _reader():
        try:
            for _ in range(4000):
                for stt in tcc.snapshot():
                    _row_fields(stt, oui, _A, 1)
                    stt.recent_list(); stt.channels_list()
        except Exception as e:                       # noqa: BLE001
            errbox.append(repr(e))
    threads = [threading.Thread(target=_writer) for _ in range(3)]
    threads.append(threading.Thread(target=_reader))
    for t in threads:
        t.start()
    threads[-1].join(timeout=15)
    stop.set()
    for t in threads[:-1]:
        t.join(timeout=2)
    check("concurrent read/write: no crash", not errbox)
    if errbox:
        print("     race error:", errbox[0])

    print(f"\n{ok} passed, {fail} failed")
    return 0 if fail == 0 else 1


# ===========================================================================
# CLI
# ===========================================================================

DEFAULT_HOP_CHANNELS = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10,
                        36, 40, 44, 48, 149, 153, 157, 161]


def build_argparser():
    p = argparse.ArgumentParser(
        description="Passive Wi-Fi station proximity + recon (monitor mode).",
        epilog="Passive by default. Use only on networks/devices you are "
               "authorized to monitor.")
    p.add_argument("iface", nargs="?",
                   help="monitor-mode interface (e.g. wlan0mon)")
    p.add_argument("--alpha", type=float, default=0.3,
                   help="EMA smoothing factor for RSSI (0<a<=1, default 0.3; "
                        "lower = smoother/slower)")
    p.add_argument("--refresh", type=float, default=1.0,
                   help="UI refresh interval seconds (default 1.0)")
    p.add_argument("--top", type=int, default=None,
                   help="show at most N stations (default 10 with --ssid, "
                        "else 30)")
    p.add_argument("--max-age", type=float, default=180, dest="max_age",
                   help="hide stations not seen for N seconds (default 180; "
                        "0 = never hide)")

    acc = p.add_argument_group("accuracy / ranking")
    acc.add_argument("--rank-by", dest="rank_by", default="weighted",
                     choices=["weighted", "median", "ema", "mean", "p80", "max"],
                     help="proximity statistic (default 'weighted' — recency-"
                          "weighted, reacts fast as devices move; 'median' is "
                          "steadier but slower; 'p80'/'max' favor best-case "
                          "signal)")
    acc.add_argument("--half-life", type=float, default=6.0, dest="half_life",
                     help="for 'weighted': seconds for a reading's influence to "
                          "halve (default 6; lower = snappier, higher = smoother)")
    acc.add_argument("--window", type=float, default=30,
                     help="sample window for median/mean/spread/N (default 30; "
                          "0 = all history). Does not affect 'weighted'.")
    acc.add_argument("--min-samples", type=int, default=4, dest="min_samples",
                     help="below this many samples a device's RSSI shows a '?' "
                          "(display only — it is NOT demoted; default 4)")
    acc.add_argument("--accurate", action="store_true",
                     help="steadier preset: longer dwell per channel + a bit "
                          "more smoothing (half-life 8s). Still reacts to "
                          "movement, just less jittery.")

    ch = p.add_argument_group("channel")
    ch.add_argument("--channel", type=int,
                    help="lock to a single channel (best for one target net)")
    ch.add_argument("--hop", action="store_true",
                    help="hop across channels to discover everything")
    ch.add_argument("--dwell", type=float, default=0.20,
                    help="seconds per channel while hopping (default 0.20; "
                         "lower = faster sweep, but catches fewer packets)")
    ch.add_argument("--hop-channels", type=str,
                    help="comma-separated channels to hop (default common set)")
    ch.add_argument("--lock-strongest", action="store_true",
                    dest="lock_strongest",
                    help="with --ssid: after a short scan, LOCK the radio to the "
                         "channel of that network's nearest (strongest) AP. On a "
                         "big multi-AP network this is the accuracy win — 100%% "
                         "of samples on one channel instead of ~8%% across a "
                         "dozen. Re-checks periodically so walking around works.")
    ch.add_argument("--lock-after", type=float, default=20.0, dest="lock_after",
                    help="seconds to scan before locking (default 20)")
    ch.add_argument("--remon", action="store_true",
                    help="(now the default) re-apply broad monitor-capture "
                         "flags incl. otherbss. Kept for compatibility.")
    ch.add_argument("--width", type=int, choices=[20, 40, 80, 160],
                    help="force capture channel width in MHz. By default the "
                         "AP's real width is read from its beacon — important, "
                         "because a 20MHz capture cannot decode the 80MHz "
                         "HT/VHT frames that carry actual client traffic.")

    fil = p.add_argument_group("filter")
    fil.add_argument("--ssid",
                     help="show ONLY devices connected to APs broadcasting this "
                          "exact network name (all its APs/mesh nodes). Auto-"
                          "enables hopping and narrows the sweep to that "
                          "network's channels, so it's faster too.")
    fil.add_argument("--bssid", help="only show stations on this AP BSSID "
                                      "(comma-separated ok)")
    fil.add_argument("--show-aps", action="store_true", dest="show_aps",
                     help="also list access points, not just client stations")

    en = p.add_argument_group("enrichment")
    en.add_argument("--no-passive", action="store_false", dest="enrich_passive",
                    help="turn OFF passive plaintext parsing (DHCP/mDNS/SSDP/"
                         "NetBIOS/HTTP/SNI). On by default — harvests whatever "
                         "devices leak in the clear on OPEN networks.")
    en.add_argument("--enrich-local", action="store_true", dest="enrich_local",
                    help="correlate MAC->IP->hostname via THIS host's neighbour "
                         "table (works on WPA networks you're joined to)")
    en.add_argument("--oui-file", dest="oui_file",
                    help="path to a Wireshark 'manuf' or IEEE 'oui.txt' file")
    p.set_defaults(enrich_passive=True)

    dist = p.add_argument_group("distance estimate (rough!)")
    dist.add_argument("--estimate-distance", action="store_true",
                      dest="estimate_distance",
                      help="add a very rough distance column from RSSI")
    dist.add_argument("--tx-power", type=float, default=-40, dest="tx_power",
                      help="expected RSSI at 1m (default -40)")
    dist.add_argument("--path-loss", type=float, default=2.5, dest="path_loss",
                      help="path-loss exponent (default 2.5)")

    out = p.add_argument_group("output")
    out.add_argument("--output", help="write JSON (.json) or CSV (.csv) report "
                                       "on exit")
    out.add_argument("--no-rich", action="store_true", dest="no_rich",
                     help="force the plain-text UI even if rich is installed")

    setup = p.add_argument_group("setup (this script handles monitor mode)")
    setup.add_argument("--no-setup", action="store_true", dest="no_setup",
                       help="do NOT auto-enable monitor mode; assume the "
                            "interface is already set up")
    setup.add_argument("--kill", action="store_true",
                       help="run `airmon-ng check kill` first to stop "
                            "NetworkManager etc. (recommended if capture is empty)")
    setup.add_argument("--restore", action="store_true",
                       help="put the interface back to managed mode and exit")
    setup.add_argument("--install-deps", action="store_true",
                       dest="install_deps",
                       help="pip-install scapy + rich for this Python, then run")

    p.add_argument("--selftest", action="store_true",
                   help="run built-in logic tests and exit (no hardware needed)")
    return p


def main(argv=None):
    args = build_argparser().parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.iface:
        print("error: an interface is required (e.g. wlan0). "
              "Try --help or --selftest.", file=sys.stderr)
        return 2

    is_root = (os.geteuid() == 0)

    # --restore: flip the card back to normal Wi-Fi and quit (needs no scapy).
    if args.restore:
        if not is_root:
            print("error: --restore needs root (use sudo).", file=sys.stderr)
            return 1
        restore_managed(args.iface)
        print(f"{args.iface} set back to managed mode. "
              f"You may need: sudo systemctl restart NetworkManager")
        return 0

    # --install-deps: pull in scapy (+rich) for THIS interpreter, then continue.
    if args.install_deps:
        ok = pip_install(["scapy", "rich"])
        print("dependencies installed." if ok else
              "warning: dependency install failed — see messages above.")

    if not is_root:
        print("error: capturing needs root. Re-run with sudo, e.g.:\n"
              f"    sudo python3 {os.path.basename(sys.argv[0])} {args.iface}",
              file=sys.stderr)
        return 1

    # Fail early & clearly if scapy is missing, BEFORE the full-screen UI
    # starts (otherwise the alt-screen can wipe the error and it looks like
    # nothing happened).
    try:
        import scapy  # noqa: F401
    except Exception:
        print("\nFATAL: scapy is not installed — it is required for capture.\n"
              "  Fix it in one shot by re-running with --install-deps:\n"
              f"      sudo python3 {os.path.basename(sys.argv[0])} "
              f"{args.iface} --install-deps\n"
              "  Or manually:  sudo pip3 install scapy   (nicer UI: rich)\n",
              file=sys.stderr)
        return 1

    # Make sure the interface is in monitor mode. Do it ourselves unless the
    # user opted out with --no-setup. This folds in the old setup_monitor.sh.
    if not args.no_setup:
        state = iface_is_monitor(args.iface)
        if state is None:
            print(f"[*] note: couldn't verify monitor mode on {args.iface} "
                  "(is 'iw' installed?). Continuing anyway.")
        else:
            # ALWAYS (re)apply the broad capture flags, incl. 'otherbss'. This is
            # what lets client/unicast frames through — without it many drivers
            # capture only broadcast, so the ranking table stays empty. Harmless
            # if the card is already set up this way.
            verb = ("enabling monitor mode" if state is False
                    else "applying broad capture flags")
            print(f"[*] {verb} on {args.iface}"
                  + (" (killing interfering processes)…" if args.kill else "…"))
            ok, msg = enable_monitor(args.iface, do_kill=args.kill)
            if not ok:
                print(f"FATAL: could not set monitor mode: {msg}\n"
                      "  Try adding --kill, or set it up manually:\n"
                      f"    sudo ip link set {args.iface} down && "
                      f"sudo iw dev {args.iface} set monitor otherbss control && "
                      f"sudo ip link set {args.iface} up", file=sys.stderr)
                return 1
            print(f"[*] {msg}.")

    # normalize filters
    args.only_bssids = None
    if args.bssid:
        args.only_bssids = {normalize_mac(b) for b in args.bssid.split(",")}
        args.only_bssids.discard(None)
    if args.max_age == 0:
        args.max_age = None
    # Steadier preset: longer dwell (more samples/channel) + a bit more
    # smoothing, but still recency-weighted so it reacts to movement.
    if args.accurate:
        if args.dwell <= 0.20:
            args.dwell = 0.5
        args.half_life = max(args.half_life, 8.0)
        if args.max_age and args.max_age < 180:
            args.max_age = 180
    if args.window == 0:
        args.window = None
    # Default to a short list when focusing on one network (accuracy > breadth).
    if args.top is None:
        args.top = 10 if args.ssid else 30
    # Focusing on a network needs to find its channels: auto-enable hopping
    # unless the user pinned a channel or already asked to hop.
    if args.ssid and not args.channel and not args.hop:
        args.hop = True

    oui = OuiResolver()
    if args.oui_file:
        try:
            n = oui.load_file(args.oui_file)
            print(f"loaded {n} OUI entries from {args.oui_file}")
        except Exception as e:
            print(f"warning: could not load OUI file: {e}", file=sys.stderr)

    tracker = Tracker(alpha=args.alpha, rank_by=args.rank_by,
                      window_s=args.window, min_samples=args.min_samples,
                      half_life=args.half_life)
    stop_event = threading.Event()

    # --ssid: show ONLY stations actually associated to an AP broadcasting this
    # exact network name. We learn the network's BSSID set from beacons as they
    # arrive (covering multiple APs / mesh / repeaters that share the name), and
    # keep a station only if its associated BSSID is in that set. Probing for the
    # name is NOT enough — the device must be connected.
    if args.ssid:
        _orig_snapshot = tracker.snapshot
        wanted = args.ssid

        def _filtered(**kw):
            rows = _orig_snapshot(**kw)
            targets = tracker.bssids_for_ssid(wanted)
            if not targets:
                return []            # network not spotted yet (finding its APs)
            return [s for s in rows if s.bssid in targets]
        tracker.snapshot = _filtered  # type: ignore

    def _stop(*_):
        stop_event.set()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    threads = []
    cap = threading.Thread(target=run_capture,
                           args=(tracker, args.iface, oui, stop_event, args),
                           daemon=True)
    cap.start()
    threads.append(cap)

    if args.hop:
        chans = DEFAULT_HOP_CHANNELS
        if args.hop_channels:
            chans = [int(c) for c in args.hop_channels.split(",") if c.strip()]
        hop = threading.Thread(
            target=channel_hopper,
            args=(args.iface, chans, stop_event),
            kwargs={"dwell": args.dwell, "tracker": tracker,
                    "ssid": args.ssid,
                    "lock_strongest": args.lock_strongest,
                    "lock_after": args.lock_after,
                    "force_width": args.width},
            daemon=True)
        hop.start()
        threads.append(hop)
    elif args.channel:
        # honour --width here too (20MHz can't decode 80MHz client traffic)
        _set_channel(args.iface, args.channel, args.width)

    if args.enrich_local:
        enr = threading.Thread(target=local_enricher,
                               args=(tracker, stop_event), daemon=True)
        enr.start()
        threads.append(enr)

    use_rich = not args.no_rich
    if use_rich:
        try:
            import rich  # noqa
        except Exception:
            use_rich = False

    try:
        if use_rich:
            run_ui_rich(tracker, oui, args, stop_event)
        else:
            run_ui_plain(tracker, oui, args, stop_event)
    finally:
        stop_event.set()
        time.sleep(0.2)
        if args.output:
            try:
                export_report(tracker, oui, args)
            except Exception as e:
                print("could not write report:", e, file=sys.stderr)

    # Surface any capture-thread error AFTER the full-screen UI has torn down,
    # so it isn't wiped off the screen (this is why it looked like it "just
    # turned off" before).
    if tracker.errors:
        print("\n" + "=" * 60, file=sys.stderr)
        for msg in tracker.errors:
            print("CAPTURE STOPPED: " + msg, file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
