# wifi_proximity.py

Passive Wi-Fi station proximity and reconnaissance tool for Linux. Uses a monitor-mode adapter to rank nearby client devices by signal strength (RSSI) so the physically closest device floats to the top of a live-updating list. Each station is enriched with as much identifying information as can be gathered from the air: vendor (OUI), hostname, IP address, OS fingerprint, device model, mDNS/SSDP services, TLS SNI domains, and WPS data.

The tool is **passive by default** -- it only listens. Active features (deauth, RTS ping) are opt-in and clearly gated behind flags that print explicit warnings.

> **Use only on networks and devices you own or are explicitly authorized to test.**

## Features

**Proximity ranking** -- Stations are sorted by signal strength using one of seven ranking algorithms: time-weighted average (default), Kalman filter, median, EMA, mean, 80th-percentile, or max. A live sparkline shows each station's RSSI trend over time.

**5 GHz first** -- When hopping, the tool sweeps 5 GHz channels (UNII-1 and UNII-3) before 2.4 GHz so nearby devices on modern networks surface fast. DFS channels (52-144) are available with `--include-dfs`.

**VHT/HT channel widths** -- Fixed-channel captures open at the correct 40/80/160 MHz width with automatically derived center channels and HT40 offsets, so you see real data frames -- not just beacons.

**Passive enrichment** (always on) -- Extracts from captured traffic:
- DHCP hostname, vendor class (OS fingerprint), and requested IP
- ARP source/destination IP mappings
- mDNS service announcements (hostname, model, services)
- SSDP device descriptions (model, manufacturer)
- NetBIOS name queries
- DNS queries and responses
- TLS ClientHello SNI (visited domains)
- Initial TTL-based OS guess (Windows/Linux/macOS/iOS)
- IPv6 EUI-64 to MAC correlation
- 802.11 probe request SSIDs
- WPS device name, model, manufacturer
- Beacon security classification (Open/WEP/WPA/WPA2/WPA3/OWE)

**Active L3 enrichment** (`--enrich-local`) -- When your machine is joined to the same network on a separate managed interface, the tool actively resolves every captured MAC via: ARP sweep, mDNS (avahi-resolve), NetBIOS (nmblookup), and reverse DNS. This is the fast, reliable path for getting hostname and IP on open or your-own networks.

**Deauthentication** (`--deauth`) -- Forces client reassociation to leak DHCP/ARP/mDNS/probe data that is otherwise encrypted on WPA networks. Supports dual-adapter mode (one captures, one injects), channel-aware injection, per-client cooldown, smart targeting (only deauth un-enriched clients), and proximity-first ordering.

**Device classification** -- Heuristically labels each station as `computer`, `phone`, `iot`, or `?` based on accumulated signals, with `--only` filtering to show just one class.

**Distance estimation** -- Rough RSSI-to-meters conversion using a log-distance path-loss model (`--estimate-distance`).

**Output** -- Live terminal UI (rich table with color-coded RSSI, or plain ANSI fallback), CSV/JSON file export, and SQLite database logging with optional per-reading history.

**Self-contained** -- Single file, ~3700 lines, 183 built-in self-tests runnable with `--selftest` (no hardware, no dependencies needed for tests).

## Requirements

- **Linux** with a Wi-Fi adapter that supports monitor mode
- **Python 3.8+**
- **scapy** (required for capture) -- `pip install scapy`
- **rich** (optional, for the prettier live UI) -- `pip install rich`
- **iw**, **ip** (standard on most distros, used for interface setup)
- **Root privileges** (monitor-mode capture requires root)

For active L3 enrichment (`--enrich-local`), these are used if available: `arp-scan`, `avahi-resolve` (mDNS), `nmblookup` (NetBIOS).

For deauth / RTS ping: an injection-capable adapter (most Atheros and Realtek chipsets with the right driver).

## Installation

```bash
# Clone or copy the script
cp wifi_proximity.py /usr/local/bin/wifi_proximity.py
chmod +x /usr/local/bin/wifi_proximity.py

# Install dependencies
pip install scapy rich

# Or let the tool do it:
sudo python3 wifi_proximity.py wlan0 --install-deps
```

No virtual environment, no build step. It's one file.

## Quick start

```bash
# Basic: monitor everything on all bands (auto-enables monitor mode)
sudo python3 wifi_proximity.py wlan0

# 5 GHz only (sweeps UNII-1 + UNII-3, skips 2.4 GHz)
sudo python3 wifi_proximity.py wlan0 --band 5

# Lock to a specific channel at 80 MHz width
sudo python3 wifi_proximity.py wlan0 --channel 149 --width 80

# Filter to one network by SSID
sudo python3 wifi_proximity.py wlan0 --ssid "MyNetwork"

# Show only phones
sudo python3 wifi_proximity.py wlan0 --only phone
```

## Usage examples

### Passive recon with L3 enrichment (open network)

You're joined to the target network on `wlan1` (managed mode, has an IP) and using `wlan0` in monitor mode:

```bash
sudo python3 wifi_proximity.py wlan0 \
    --band 5 \
    --enrich-iface wlan1 \
    --ssid "CoffeeShop_5G"
```

This gives you hostname, IP, and OS for every device on the network, ranked by proximity. The ARP sweep fills MAC-to-IP mappings fast; mDNS and NetBIOS resolve hostnames.

### Dual-adapter deauth (authorized lab)

Two adapters: `wlan0` captures, `wlan1` injects deauth frames. Smart mode stops deauthing a client once its hostname/IP/OS are known:

```bash
sudo python3 wifi_proximity.py wlan0 wlan1 \
    --band 5 \
    --ssid "LabNetwork" \
    --deauth \
    --deauth-smart \
    --deauth-cooldown 120 \
    --enrich-iface eth0
```

### Single-adapter deauth

Works with one adapter (same interface captures and injects), but you lose packets during injection:

```bash
sudo python3 wifi_proximity.py wlan0 \
    --deauth \
    --deauth-interval 60 \
    --deauth-count 5
```

### Logging to SQLite

```bash
sudo python3 wifi_proximity.py wlan0 \
    --band 5 \
    --db recon.db \
    --db-history \
    --db-interval 5
```

`--db-history` writes a timestamped row per station per interval, so you can plot RSSI over time. Without it, only the latest state per MAC is stored.

### CSV/JSON snapshot export

```bash
# CSV
sudo python3 wifi_proximity.py wlan0 --output stations.csv

# JSON
sudo python3 wifi_proximity.py wlan0 --output stations.json
```

The file is overwritten on each UI refresh with the current station list.

### Distance estimation

```bash
sudo python3 wifi_proximity.py wlan0 \
    --estimate-distance \
    --tx-power -30 \
    --path-loss 2.8
```

Adds a rough meters column. Accuracy depends heavily on the environment; treat it as a relative indicator, not a measurement.

## CLI reference

### Positional

| Argument | Description |
|----------|-------------|
| `iface` | One or more monitor-mode interfaces. First = capture, last = inject (for `--deauth` with 2+ adapters). |

### General

| Flag | Default | Description |
|------|---------|-------------|
| `--alpha` | 0.3 | EMA smoothing factor for RSSI |
| `--refresh` | 1.0 | UI refresh interval (seconds) |
| `--top` | 30 (10 with `--ssid`) | Max stations to display |
| `--max-age` | 180 | Hide stations not seen for N seconds (0 = never hide) |

### Accuracy / ranking

| Flag | Default | Description |
|------|---------|-------------|
| `--rank-by` | weighted | Ranking algorithm: `weighted`, `kalman`, `median`, `ema`, `mean`, `p80`, `max` |
| `--half-life` | 6.0 | Half-life in seconds for time-weighted ranking |
| `--window` | 30 | Time window in seconds for sample collection (0 = all time) |
| `--min-samples` | 4 | Minimum RSSI samples before ranking a station |
| `--accurate` | off | Preset: longer dwell, larger half-life, longer max-age |

### Channel

| Flag | Default | Description |
|------|---------|-------------|
| `--channel` | (hop) | Lock to a single channel |
| `--band` | all | `5` = 5 GHz only, `2.4` = 2.4 GHz only, `all` = 5 GHz first then 2.4 |
| `--include-dfs` | off | Include DFS channels 52-144 in hop plan |
| `--hop` | auto | Enable channel hopping (implied by `--band` or `--ssid`) |
| `--dwell` | 0.20 | Seconds to stay on each channel |
| `--hop-channels` | (auto) | Comma-separated custom channel list |
| `--lock-strongest` | off | After `--lock-after` seconds, stop hopping and lock to the channel with the strongest station |
| `--lock-after` | 20.0 | Seconds before lock-strongest activates |
| `--remon` | off | Re-enable monitor mode after each channel change |
| `--width` | (auto) | Force channel width: 20, 40, 80, or 160 MHz |

### Filter

| Flag | Description |
|------|-------------|
| `--ssid` | Show only stations associated with this SSID |
| `--bssid` | Comma-separated BSSID(s) to filter to |
| `--show-aps` | Include access points in the station list (normally hidden) |
| `--only` | Show only one device class: `computer`, `phone`, or `iot` |
| `--include-unknown` | Show stations with no RSSI readings yet |

### Enrichment

| Flag | Default | Description |
|------|---------|-------------|
| `--no-passive` | (passive on) | Disable passive L3 extraction from captured frames |
| `--enrich-local` | off | Active L3 resolution over a joined interface (ARP + mDNS + NetBIOS + rDNS) |
| `--enrich-iface` | auto | Managed interface for active resolution (implies `--enrich-local`) |
| `--enrich-interval` | 6.0 | Seconds between active enrichment passes |
| `--no-arp-scan` | (ARP on) | Disable ARP sweep in `--enrich-local` |
| `--oui-file` | (built-in) | Path to a Wireshark-format OUI file for vendor lookup |

### Distance estimate

| Flag | Default | Description |
|------|---------|-------------|
| `--estimate-distance` | off | Show rough distance-in-meters column |
| `--tx-power` | -40 | Assumed transmit power at 1 meter (dBm) |
| `--path-loss` | 2.5 | Path-loss exponent (2.0 = free space, 2.5-3.5 = indoors) |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | (none) | Write station list to file on each refresh (`.csv` or `.json` by extension) |
| `--db` | (none) | SQLite database path for persistent logging |
| `--db-interval` | 10.0 | Seconds between database writes |
| `--db-history` | off | Write per-reading history rows (not just latest state) |
| `--no-rich` | off | Force plain ANSI renderer even if `rich` is installed |

### Active probing (authorized labs only)

| Flag | Default | Description |
|------|---------|-------------|
| `--ping-clients` | off | Inject RTS frames to elicit CTS replies (does not disconnect) |
| `--ping-interval` | 5.0 | Seconds between ping sweeps |
| `--ping-gap` | 0.05 | Delay between pinging different clients |
| `--ping-max` | 40 | Max clients to ping per sweep |
| `--ping-src` | (random LAA) | Source MAC for RTS frames |
| `--deauth` | off | Send deauth frames to force reassociation |
| `--deauth-interval` | 30.0 | Seconds between deauth sweeps |
| `--deauth-count` | 3 | Deauth frames per direction per client per sweep |
| `--deauth-gap` | 0.1 | Delay between deauthing different clients |
| `--deauth-max` | 20 | Max clients to deauth per sweep |
| `--deauth-cooldown` | 120.0 | Skip a client if deauthed within this many seconds |
| `--deauth-smart` | off | Only deauth clients still missing hostname, IP, and OS |

### Setup

| Flag | Description |
|------|-------------|
| `--no-setup` | Skip automatic monitor-mode setup |
| `--kill` | Kill interfering processes (NetworkManager, wpa_supplicant) before setup |
| `--restore` | Restore interface(s) to managed mode and exit |
| `--install-deps` | Install scapy and rich via pip |
| `--selftest` | Run 183 built-in self-tests (no hardware needed) and exit |

## Architecture

The tool runs as a set of cooperating threads coordinated through a shared `Tracker` object protected by a reentrant lock:

```
main thread          -- UI rendering loop (rich Table or plain ANSI)
capture thread(s)    -- scapy.sniff() on each monitor interface
channel hopper       -- tunes interfaces across the channel plan
local enricher       -- ARP sweep + mDNS + NetBIOS + rDNS resolution
client pinger        -- RTS frame injection (optional)
client deauther      -- deauth frame injection (optional)
```

### Key classes

- **`Station`** -- Per-MAC state: RSSI history (time-stamped deque), hostname, IP, OS hint, vendor, model, services, probed SSIDs, TLS SNI set, security classification, channel, BSSID, device kind, and deauth log.

- **`Tracker`** -- Thread-safe container of all stations. Provides `update_rssi()`, `snapshot()` (returns stations sorted by chosen ranking metric), `bssids_for_ssid()`, and deauth-tracking methods (`log_deauth`, `needs_enrichment`, `deauth_due`).

- **`OuiResolver`** -- MAC-to-vendor lookup from a built-in table of ~60 common OUIs, extensible via `--oui-file` with a Wireshark-format OUI database.

- **`DeviceDB`** -- SQLite writer for `--db`. Stores latest station state and optionally per-reading RSSI history.

### Passive L3 extraction pipeline

Every captured packet passes through `_passive_l3()`, which inspects layer-3 and above without transmitting anything:

1. ARP -- maps MAC to IP (both request and reply)
2. DHCP -- extracts hostname (option 12), vendor class ID (option 60, fingerprinted to OS), requested IP (option 50)
3. mDNS -- service instance names, model from TXT records, hostname from PTR/A/AAAA
4. SSDP -- SERVER/LOCATION headers for manufacturer and model
5. NetBIOS -- name query responses
6. DNS -- query names and A/AAAA responses
7. TLS ClientHello -- SNI extraction (proper record/handshake/extension walk)
8. IPv6 -- EUI-64 addresses mapped back to MAC
9. Initial TTL -- OS family guess (64=Linux/macOS, 128=Windows, 255=iOS/network gear)

## Self-tests

183 tests cover all pure-logic functions. They run without hardware, without root, and without scapy or rich installed:

```bash
python3 wifi_proximity.py --selftest
```

Tests cover: MAC normalization, IP validation, multicast/LAA detection, OUI resolution, frequency/channel conversion, VHT/HT width derivation, channel plans, sparkline rendering, device classification, frame protection detection, RTS/deauth field generation, association inference, percentile calculation, distance estimation, ip-neigh and arp-a parsing, RSSI ranking (all seven algorithms), Station and Tracker lifecycle, TLS SNI parsing, security classification, mDNS/NetBIOS parsing, Kalman filter, DHCP fingerprinting, TTL OS guessing, EUI-64 extraction, deauth log/cooldown/smart-targeting, and more.

A passing run prints each test with `OK` and ends with:

```
=== 183 passed, 0 FAILED ===
```

## Wireshark tips

To verify deauth frames are being sent, capture on the monitor interface and filter:

```
wlan.fc.type_subtype == 0x000c
```

To see only traffic for a specific client MAC:

```
wlan.addr == aa:bb:cc:dd:ee:ff
```

## License

This tool is provided as-is for authorized security testing and network diagnostics. Use responsibly.

## Version

`2026.09.15-5ghz+fastL3+deauth2`
