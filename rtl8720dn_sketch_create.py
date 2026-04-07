#!/usr/bin/env python3
"""
rtl8720dn_sketch_create.py
--------------------------
Generates an RTL8720dn_5G_Spoofer Arduino sketchbook from a SkyLift JSON
network file.  Mirrors the behaviour of sketchCreate.py but targets the
Realtek RTL8720dn (BW16 / AmebaD) board and its SpoofAP struct format.

Author  : Huiyuan Yang
GitHub  : https://github.com/hyang-cyber/Dolus

This script is intentionally self-contained (no SkyLift package imports)
so it can be dropped into a dedicated repo without modification.

Security modes (opt_security):
  'wpa2'   — every AP uses AP_SEC_WPA2  (default, reserved)
  'wpa3'   — every AP uses AP_SEC_WPA3
  'open'   — every AP uses AP_SEC_OPEN
  'random' — each AP is assigned security independently using a weighted
             random draw (60 % WPA2, 30 % WPA3, 10 % OPEN) to make the
             spoof list look like a realistic mixed environment and lower
             the probability of pattern-based detection.

Usage (direct):
  python rtl8720dn_sketch_create.py

Usage (imported):
  from rtl8720dn_sketch_create import rtl8720dn_sketch_create
  rtl8720dn_sketch_create(opt_input=..., opt_output=..., ...)
"""

import json
import os
import random
from pathlib import Path


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

#: Weighted pool used when opt_security == 'random'.
#: Adjust probabilities here to change the realism profile.
_RANDOM_SECURITY_POOL = [
    ('AP_SEC_WPA2', 60),
    ('AP_SEC_WPA3', 30),
    ('AP_SEC_OPEN', 10),
]

_SECURITY_MAP = {
    'wpa2': 'AP_SEC_WPA2',
    'wpa3': 'AP_SEC_WPA3',
    'open': 'AP_SEC_OPEN',
}

def _pick_security(opt_security: str) -> str:
    """Return a C++ WiFiSecurity enum string for a single AP entry.

    Args:
        opt_security: one of 'wpa2', 'wpa3', 'open', or 'random'.

    Returns:
        'AP_SEC_WPA2', 'AP_SEC_WPA3', or 'AP_SEC_OPEN'
    """
    if opt_security == 'random':
        labels, weights = zip(*_RANDOM_SECURITY_POOL)
        return random.choices(labels, weights=weights, k=1)[0]
    return _SECURITY_MAP.get(opt_security.lower(), 'AP_SEC_WPA2')


# ---------------------------------------------------------------------------
# Network loading
# ---------------------------------------------------------------------------

def _bssid_as_hex_list_ino(bssid: str) -> str:
    """Convert 'AA:BB:CC:DD:EE:FF' to '{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }'."""
    parts = bssid.strip().split(':')
    if len(parts) != 6:
        raise ValueError(f'Invalid BSSID: {bssid!r}')
    return '{ ' + ', '.join(f'0x{b.upper()}' for b in parts) + ' }'


def _load_networks(fp_json: str, min_rssi: int, max_rssi: int,
                   max_networks: int) -> list:
    """Load and filter WiFi networks from a SkyLift JSON file.

    Args:
        fp_json:      Path to the JSON network file.
        min_rssi:     Minimum RSSI threshold (inclusive).
        max_rssi:     Maximum RSSI threshold (inclusive).
        max_networks: Maximum number of networks to return.

    Returns:
        List of dicts with keys: ssid, bssid, channel, rssi.
    """
    with open(fp_json, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Support both top-level list and SkyLift {"wifi": [...]} envelope
    if isinstance(data, list):
        raw_nets = data
    elif isinstance(data, dict) and 'wifi' in data:
        raw_nets = data['wifi']
    else:
        raise ValueError(
            f'Unrecognised JSON structure in {fp_json!r}. '
            'Expected a list or {"wifi": [...]} dict.'
        )

    nets = []
    for n in raw_nets:
        rssi = int(n.get('rssi', -100))
        if rssi < min_rssi or rssi > max_rssi:
            continue
        nets.append({
            'ssid':    n.get('ssid', ''),
            'bssid':   n.get('bssid', '00:00:00:00:00:00'),
            'channel': int(n.get('channel', 1)),
            'rssi':    rssi,
        })

    # Sort by descending RSSI (strongest first — most likely to be seen)
    nets.sort(key=lambda x: x['rssi'], reverse=True)
    return nets[:max_networks]


# ---------------------------------------------------------------------------
# Template injection
# ---------------------------------------------------------------------------

def _load_txt(fp: str) -> str:
    with open(fp, 'r', encoding='utf-8') as f:
        return f.read()


def _write_txt(fp: str, content: str) -> None:
    with open(fp, 'w', encoding='utf-8') as f:
        f.write(content)


def _insert_template(src: str, tag: str, payload: str) -> str:
    """Replace a {{TEMPLATE:TAG ... TEMPLATE:TAG}} block with payload."""
    tag_start = f'// {{{{TEMPLATE:{tag}'
    tag_end   = f'// TEMPLATE:{tag}}}}}'
    idx_start = src.index(tag_start)
    idx_end   = src.index(tag_end) + len(tag_end)
    return src[:idx_start] + payload + src[idx_end:]


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def rtl8720dn_sketch_create(
    opt_input:        str,
    opt_output:       str,
    opt_max_networks: int   = 50,
    opt_max_rssi:     int   = -20,
    opt_min_rssi:     int   = -95,
    opt_channels:     list  = None,
    opt_security:     str   = 'wpa2',
) -> None:
    """Generate an RTL8720dn_5G_Spoofer Arduino sketchbook.

    Args:
        opt_input:        Path to the SkyLift JSON network file.
        opt_output:       Output *directory* path.  The sketch name is
                          derived from the directory name, e.g.
                          ``RTL8720dn_5G_Spoofer/`` → ``RTL8720dn_5G_Spoofer.ino``.
        opt_max_networks: Maximum number of AP entries to generate.
        opt_max_rssi:     Strongest-signal cutoff (dBm).  Networks stronger
                          than this are excluded (they are unlikely to need
                          spoofing).
        opt_min_rssi:     Weakest-signal cutoff (dBm).  Networks weaker than
                          this are excluded.
        opt_channels:     List of 5 GHz channels to assign (round-robin).
                          Defaults to the main UNII-1/3 non-DFS channels.
        opt_security:     Security mode applied to each AP.
                          ``'wpa2'`` (default) | ``'wpa3'`` | ``'open'`` |
                          ``'random'`` (per-AP weighted random selection).
    """

    if opt_channels is None:
        opt_channels = [36, 40, 44, 48, 149, 153, 157, 161, 165]

    # ------------------------------------------------------------------
    # Resolve template .ino
    # ------------------------------------------------------------------
    # RTL8720dn_5G_Spoofer.ino lives next to this script and acts as the
    # template; its {{TEMPLATE:...}} markers are replaced with generated data.
    _this_dir = Path(__file__).resolve().parent
    fp_template_ino = _this_dir / 'RTL8720dn_5G_Spoofer.ino'
    if not fp_template_ino.exists():
        raise FileNotFoundError(
            f'Template not found: {fp_template_ino}\n'
            'RTL8720dn_5G_Spoofer.ino must be in the same directory as this script.'
        )

    # ------------------------------------------------------------------
    # Resolve output .ino path
    # ------------------------------------------------------------------
    out_path = Path(opt_output)
    if out_path.suffix.lower() == '.ino':
        # Caller passed an explicit file path, e.g. generated/MySketch.ino
        fp_sketch_ino = out_path
    else:
        # Caller passed a directory; write <dir>/<dirname>.ino inside it
        sketch_name   = out_path.name
        fp_sketch_ino = out_path / f'{sketch_name}.ino'
    fp_sketch_ino.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Load and filter networks
    # ------------------------------------------------------------------
    if not Path(opt_input).suffix.lower() == '.json':
        raise ValueError(f'Only JSON input is supported, got: {opt_input!r}')

    wifi_nets = _load_networks(
        fp_json=opt_input,
        min_rssi=opt_min_rssi,
        max_rssi=opt_max_rssi,
        max_networks=opt_max_networks,
    )

    if not wifi_nets:
        print(f'[WARNING] No networks matched the RSSI filter '
              f'({opt_min_rssi} ≤ RSSI ≤ {opt_max_rssi}). Sketch will have an empty spoof list.')

    # ------------------------------------------------------------------
    # Build SPOOF_LIST payload
    # ------------------------------------------------------------------
    # Assign 5GHz channels round-robin by RSSI rank, then sort by channel so
    # the firmware's channel-hopping loop switches the radio as few times as
    # possible per cycle (one switch per distinct channel, not per AP).
    for idx, net in enumerate(wifi_nets):
        net['channel_5g'] = opt_channels[idx % len(opt_channels)]
        net['security']   = _pick_security(opt_security)

    wifi_nets.sort(key=lambda n: n['channel_5g'])

    spoof_lines = ['SpoofAP spoof_list[] = {']
    for net in wifi_nets:
        bssid_ino = _bssid_as_hex_list_ino(net['bssid'])
        ssid_safe = net['ssid'].replace('"', '\\"')  # escape quotes in SSID
        spoof_lines.append(
            f'  {{ "{ssid_safe}", {net["channel_5g"]}, {bssid_ino}, {net["security"]} }},  '
            f'// RSSI {net["rssi"]} dBm'
        )
    spoof_lines.append('};')
    spoof_payload = '\n'.join(spoof_lines)

    # Header comment
    header_payload = f'// Auto-generated from: {Path(opt_input).name}'

    # ------------------------------------------------------------------
    # Inject templates and write output
    # ------------------------------------------------------------------
    t = _load_txt(str(fp_template_ino))
    t = _insert_template(t, 'HEADER',     header_payload)
    t = _insert_template(t, 'SPOOF_LIST', spoof_payload)
    _write_txt(str(fp_sketch_ino), t)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    sec_label = opt_security.upper()
    print(f'[rtl8720dn_sketch_create] Done.')
    print(f'  Output   : {fp_sketch_ino}')
    print(f'  Networks : {len(wifi_nets)} AP entries generated')
    print(f'  Security : {sec_label}')
    if opt_security == 'random':
        counts = {}
        for line in spoof_lines:
            for key in ('AP_SEC_WPA2', 'AP_SEC_WPA3', 'AP_SEC_OPEN'):
                if key in line:
                    counts[key] = counts.get(key, 0) + 1
        for k, v in sorted(counts.items()):
            print(f'    {k}: {v}')
    print(f'  Channels : {opt_channels}')


# ---------------------------------------------------------------------------
# Standalone entry point — edit defaults here before running
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    rtl8720dn_sketch_create(
        opt_input        = r'E:\code\Dolus\Tmu.json',
        # Output goes into a dedicated subfolder so the generated sketch
        # (generated/RTL8720dn_5G_Spoofer/RTL8720dn_5G_Spoofer.ino) never
        # overwrites the hand-written root RTL8720dn_5G_Spoofer.ino.
        opt_output       = r'E:\code\Dolus\generated',

        opt_max_networks = 50,
        opt_max_rssi     = -20,    # exclude extremely strong (nearby) signals
        opt_min_rssi     = -95,    # exclude noise-floor signals

        # 5 GHz UNII-1 and UNII-3 non-DFS channels
        opt_channels     = [36, 40, 44, 48, 149, 153, 157, 161, 165],

        # Security mode: 'wpa2' | 'wpa3' | 'open' | 'random'
        # 'wpa2'   → every AP is WPA2 (safe default, reserved)
        # 'random' → realistic mixed environment (60% WPA2 / 30% WPA3 / 10% OPEN)
        opt_security     = 'wpa2',
    )
