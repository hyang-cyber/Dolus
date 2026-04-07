// Auto-generated from: Sheppard.json
/*
  RTL8720dn 5GHz WiFi AP Spoofer
  --------------------------------
  Broadcasts fake 802.11a beacon frames on 5GHz channels to simulate
  the presence of multiple 5GHz WiFi access points. Useful for testing
  device anti-spoof / rogue-AP detection capabilities.

  Hardware : Realtek RTL8720dn (BW16 / AmebaD module)
  SDK       : Realtek AmebaD Arduino SDK
  Reuses   : wifi_cust_tx.h / wifi_cust_tx.cpp (already in repo)

  ⚠  For authorized testing only on networks/devices you own.
*/

#include "WiFi.h"
#include "src/packet-injection/packet-injection.h"
#include "wifi_conf.h"
#include "wifi_util.h"

// -----------------------------------------------------------------------
// Security profile for each spoofed AP
// Note: SECURITY_OPEN/WPA2/WPA3 are already defined as macros by the Realtek
// AmebaD SDK (wl_definitions.h), so we use AP_SEC_ prefix to avoid collision.
enum WiFiSecurity {
  AP_SEC_OPEN, // No lock icon
  AP_SEC_WPA2, // Lock icon, shows WPA2-PSK
  AP_SEC_WPA3  // Lock icon, shows WPA3-SAE
};

struct SpoofAP {
  const char *ssid;
  uint8_t channel;
  uint8_t bssid[6];
  WiFiSecurity security; // AP_SEC_OPEN, AP_SEC_WPA2, or AP_SEC_WPA3
};

SpoofAP spoof_list[] = {
  { "Ignite TV", 36, { 0x42, 0x75, 0xC3, 0xC6, 0x38, 0x70 }, AP_SEC_WPA2 },  // RSSI -47 dBm
  { "BELL205", 40, { 0x90, 0x72, 0x82, 0xFE, 0xBA, 0xA6 }, AP_SEC_WPA2 },  // RSSI -49 dBm
  { "!YongeSheppard_Guest", 44, { 0xE2, 0xCB, 0xAC, 0x51, 0xFA, 0xD0 }, AP_SEC_WPA2 },  // RSSI -51 dBm
  { "TEMP-EVENTS", 48, { 0xF2, 0xCB, 0xAC, 0x51, 0xFA, 0xD0 }, AP_SEC_WPA2 },  // RSSI -51 dBm
  { "YEC Fido", 149, { 0xD8, 0xEB, 0x97, 0xE0, 0x38, 0xA0 }, AP_SEC_WPA2 },  // RSSI -52 dBm
  { "N15 Hair & Lash Salon_EXT", 153, { 0x30, 0xDE, 0x4B, 0x4D, 0xC1, 0xBC }, AP_SEC_WPA2 },  // RSSI -53 dBm
  { "!YongeSheppard_Guest", 157, { 0xE0, 0xCB, 0xBC, 0x51, 0xFA, 0xD0 }, AP_SEC_WPA2 },  // RSSI -53 dBm
  { "VIRGIN", 161, { 0x54, 0x64, 0xD9, 0x2F, 0xA9, 0x0C }, AP_SEC_WPA2 },  // RSSI -53 dBm
  { "BELL774", 165, { 0xF0, 0x82, 0x61, 0x48, 0x3D, 0x12 }, AP_SEC_WPA2 },  // RSSI -54 dBm
  { "Ticketcenter", 36, { 0xF4, 0xF2, 0x6D, 0x9E, 0x68, 0xDE }, AP_SEC_WPA2 },  // RSSI -55 dBm
  { "N15 Hair & Lash Salon", 40, { 0x40, 0xF2, 0x01, 0xFC, 0x21, 0x6F }, AP_SEC_WPA2 },  // RSSI -56 dBm
  { "BELL981", 44, { 0x44, 0xE9, 0xDD, 0x46, 0x5A, 0x6A }, AP_SEC_WPA2 },  // RSSI -56 dBm
  { "HYA-CNY Guest", 48, { 0xF2, 0xF2, 0x6D, 0x9E, 0x68, 0xDE }, AP_SEC_WPA2 },  // RSSI -57 dBm
  { "N15 Hair & Lash Salon_EXT", 149, { 0x30, 0xDE, 0x4B, 0x4D, 0xC1, 0xBD }, AP_SEC_WPA2 },  // RSSI -57 dBm
  { "!YongeSheppard_Guest", 153, { 0xE2, 0xCB, 0xAC, 0x51, 0xFE, 0x96 }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "TEMP-EVENTS", 157, { 0xF2, 0xCB, 0xAC, 0x51, 0xFE, 0x96 }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "VIRGIN474-V", 161, { 0x5A, 0x2F, 0xF7, 0xFD, 0x85, 0x37 }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "VIRGIN474", 165, { 0x58, 0x2F, 0xF7, 0xFD, 0x85, 0x36 }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "SUSHIQ", 36, { 0x54, 0x64, 0xD9, 0x39, 0x4A, 0x77 }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "!YongeSheppard_Guest", 40, { 0xAE, 0x17, 0xD8, 0xA3, 0x02, 0xAE }, AP_SEC_WPA2 },  // RSSI -58 dBm
  { "WDNA Store", 44, { 0xEA, 0x55, 0x3D, 0xF3, 0xBE, 0x95 }, AP_SEC_WPA2 },  // RSSI -59 dBm
  { "TEMP-EVENTS", 48, { 0xF2, 0xCB, 0xBC, 0x51, 0xFA, 0xD0 }, AP_SEC_WPA2 },  // RSSI -59 dBm
  { "TEMP-EVENTS", 149, { 0xBE, 0x17, 0xD8, 0xA3, 0x02, 0xAE }, AP_SEC_WPA2 },  // RSSI -59 dBm
  { "BELL774", 153, { 0xF0, 0x82, 0x61, 0x48, 0x3D, 0x11 }, AP_SEC_WPA2 },  // RSSI -59 dBm
  { "pdy-employee", 157, { 0x70, 0x3A, 0x0E, 0x2F, 0xC0, 0xF3 }, AP_SEC_WPA2 },  // RSSI -59 dBm
  { "!YongeSheppard_Guest", 161, { 0xAC, 0x17, 0xC8, 0xA3, 0x02, 0xBC }, AP_SEC_WPA2 },  // RSSI -61 dBm
  { "Ignite TV", 165, { 0x42, 0x75, 0xC3, 0xCD, 0x38, 0x79 }, AP_SEC_WPA2 },  // RSSI -62 dBm
  { "BELL205", 36, { 0x90, 0x72, 0x82, 0xFE, 0xBA, 0xA7 }, AP_SEC_WPA2 },  // RSSI -62 dBm
  { "!YongeSheppard_Guest", 40, { 0xAC, 0x17, 0xC8, 0xA3, 0x00, 0x62 }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "WDNA Office", 44, { 0xE2, 0x55, 0x2D, 0xF3, 0xBE, 0x95 }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "!YongeSheppard_Guest", 48, { 0xE2, 0xCB, 0xAC, 0x51, 0xF5, 0x06 }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "!YongeSheppard_Guest", 149, { 0xE0, 0xCB, 0xBC, 0x51, 0xFF, 0x66 }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "VIRGIN474", 153, { 0x46, 0x2F, 0xF7, 0xFD, 0x85, 0x35 }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "BELL981", 157, { 0x44, 0xE9, 0xDD, 0x46, 0x5A, 0x6B }, AP_SEC_WPA2 },  // RSSI -63 dBm
  { "BELL507", 161, { 0xA0, 0x8E, 0x78, 0x2E, 0x30, 0x7E }, AP_SEC_WPA2 },  // RSSI -64 dBm
  { "TEMP-EVENTS", 165, { 0xF2, 0xCB, 0xAC, 0x51, 0xF5, 0x06 }, AP_SEC_WPA2 },  // RSSI -64 dBm
  { "DIRECT-a4-HP M426 LaserJet", 36, { 0x56, 0x13, 0x79, 0xA7, 0xE0, 0xA4 }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "DIRECT-d4-HP M203 LaserJet", 40, { 0x12, 0x6F, 0xD9, 0x33, 0x1C, 0xD4 }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "TEMP-EVENTS", 44, { 0xBE, 0x17, 0xC8, 0xA3, 0x00, 0x62 }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "WDNA Office", 48, { 0xE0, 0x55, 0x3D, 0xF3, 0xBE, 0x95 }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "TEMP-EVENTS", 149, { 0xBE, 0x17, 0xC8, 0xA3, 0x02, 0xBC }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "VIRGIN474-V", 153, { 0x5A, 0x2F, 0xF7, 0xFD, 0x85, 0x30 }, AP_SEC_WPA2 },  // RSSI -65 dBm
  { "HelixFEF3", 157, { 0x54, 0x21, 0x60, 0x82, 0x27, 0x08 }, AP_SEC_WPA2 },  // RSSI -66 dBm
  { "!YongeSheppard_Guest", 161, { 0xAC, 0x17, 0xC8, 0xA3, 0x02, 0xAE }, AP_SEC_WPA2 },  // RSSI -66 dBm
  { "FWB Sheppard", 165, { 0x3A, 0x66, 0x85, 0xE9, 0x72, 0x1C }, AP_SEC_WPA2 },  // RSSI -66 dBm
  { "VIRGIN474", 36, { 0x58, 0x2F, 0xF7, 0xFD, 0x85, 0x37 }, AP_SEC_WPA2 },  // RSSI -66 dBm
  { "N15 Hair & Lash Salon", 40, { 0x40, 0xF2, 0x01, 0xFC, 0x21, 0x70 }, AP_SEC_WPA2 },  // RSSI -66 dBm
  { "WDNA Service", 44, { 0xF6, 0x55, 0x2D, 0xF3, 0xBE, 0x95 }, AP_SEC_WPA2 },  // RSSI -67 dBm
  { "REAL FRUIT BUBBLE TEA", 48, { 0x56, 0x64, 0xD9, 0x33, 0x38, 0xBC }, AP_SEC_WPA2 },  // RSSI -67 dBm
  { "easyguest WiFi", 149, { 0xEA, 0x55, 0xA8, 0x55, 0x1B, 0x07 }, AP_SEC_WPA2 },  // RSSI -67 dBm
};

// Automatically computed — just add/remove entries in spoof_list above
#define NUM_SPOOF_APS (sizeof(spoof_list) / sizeof(spoof_list[0]))

// 802.11 beacon interval: exactly 100 TUs = 102400 microseconds
// The full interval is divided into equal slots — one sequential slot per AP.
// Each AP's beacon recurs at exactly 102.4ms from a sniffer's perspective.
#define BEACON_INTERVAL_US 102400UL

uint32_t sent_frames = 0; // total beacon frames transmitted

// -----------------------------------------------------------------------
// 5GHz Beacon Frame Builder
//
// 802.11 beacon frame layout used here:
//
//  [0-1]   Frame Control  = 0x80 0x00  (beacon)
//  [2-3]   Duration       = 0x00 0x00
//  [4-9]   Destination    = FF:FF:FF:FF:FF:FF (broadcast)
//  [10-15] Source (BSSID)
//  [16-21] BSSID          (same as source for an AP)
//  [22-23] Sequence ctrl  = 0x00 0x00
//  --- Management frame body ---
//  [24-31] Timestamp      (8 bytes, little-endian microseconds)
//  [32-33] Beacon interval= 0x64 0x00  (100 TUs = ~102.4 ms)
//  [34-35] Capability     = 0x21 0x00  (ESS + Short Preamble; Privacy bit set
//  for WPA2/WPA3) IEs in order: SSID, Supported Rates (5GHz OFDM), DS Param,
//                HT Cap, HT Op, VHT Cap, VHT Op, RSN
//
//  Supported Rates (5GHz OFDM only — no legacy 2.4GHz DSSS rates):
//    6* 12* 24*  9  18  36  48  54 Mbps  (* = basic/mandatory)
//    0x8C 0x98 0xB0 0x12 0x24 0x48 0x60 0x6C
// NOTE: DS Parameter Set IE (tag 3) is included for channel advertisement.
// -----------------------------------------------------------------------

// VHT helper: returns the 80 MHz centre channel for a given primary channel.
// Falls back to the primary channel itself (20 MHz) for edge channels.
static uint8_t vht_center_ch(uint8_t ch) {
  if (ch >= 36 && ch <= 48)
    return 42; // UNII-1 80 MHz block
  if (ch >= 52 && ch <= 64)
    return 58; // UNII-2A 80 MHz block
  if (ch >= 149 && ch <= 161)
    return 155; // UNII-3 80 MHz block
  return ch;    // e.g. CH 165 — treat as 20 MHz
}

// Expanded buffer: 320 bytes — fits MAC header + all IEs including VHT
static uint8_t beacon_buf[320];

size_t build_beacon_5g(const SpoofAP &ap) {
  uint8_t ssid_len = (uint8_t)strlen(ap.ssid);
  if (ssid_len > 32)
    ssid_len = 32; // cap per 802.11 spec

  uint8_t *p = beacon_buf;

  // ---- Fixed MAC header (24 bytes) ----
  // Frame control: beacon
  *p++ = 0x80;
  *p++ = 0x00;
  // Duration
  *p++ = 0x00;
  *p++ = 0x00;
  // Destination: broadcast
  *p++ = 0xFF;
  *p++ = 0xFF;
  *p++ = 0xFF;
  *p++ = 0xFF;
  *p++ = 0xFF;
  *p++ = 0xFF;
  // Source address = BSSID
  memcpy(p, ap.bssid, 6);
  p += 6;
  // BSSID
  memcpy(p, ap.bssid, 6);
  p += 6;
  // Sequence control (will be overwritten by firmware to 0)
  *p++ = 0x00;
  *p++ = 0x00;

  // ---- Fixed beacon fields (12 bytes) ----
  // Timestamp: 8 bytes, little-endian microseconds uptime
  uint64_t ts = (uint64_t)micros();
  memcpy(p, &ts, 8);
  p += 8;
  // Beacon interval: 100 TUs = 0x0064
  *p++ = 0x64;
  *p++ = 0x00;
  // Capability info:
  // Bit 0 = ESS, Bit 5 = Short Preamble, Bit 4 = Privacy (set for WPA2/WPA3)
  uint8_t cap = 0x21; // ESS + Short Preamble
  if (ap.security != AP_SEC_OPEN)
    cap |= 0x10; // set Privacy bit
  *p++ = cap;
  *p++ = 0x00;

  // ---- Information Elements ----

  // IE 0: SSID
  *p++ = 0x00; // Tag: SSID
  *p++ = ssid_len;
  memcpy(p, ap.ssid, ssid_len);
  p += ssid_len;

  // IE 1: Supported Rates — 5GHz OFDM only (no 2.4GHz legacy DSSS rates)
  // Basic mandatory rates: 6, 12, 24 Mbps; optional: 9, 18, 36, 48, 54 Mbps
  *p++ = 0x01;
  *p++ = 0x08;
  *p++ = 0x8C;
  *p++ = 0x98;
  *p++ = 0xB0;
  *p++ = 0x12;
  *p++ = 0x24;
  *p++ = 0x48;
  *p++ = 0x60;
  *p++ = 0x6C;

  // IE 3: DS Parameter Set (Current Channel)
  // Many phones ignore beacons without a channel broadcast
  *p++ = 0x03; // Tag: DS Parameter Set
  *p++ = 0x01; // Length: 1
  *p++ = ap.channel;

  // IE 45: HT Capabilities (802.11n) — 26 bytes
  *p++ = 45;
  *p++ = 26;
  const uint8_t ht_cap[26] = {0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(p, ht_cap, 26);
  p += 26;

  // IE 61: HT Operation (802.11n) — 22 bytes
  *p++ = 61;
  *p++ = 22;
  const uint8_t ht_op[22] = {
      ap.channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00,       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  memcpy(p, ht_op, 22);
  p += 22;

  // IE 191: VHT Capabilities (802.11ac / Wi-Fi 5)
  // Required by iOS/Android to treat a 5GHz AP as modern.
  // Cap Info: LDPC + ShortGI-80 + TX-STBC + 1-SS RX-STBC + Max-A-MPDU-exp=7 +
  // Ant-patterns
  *p++ = 191;
  *p++ = 12;
  const uint8_t vht_cap[12] = {
      0xB0, 0x01,
      0x80, 0x33, // VHT Cap Info (little-endian 32-bit)
      0xFC, 0xFF,
      0x00, 0x00, // RX MCS Map: SS1=MCS0-9, SS2-8=not supported; RX max rate
      0xFC, 0xFF,
      0x00, 0x00 // TX MCS Map: same; TX max rate
  };
  memcpy(p, vht_cap, 12);
  p += 12;

  // IE 192: VHT Operation (802.11ac)
  // Use 80 MHz where possible; CH 165 falls back to 20 MHz (no full 80 MHz
  // block).
  *p++ = 192;
  *p++ = 5;
  uint8_t vht_center = vht_center_ch(ap.channel);
  uint8_t vht_width = (vht_center != ap.channel) ? 1 : 0; // 1=80MHz, 0=20/40MHz
  *p++ = vht_width;                                       // Channel Width
  *p++ = vht_center; // Channel Center Freq Seg 0
  *p++ = 0;          // Channel Center Freq Seg 1 (0 = not used)
  *p++ = 0x00;
  *p++ = 0x00; // Basic MCS Set (inherit from capabilities)

  // IE 48: RSN (Robust Security Network) — WPA2-Personal or WPA3-Personal
  if (ap.security == AP_SEC_WPA2) {
    *p++ = 0x30;
    *p++ = 20; // Tag RSN, length 20
    *p++ = 0x01;
    *p++ = 0x00; // RSN version 1
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x04; // Group cipher: CCMP
    *p++ = 0x01;
    *p++ = 0x00; // Pairwise cipher count: 1
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x04; // Pairwise cipher: CCMP
    *p++ = 0x01;
    *p++ = 0x00; // AKM count: 1
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x02; // AKM: PSK
    *p++ = 0x00;
    *p++ = 0x00; // RSN Capabilities
  } else if (ap.security == AP_SEC_WPA3) {
    *p++ = 0x30;
    *p++ = 20;
    *p++ = 0x01;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x04;
    *p++ = 0x01;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x04;
    *p++ = 0x01;
    *p++ = 0x00;
    *p++ = 0x00;
    *p++ = 0x0F;
    *p++ = 0xAC;
    *p++ = 0x08; // AKM: SAE (WPA3)
    *p++ = 0x00;
    *p++ = 0xC0; // RSN Capabilities: MFP Required (bit6) + MFP Capable (bit7)
  }
  // AP_SEC_OPEN: no RSN IE (intentional — no lock icon)

  return (size_t)(p - beacon_buf);
}

// -----------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  Serial.println("\n[5G Spoofer] Starting up...");

  // The RTL8720dn needs WiFi initialised before wext_set_channel() works.
  // We start a minimal AP on 5GHz channel 36 just to put the radio into 5G
  // mode, then the loop takes over channel control for 5GHz TX.
  char init_ssid[] = "_init_";
  char init_pass[] = "00000000";
  char init_chan[] = "36";
  WiFi.apbegin(init_ssid, init_pass, init_chan);
  delay(500); // let the driver settle

  Serial.println("[5G Spoofer] Radio up. Starting beacon loop.");
  Serial.println("[5G Spoofer] Spoofing the following 5GHz networks:");
  for (int i = 0; i < NUM_SPOOF_APS; i++) {
    char print_buf[128];
    const char *sec_str = (spoof_list[i].security == AP_SEC_WPA2)   ? "WPA2"
                          : (spoof_list[i].security == AP_SEC_WPA3) ? "WPA3"
                                                                    : "OPEN";
    snprintf(print_buf, sizeof(print_buf),
             "  [%d] SSID: %-24s  CH: %3d  SEC: %-4s  BSSID: "
             "%02X:%02X:%02X:%02X:%02X:%02X\n",
             i, spoof_list[i].ssid, spoof_list[i].channel, sec_str,
             spoof_list[i].bssid[0], spoof_list[i].bssid[1],
             spoof_list[i].bssid[2], spoof_list[i].bssid[3],
             spoof_list[i].bssid[4], spoof_list[i].bssid[5]);
    Serial.print(print_buf);
  }
  // No staggering needed — the sequential loop handles timing automatically.
}

// -----------------------------------------------------------------------
// Main Loop — Sequential time-sliced beacon transmission.
//
// Each AP gets a fixed SLOT_US time slot. The full cycle (NUM_SPOOF_APS × SLOT_US)
// must be shorter than the minimum WiFi scan dwell time of the target device.
//
// Android passive scan dwell: ~60-90ms  → full cycle must be < 60ms
// Windows passive scan dwell: ~150ms+   → much more forgiving
// iOS passive scan dwell:     ~80-120ms → full cycle must be < 80ms
//
// With SLOT_US = 1000 (1ms):  50 APs = 50ms cycle  ✅ Android + iOS + Windows
//                              30 APs = 30ms cycle  ✅
//                              10 APs = 10ms cycle  ✅
// BEACON_BURST_COUNT × frame_tx_time must be ≤ SLOT_US.
// At ~300µs per frame: 3 × 300µs = 900µs < 1000µs ✅
// -----------------------------------------------------------------------
#define SLOT_US            1000UL  // µs per AP slot — keep cycle < scan dwell time
#define BEACON_BURST_COUNT 3       // frames per slot (3 × ~300µs ≈ 900µs fits in 1ms)

void loop() {
  for (int i = 0; i < (int)NUM_SPOOF_APS; i++) {
    unsigned long slot_start = micros();

    // Burst at the start of the slot — all frames for this AP.
    size_t frame_len = build_beacon_5g(spoof_list[i]);
    for (int b = 0; b < BEACON_BURST_COUNT; b++) {
      wifi_tx_raw_frame(beacon_buf, frame_len);
      sent_frames++;
    }

    // Idle out the rest of this AP's slot.
    while ((micros() - slot_start) < SLOT_US) { /* spin */
    }
  }
}
