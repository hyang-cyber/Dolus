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

#include "src/packet-injection/packet-injection.h"
#include "wifi_conf.h"
#include "wifi_util.h"
#include "WiFi.h"

// -----------------------------------------------------------------------
// Spoof list — edit SSIDs, channels and BSSIDs to your liking
// Channels must be valid UNII-1 / UNII-3 5GHz channels:
//   UNII-1 : 36, 40, 44, 48
//   UNII-2 : 52, 56, 60, 64  (may require DFS — use with caution)
//   UNII-3 : 149, 153, 157, 161, 165
// -----------------------------------------------------------------------
// Automatically computed — just add/remove entries in spoof_list below
#define NUM_SPOOF_APS (sizeof(spoof_list) / sizeof(spoof_list[0]))

// Security profile for each spoofed AP
// Note: SECURITY_OPEN/WPA2/WPA3 are already defined as macros by the Realtek
// AmebaD SDK (wl_definitions.h), so we use AP_SEC_ prefix to avoid collision.
enum WiFiSecurity {
  AP_SEC_OPEN,   // No lock icon
  AP_SEC_WPA2,   // Lock icon, shows WPA2-PSK
  AP_SEC_WPA3    // Lock icon, shows WPA3-SAE
};

struct SpoofAP {
  const char   *ssid;
  uint8_t       channel;
  uint8_t       bssid[6];
  WiFiSecurity  security;  // SECURITY_OPEN, SECURITY_WPA2, or SECURITY_WPA3
};

SpoofAP spoof_list[] = {
  { "HomeNetwork_5G",   36, { 0x00, 0x14, 0x6C, 0x11, 0x22, 0x01 }, AP_SEC_WPA2 }, // Cisco
  { "OfficeWiFi_5G",   36, { 0xC0, 0xFF, 0xD4, 0x11, 0x22, 0x02 }, AP_SEC_WPA3 }, // Netgear
  { "GuestNet_5G",     36, { 0xE8, 0x94, 0xF6, 0x11, 0x22, 0x03 }, AP_SEC_OPEN }, // TP-Link
  { "CafeWireless_5G", 36, { 0x00, 0x14, 0xBF, 0x11, 0x22, 0x04 }, AP_SEC_WPA2 }, // Linksys
  { "RouterAX_5G",     36, { 0x08, 0x60, 0x6E, 0x11, 0x22, 0x05 }, AP_SEC_WPA3 }, // Asus
};

// 802.11 beacon interval: exactly 100 TUs = 102400 microseconds
// The full interval is divided into equal slots — one sequential slot per AP.
// Each AP's beacon recurs at exactly 102.4ms from a sniffer's perspective.
#define BEACON_INTERVAL_US  102400UL

uint32_t sent_frames = 0;  // total beacon frames transmitted

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
//  [34-35] Capability     = 0x01 0x00  (ESS only — OFDM AP, no DSSS)
//  [36]    IE Tag 0       = 0x00  (SSID)
//  [37]    SSID length
//  [38 ..] SSID bytes
//  [38+n]  IE Tag 1       = 0x01  (Supported Rates — OFDM mandatory)
//            Length = 3
//            6 Mbps  = 0x8C  (basic/mandatory)
//           12 Mbps  = 0x98  (basic/mandatory)
//           24 Mbps  = 0xB0  (basic/mandatory)
//  [+5]    IE Tag 50      = 0x32  (Extended Supported Rates)
//            Length = 5
//            9 Mbps  = 0x12
//           18 Mbps  = 0x24
//           36 Mbps  = 0x48
//           48 Mbps  = 0x60
//           54 Mbps  = 0x6C
//
// NOTE: No DS Parameter Set IE (tag 3 / DSSS) — that IE is 2.4GHz only.
// -----------------------------------------------------------------------

// Expanded buffer: max 256 bytes to accommodate RSN IE for WPA2/WPA3
static uint8_t beacon_buf[256];

size_t build_beacon_5g(const SpoofAP &ap) {
  uint8_t ssid_len = (uint8_t)strlen(ap.ssid);
  if (ssid_len > 32) ssid_len = 32;  // cap per 802.11 spec

  uint8_t *p = beacon_buf;

  // ---- Fixed MAC header (24 bytes) ----
  // Frame control: beacon
  *p++ = 0x80; *p++ = 0x00;
  // Duration
  *p++ = 0x00; *p++ = 0x00;
  // Destination: broadcast
  *p++ = 0xFF; *p++ = 0xFF; *p++ = 0xFF; *p++ = 0xFF; *p++ = 0xFF; *p++ = 0xFF;
  // Source address = BSSID
  memcpy(p, ap.bssid, 6); p += 6;
  // BSSID
  memcpy(p, ap.bssid, 6); p += 6;
  // Sequence control (will be overwritten by firmware to 0)
  *p++ = 0x00; *p++ = 0x00;

  // ---- Fixed beacon fields (12 bytes) ----
  // Timestamp: 8 bytes, little-endian microseconds uptime
  uint64_t ts = (uint64_t)micros();
  memcpy(p, &ts, 8); p += 8;
  // Beacon interval: 100 TUs = 0x0064
  *p++ = 0x64; *p++ = 0x00;
  // Capability info:
  // Bit 0 = ESS, Bit 5 = Short Preamble, Bit 4 = Privacy (set for WPA2/WPA3)
  uint8_t cap = 0x21;  // ESS + Short Preamble
  if (ap.security != AP_SEC_OPEN) cap |= 0x10;  // set Privacy bit
  *p++ = cap; *p++ = 0x00;

  // ---- Information Elements ----

  // IE 0: SSID
  *p++ = 0x00;           // Tag: SSID
  *p++ = ssid_len;
  memcpy(p, ap.ssid, ssid_len); p += ssid_len;

  // IE 1: Supported Rates (Universal 8-rate array)
  // strict Android/iOS often drop APs using pure OFDM rates because iOS expects b/g fallback compatibility tags
  *p++ = 0x01;  // Tag: Supported Rates
  *p++ = 0x08;  // Length: 8 rates
  *p++ = 0x82; *p++ = 0x84; *p++ = 0x8b; *p++ = 0x96;
  *p++ = 0x24; *p++ = 0x30; *p++ = 0x48; *p++ = 0x6C;

  // IE 3: DS Parameter Set (Current Channel)
  // Many phones ignore beacons without a channel broadcast
  *p++ = 0x03;  // Tag: DS Parameter Set
  *p++ = 0x01;  // Length: 1
  *p++ = ap.channel;

  // IE 45: HT Capabilities (802.11n) - 26 bytes
  *p++ = 45; *p++ = 26;
  const uint8_t ht_cap[26] = { 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  memcpy(p, ht_cap, 26); p += 26;

  // IE 61: HT Operation (802.11n) - 22 bytes
  *p++ = 61; *p++ = 22;
  const uint8_t ht_op[22] = { ap.channel, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  memcpy(p, ht_op, 22); p += 22;

  // IE 48: RSN (Robust Security Network) — only for WPA2 / WPA3
  if (ap.security == AP_SEC_WPA2) {
    // RSN IE for WPA2-Personal (CCMP cipher + PSK AKM)
    *p++ = 0x30;  // Tag: RSN
    *p++ = 20;    // Length: 20 bytes
    *p++ = 0x01; *p++ = 0x00;  // RSN version 1
    // Group cipher: CCMP (00-0F-AC-04)
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x04;
    // Pairwise cipher count: 1
    *p++ = 0x01; *p++ = 0x00;
    // Pairwise cipher: CCMP (00-0F-AC-04)
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x04;
    // AKM count: 1
    *p++ = 0x01; *p++ = 0x00;
    // AKM: PSK (00-0F-AC-02)
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x02;
    // RSN Capabilities: 0x0000
    *p++ = 0x00; *p++ = 0x00;
  } else if (ap.security == AP_SEC_WPA3) {
    // RSN IE for WPA3-Personal (CCMP cipher + SAE AKM)
    *p++ = 0x30;  // Tag: RSN
    *p++ = 20;    // Length: 20 bytes
    *p++ = 0x01; *p++ = 0x00;  // RSN version 1
    // Group cipher: CCMP (00-0F-AC-04)
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x04;
    // Pairwise cipher count: 1
    *p++ = 0x01; *p++ = 0x00;
    // Pairwise cipher: CCMP (00-0F-AC-04)
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x04;
    // AKM count: 1
    *p++ = 0x01; *p++ = 0x00;
    // AKM: SAE (00-0F-AC-08) — WPA3 identifier
    *p++ = 0x00; *p++ = 0x0F; *p++ = 0xAC; *p++ = 0x08;
    // RSN Capabilities: MFP capable (bit 7) = 0x0080
    *p++ = 0x00; *p++ = 0x80;
  }

  return (size_t)(p - beacon_buf);
}


// -----------------------------------------------------------------------
// Setup
// -----------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  Serial.println("\n[5G Spoofer] Starting up...");

  // The RTL8720dn needs WiFi initialised before wext_set_channel() works.
  // We start a minimal AP on 5GHz channel 36 just to put the radio into 5G mode,
  // then the loop takes over channel control for 5GHz TX.
  char init_ssid[] = "_init_";
  char init_pass[] = "00000000";
  char init_chan[] = "36";
  WiFi.apbegin(init_ssid, init_pass, init_chan);
  delay(500);  // let the driver settle

  Serial.println("[5G Spoofer] Radio up. Starting beacon loop.");
  Serial.println("[5G Spoofer] Spoofing the following 5GHz networks:");
  for (int i = 0; i < NUM_SPOOF_APS; i++) {
    char print_buf[128];
    snprintf(print_buf, sizeof(print_buf), "  [%d] SSID: %-24s  CH: %d  BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
      i,
      spoof_list[i].ssid,
      spoof_list[i].channel,
      spoof_list[i].bssid[0], spoof_list[i].bssid[1], spoof_list[i].bssid[2],
      spoof_list[i].bssid[3], spoof_list[i].bssid[4], spoof_list[i].bssid[5]);
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
// Android passive scan dwell: ~60-90ms → full cycle must be < 60ms
// Windows passive scan dwell: ~150ms+  → much more forgiving
//
// With SLOT_US = 10000 (10ms):  5 APs = 50ms cycle  ✅ Android + Windows
//                               10 APs = 100ms cycle ⚠️ increase BEACON_BURST_COUNT
//                               20 APs = 200ms cycle ⚠️ reduce SLOT_US to 5000
// -----------------------------------------------------------------------
#define SLOT_US            10000UL  // µs per AP slot
#define BEACON_BURST_COUNT 5        // frames per slot — increase if APs are missed

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
    while ((micros() - slot_start) < SLOT_US) { /* spin */ }
  }
}
