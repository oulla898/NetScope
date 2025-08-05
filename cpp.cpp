#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"

// WiFi sniffer configuration
#define WIFI_CHANNEL_MAX 13
#define WIFI_CHANNEL_SWITCH_INTERVAL 2000 // Switch channels every 2 seconds
#define MAXIMUM_AP_COUNT 20

// Frame type definitions
#define WIFI_MANAGEMENT_FRAME 0x00
#define WIFI_CONTROL_FRAME 0x01
#define WIFI_DATA_FRAME 0x02

// Frame subtype definitions for management frames
#define WIFI_BEACON_FRAME 0x08
#define WIFI_PROBE_REQUEST 0x04
#define WIFI_PROBE_RESPONSE 0x05
#define WIFI_ASSOCIATION_REQUEST 0x00
#define WIFI_ASSOCIATION_RESPONSE 0x01
#define WIFI_DISASSOCIATION 0x0A
#define WIFI_AUTHENTICATION 0x0B
#define WIFI_DEAUTHENTICATION 0x0C

// Global variables
static const char* TAG = "WiFi_Sniffer";
static int current_channel = 1;
static uint32_t last_channel_switch = 0;
static int frame_count = 0;
static int interesting_frame_count = 0;

// Function prototypes
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type);
void switch_wifi_channel();
const char* get_frame_type_string(uint8_t frame_type, uint8_t frame_subtype);
const char* get_management_subtype_string(uint8_t subtype);
void print_mac_address(const uint8_t* mac);
bool is_interesting_frame(uint8_t frame_type, uint8_t frame_subtype);

void setup() {
  Serial.begin(115200);
  delay(2000); // Longer delay to avoid boot noise
  
  Serial.println("\n=== ESP32 WiFi Packet Sniffer ===");
  Serial.println("IAESTE Internship - Ege University");
  Serial.println("Computer Engineering - Almoulla Al Maawali");
  Serial.println("=====================================\n");

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // Initialize WiFi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_start());

  // Configure WiFi sniffer
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
  ESP_ERROR_CHECK(esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE));

  Serial.printf("WiFi Sniffer initialized on channel %d\n", current_channel);
  Serial.println("Capturing interesting packets...\n");
  Serial.println("Format: [Channel] [Frame Type] [RSSI] [Source MAC] [Destination MAC] [Additional Info]");
  Serial.println("----------------------------------------------------------------");
}

void loop() {
  // Switch channels periodically to capture more devices
  if (millis() - last_channel_switch > WIFI_CHANNEL_SWITCH_INTERVAL) {
    switch_wifi_channel();
  }
  
  delay(10); // Small delay to prevent watchdog issues
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MISC) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
    wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;
    
    // Extract frame control field
    uint16_t frame_control = pkt->payload[0] | (pkt->payload[1] << 8);
    uint8_t frame_type = (frame_control >> 2) & 0x03;
    uint8_t frame_subtype = (frame_control >> 4) & 0x0F;
    
    // Only process interesting frames to reduce spam
    if (!is_interesting_frame(frame_type, frame_subtype)) {
      frame_count++;
      return;
    }
    
    // Extract MAC addresses (positions depend on frame type)
    uint8_t* addr1 = &pkt->payload[4];  // Destination address
    uint8_t* addr2 = &pkt->payload[10]; // Source address
    uint8_t* addr3 = &pkt->payload[16]; // BSSID (for management frames)
    
    // Print frame information
    Serial.printf("[CH%d] ", current_channel);
    Serial.printf("[%s] ", get_frame_type_string(frame_type, frame_subtype));
    Serial.printf("[RSSI:%d] ", ctrl.rssi);
    Serial.print("[SRC:");
    print_mac_address(addr2);
    Serial.print("] [DST:");
    print_mac_address(addr1);
    Serial.print("]");
    
    // Additional info for management frames
    if (frame_type == WIFI_MANAGEMENT_FRAME) {
      if (frame_subtype == WIFI_BEACON_FRAME) {
        // Try to extract SSID from beacon frame
        if (pkt->rx_ctrl.sig_len > 36) {
          uint8_t ssid_len = pkt->payload[37];
          if (ssid_len > 0 && ssid_len <= 32) {
            Serial.print(" [SSID:");
            for (int i = 0; i < ssid_len; i++) {
              Serial.print((char)pkt->payload[38 + i]);
            }
            Serial.print("]");
          }
        }
      } else if (frame_subtype == WIFI_PROBE_REQUEST) {
        // Try to extract SSID from probe request
        if (pkt->rx_ctrl.sig_len > 24) {
          uint8_t ssid_len = pkt->payload[25];
          if (ssid_len > 0 && ssid_len <= 32) {
            Serial.print(" [SSID:");
            for (int i = 0; i < ssid_len; i++) {
              Serial.print((char)pkt->payload[26 + i]);
            }
            Serial.print("]");
          }
        }
      }
    }
    
    Serial.println();
    frame_count++;
    interesting_frame_count++;
    
    // Print statistics every 50 interesting frames
    if (interesting_frame_count % 50 == 0) {
      Serial.printf("\n--- Statistics: %d interesting frames, %d total frames on channel %d ---\n", 
                   interesting_frame_count, frame_count, current_channel);
    }
  }
}

bool is_interesting_frame(uint8_t frame_type, uint8_t frame_subtype) {
  // Filter out common spam frames
  if (frame_type == WIFI_MANAGEMENT_FRAME) {
    switch (frame_subtype) {
      case WIFI_BEACON_FRAME:
        return true; // Show beacons (but they're common)
      case WIFI_PROBE_REQUEST:
        return true; // Show probe requests (devices looking for networks)
      case WIFI_PROBE_RESPONSE:
        return true; // Show probe responses
      case WIFI_ASSOCIATION_REQUEST:
        return true; // Show when devices connect
      case WIFI_ASSOCIATION_RESPONSE:
        return true; // Show connection responses
      case WIFI_DISASSOCIATION:
        return true; // Show when devices disconnect
      case WIFI_AUTHENTICATION:
        return true; // Show authentication
      case WIFI_DEAUTHENTICATION:
        return true; // Show deauthentication
      default:
        return false; // Filter out other management frames
    }
  } else if (frame_type == WIFI_DATA_FRAME) {
    return false; // Filter out most data frames (too much spam)
  } else if (frame_type == WIFI_CONTROL_FRAME) {
    return false; // Filter out control frames (too much spam)
  }
  return false;
}

void switch_wifi_channel() {
  current_channel = (current_channel % WIFI_CHANNEL_MAX) + 1;
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  last_channel_switch = millis();
  Serial.printf("\n--- Switched to channel %d ---\n", current_channel);
}

const char* get_frame_type_string(uint8_t frame_type, uint8_t frame_subtype) {
  switch (frame_type) {
    case WIFI_MANAGEMENT_FRAME:
      return get_management_subtype_string(frame_subtype);
    case WIFI_CONTROL_FRAME:
      return "CTRL";
    case WIFI_DATA_FRAME:
      return "DATA";
    default:
      return "UNKN";
  }
}

const char* get_management_subtype_string(uint8_t subtype) {
  switch (subtype) {
    case WIFI_BEACON_FRAME:
      return "BEACON";
    case WIFI_PROBE_REQUEST:
      return "PROBE_REQ";
    case WIFI_PROBE_RESPONSE:
      return "PROBE_RESP";
    case WIFI_ASSOCIATION_REQUEST:
      return "ASSOC_REQ";
    case WIFI_ASSOCIATION_RESPONSE:
      return "ASSOC_RESP";
    case WIFI_DISASSOCIATION:
      return "DISASSOC";
    case WIFI_AUTHENTICATION:
      return "AUTH";
    case WIFI_DEAUTHENTICATION:
      return "DEAUTH";
    default:
      return "MGMT";
  }
}

void print_mac_address(const uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    if (i > 0) Serial.print(":");
    if (mac[i] < 0x10) Serial.print("0");
    Serial.print(mac[i], HEX);
  }
} 