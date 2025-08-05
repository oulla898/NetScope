// i belive this version is the latest
// Project Title: Wi-Fi Packet Sniffer with Professional Display Interface
// Objective: ESP32 WiFi sniffer with 1.3" ST7789 display showing network intelligence
//
// IAESTE Internship - Ege University - Almoulla Al Maawali
//
// Display + WiFi Sniffer Integration with Professional UI - FIXED VERSION

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "driver/gpio.h"
#include "driver/rtc_io.h"
#include <lvgl.h>
#include <LovyanGFX.hpp>
#include <map>
#include <vector>
#include <algorithm>
#include <set>

// Display configuration for ST7789VW
class LGFX : public lgfx::LGFX_Device {
    lgfx::Panel_ST7789 _panel_instance;
    lgfx::Bus_SPI _bus_instance;

public:
    LGFX(void) {
        { // Configure bus
            auto cfg = _bus_instance.config();
            cfg.spi_host = VSPI_HOST;  // ESP32-WROVER-KIT uses VSPI
            cfg.spi_mode = 3;  // CRITICAL for ST7789VW
            cfg.freq_write = 80000000;  // Full speed for stability
            cfg.pin_sclk = 18;
            cfg.pin_mosi = 23;
            cfg.pin_miso = -1;
            cfg.pin_dc = 5;  // GPIO 5 - no boot conflicts
            _bus_instance.config(cfg);
            _panel_instance.setBus(&_bus_instance);
        }
        { // Configure panel
            auto cfg = _panel_instance.config();
            cfg.pin_cs = -1;
            cfg.pin_rst = 4;   // RST connected to GPIO 4
            cfg.panel_width = 240;
            cfg.panel_height = 240;
            cfg.offset_rotation = 0;  // Correct orientation
            cfg.readable = false;
            cfg.invert = true;
            cfg.rgb_order = true;
            cfg.bus_shared = true;
            cfg.offset_x = 0;          // X offset
            cfg.offset_y = 0;          // Y offset
            _panel_instance.config(cfg);
        }
        setPanel(&_panel_instance);
    }
};

// WiFi sniffer configuration
#define WIFI_CHANNEL_MAX 13
#define WIFI_CHANNEL_SWITCH_INTERVAL 3000  // 3 seconds per channel
#define WIFI_MANAGEMENT_FRAME 0x00
#define WIFI_CONTROL_FRAME 0x01
#define WIFI_DATA_FRAME 0x02

// Management frame subtypes
#define WIFI_BEACON_FRAME 0x08
#define WIFI_PROBE_REQUEST 0x04
#define WIFI_PROBE_RESPONSE 0x05
#define WIFI_ASSOCIATION_REQUEST 0x00
#define WIFI_ASSOCIATION_RESPONSE 0x01
#define WIFI_REASSOCIATION_REQUEST 0x02
#define WIFI_REASSOCIATION_RESPONSE 0x03
#define WIFI_DISASSOCIATION 0x0A
#define WIFI_AUTHENTICATION 0x0B
#define WIFI_DEAUTHENTICATION 0x0C

// Touch pins (avoiding display pins 18, 23, 2, 4)
#define PIN_NEXT 32  // PIN 32: Next card
#define PIN_SCROLL 33  // PIN 33: Scroll within card

// Target phone MAC (your phone's WiFi MAC)
const char* TARGET_PHONE = "C4:EF:3D:B3:23:BD";

// Data structures
struct APInfo {
    String ssid;
    String bssid;
    int channel;
    int rssi;
    int client_count;
    String security;
    unsigned long last_seen;
    int beacon_count;
    std::set<String> associated_clients;
};

struct ClientInfo {
    String mac;
    String connected_ap;
    int rssi;
    String vendor;
    unsigned long last_seen;
    int frame_count;
    bool is_associated;
};

struct ChannelStats {
    int ap_count;
    int total_frames;
    int avg_rssi;
    unsigned long last_activity;
};

// Device registry for serial output
struct DeviceInfo {
    String mac;
    int rssi;
    unsigned long last_seen;
    int frame_count;
    String device_type;
};

// Add these new structures for target phone tracking
struct TargetPacketInfo {
    unsigned long timestamp;
    String frame_type;
    int rssi;
    String direction; // "TX" or "RX"
    String details;
};

// Anomaly detection structures
struct AnomalyTracker {
    String mac;
    int probe_count;
    int deauth_count;
    int beacon_count;
    int assoc_count;
    std::set<int> channels_seen;
    unsigned long first_seen;
    unsigned long last_seen;
    bool is_flagged;
    String threat_type;
    unsigned long last_reset;
};

struct AnomalyAlert {
    String mac;
    String threat_type;
    int count;
    unsigned long timestamp;
    String details;
};

// Enhanced Serial output control system
enum OutputMode { 
    SILENT,     // Only critical alerts
    QUIET,      // Anomalies + new device discoveries  
    NORMAL,     // Intelligent summaries + important events (DEFAULT)
    VERBOSE,    // Rate-limited packet samples + analysis
    DEBUG,      // Full technical details (rate-limited)
    ANALYST     // Professional network intelligence format
};
OutputMode current_serial_mode = NORMAL;

// Rate limiting and smart filtering
struct SerialRateLimit {
    unsigned long last_print_time = 0;
    int print_count = 0;
    unsigned long window_start = 0;
    static const int MAX_PRINTS_PER_SECOND = 5;
    static const int WINDOW_SIZE_MS = 1000;
};

SerialRateLimit packet_rate_limiter;
SerialRateLimit event_rate_limiter;

// Event tracking for intelligent notifications
struct NotificationEvent {
    String type;
    String message;
    unsigned long timestamp;
    int priority; // 1=critical, 2=important, 3=info
};

std::vector<NotificationEvent> recent_events;
unsigned long last_dashboard_update = 0;
unsigned long last_intelligence_report = 0;

// Anomaly detection thresholds
#define PROBE_FLOOD_THRESHOLD 10
#define PROBE_FLOOD_WINDOW 30000  // 30 seconds
#define DEAUTH_ATTACK_THRESHOLD 5
#define DEAUTH_ATTACK_WINDOW 10000  // 10 seconds
#define BEACON_FLOOD_THRESHOLD 50
#define BEACON_FLOOD_WINDOW 30000  // 30 seconds
#define ASSOC_FLOOD_THRESHOLD 10
#define ASSOC_FLOOD_WINDOW 30000  // 30 seconds
#define CHANNEL_HOPPING_THRESHOLD 5
#define CHANNEL_HOPPING_WINDOW 10000  // 10 seconds

#define MAX_TARGET_PACKETS 20
std::vector<TargetPacketInfo> target_packets;
String target_ip = "Scanning...";
int target_tx_packets = 0;
int target_rx_packets = 0;
String target_ssid = "Unknown";

// Global variables
LGFX tft;
static lv_disp_draw_buf_t draw_buf;
static lv_color_t buf[240 * 20];

// UI State
enum UICard { AP_HOTSPOTS, CLIENT_ANALYSIS, TARGET_HUNT, SIGNAL_MAP, NETWORK_INTEL, THREATS, SYSTEM_STATUS };
UICard current_card = AP_HOTSPOTS;
int scroll_pos = 0;
uint32_t frame_count = 0;

// WiFi Data
std::map<String, APInfo> ap_registry;
std::map<String, ClientInfo> client_registry;
std::map<String, DeviceInfo> device_registry;
ChannelStats channel_stats[14]; // Index 0 unused, 1-13 for channels
int current_channel = 1;
uint32_t last_channel_switch = 0;
int total_frames = 0;
int mgmt_frames = 0;
int data_frames = 0;
int ctrl_frames = 0;

// Target tracking
bool target_found = false;
int target_rssi = 0;
String target_ap = "";
unsigned long target_last_seen = 0;

// Anomaly detection system
std::map<String, AnomalyTracker> anomaly_trackers;
std::vector<AnomalyAlert> anomaly_alerts;
int total_threats = 0;
int flagged_macs = 0;
unsigned long last_anomaly_check = 0;

// Touch handling
bool pin32_pressed = false;
bool pin33_pressed = false;
unsigned long pin32_press_time = 0;
unsigned long pin33_press_time = 0;
unsigned long last_touch_time = 0;
unsigned long last_display_update = 0;

// UI Objects
lv_obj_t* main_screen;
lv_obj_t* title_label;
lv_obj_t* content_area;

// Enhanced display configuration for cooler UI
lv_obj_t* signal_bar = nullptr;
lv_obj_t* progress_arc = nullptr;
lv_obj_t* status_indicator = nullptr;
int animation_counter = 0;

// Color scheme
#define COLOR_PRIMARY    0x00ff88    // Bright green
#define COLOR_SECONDARY  0x00aaff    // Bright blue  
#define COLOR_ACCENT     0xff6600    // Orange
#define COLOR_WARNING    0xffaa00    // Yellow
#define COLOR_DANGER     0xff3333    // Red
#define COLOR_BG_DARK    0x1a1a1a    // Dark background
#define COLOR_TEXT_DIM   0x888888    // Dim text
#define COLOR_TEXT_BRIGHT 0xffffff   // Bright text

// Create animated signal strength bars
void create_signal_bars(lv_obj_t* parent, int x, int y, int rssi) {
    int bars = 5;
    int signal_strength = (rssi + 100) / 10; // Convert RSSI to 0-10 scale
    if (signal_strength > 5) signal_strength = 5;
    if (signal_strength < 0) signal_strength = 0;
    
    for (int i = 0; i < bars; i++) {
        lv_obj_t* bar = lv_obj_create(parent);
        lv_obj_set_size(bar, 6, 8 + (i * 4));
        lv_obj_set_pos(bar, x + (i * 8), y - (i * 4));
        
        // Color based on signal strength
        lv_color_t bar_color;
        if (i < signal_strength) {
            if (signal_strength >= 4) bar_color = lv_color_hex(COLOR_PRIMARY);
            else if (signal_strength >= 2) bar_color = lv_color_hex(COLOR_WARNING);
            else bar_color = lv_color_hex(COLOR_DANGER);
        } else {
            bar_color = lv_color_hex(COLOR_TEXT_DIM);
        }
        
        lv_obj_set_style_bg_color(bar, bar_color, LV_PART_MAIN);
        lv_obj_set_style_border_width(bar, 0, LV_PART_MAIN);
        lv_obj_set_style_radius(bar, 2, LV_PART_MAIN);
    }
}

// Create animated progress arc
void create_progress_arc(lv_obj_t* parent, int x, int y, int percentage, lv_color_t color) {
    lv_obj_t* arc = lv_arc_create(parent);
    lv_obj_set_size(arc, 60, 60);
    lv_obj_set_pos(arc, x, y);
    lv_arc_set_range(arc, 0, 100);
    lv_arc_set_value(arc, percentage);
    
    lv_obj_set_style_arc_color(arc, color, LV_PART_MAIN);
    lv_obj_set_style_arc_color(arc, lv_color_hex(COLOR_TEXT_DIM), LV_PART_INDICATOR);
    lv_obj_set_style_arc_width(arc, 8, LV_PART_MAIN);
    lv_obj_set_style_arc_width(arc, 8, LV_PART_INDICATOR);
    
    // Remove knob
    lv_obj_clear_flag(arc, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_style_bg_opa(arc, LV_OPA_TRANSP, LV_PART_KNOB);
}

// Helper functions
String mac_to_str(const uint8_t* mac) {
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(buf);
}

String get_vendor_from_mac(const String& mac) {
    // Simple vendor detection based on OUI
    if (mac.startsWith("00:16:B6") || mac.startsWith("DC:A6:32")) return "RaspPi";
    if (mac.startsWith("AC:DE:48") || mac.startsWith("F0:18:98")) return "Apple";
    if (mac.startsWith("28:11:A5") || mac.startsWith("34:2E:B7")) return "Samsung";
    if (mac.startsWith("00:50:56")) return "VMware";
    if (mac.startsWith("08:00:27")) return "VBox";
    return "Unknown";
}

String get_security_from_beacon(const uint8_t* payload, int len) {
    // Parse capability info and RSN/WPA information elements
    if (len > 34) {
        uint16_t capability = payload[34] | (payload[35] << 8);
        if (capability & 0x0010) {
            // Look for RSN/WPA IEs in the rest of the frame
            for (int i = 36; i < len - 2; i++) {
                if (payload[i] == 0x30) return "WPA2"; // RSN IE
                if (payload[i] == 0xDD && i + 4 < len && 
                    payload[i+2] == 0x00 && payload[i+3] == 0x50 && payload[i+4] == 0xF2) return "WPA"; // WPA IE
            }
            return "WEP";
        }
    }
    return "Open";
}

// Helper function to find closest AP by RSSI and timing
String find_closest_ap(const String& client_mac, int client_rssi, unsigned long client_time) {
    String closest_ap = "";
    int best_score = -999;
    
    for (const auto& kv : ap_registry) {
        const APInfo& ap = kv.second;
        // AP must be recently active and on same or recent channel
        if (millis() - ap.last_seen < 10000) {
            // Score based on RSSI similarity and time proximity
            int rssi_diff = abs(client_rssi - ap.rssi);
            int time_diff = abs((long)(client_time - ap.last_seen)) / 1000;
            int score = -rssi_diff - time_diff;
            
            if (score > best_score) {
                best_score = score;
                closest_ap = ap.bssid;
            }
        }
    }
    
    return closest_ap;
}

// Update AP client counts based on proximity
void update_ap_client_associations() {
    // Reset all client counts
    for (auto& kv : ap_registry) {
        kv.second.client_count = 0;
        kv.second.associated_clients.clear();
    }
    
    // Associate clients to nearest APs
    for (const auto& kv : client_registry) {
        const ClientInfo& client = kv.second;
        
        // Find the closest AP for this client
        String closest_ap = find_closest_ap(client.mac, client.rssi, client.last_seen);
        if (closest_ap.length() > 0) {
            if (ap_registry.find(closest_ap) != ap_registry.end()) {
                ap_registry[closest_ap].associated_clients.insert(client.mac);
                ap_registry[closest_ap].client_count++;
            }
        }
    }
}

// Forward declarations for functions used by anomaly detection
void add_notification(const String& type, const String& message, int priority = 2);
void print_notification(const NotificationEvent& event);
bool should_print_event(int priority);

// Anomaly detection functions
void track_anomaly(const String& mac, const String& frame_type, int channel) {
    AnomalyTracker& tracker = anomaly_trackers[mac];
    tracker.mac = mac;
    tracker.last_seen = millis();
    
    if (tracker.first_seen == 0) {
        tracker.first_seen = millis();
        tracker.last_reset = millis();
    }
    
    // Track frame types
    if (frame_type == "PROBE_REQ") tracker.probe_count++;
    else if (frame_type == "DEAUTH") tracker.deauth_count++;
    else if (frame_type == "BEACON") tracker.beacon_count++;
    else if (frame_type == "ASSOC_REQ" || frame_type == "REASSOC_REQ") tracker.assoc_count++;
    
    // Track channels
    tracker.channels_seen.insert(channel);
}

void check_anomaly_thresholds() {
    unsigned long now = millis();
    
    for (auto& kv : anomaly_trackers) {
        AnomalyTracker& tracker = kv.second;
        bool anomaly_detected = false;
        String threat_type = "";
        int count = 0;
        
        // Check probe flood
        if (tracker.probe_count >= PROBE_FLOOD_THRESHOLD && 
            (now - tracker.last_reset) <= PROBE_FLOOD_WINDOW) {
            anomaly_detected = true;
            threat_type = "PROBE_FLOOD";
            count = tracker.probe_count;
        }
        
        // Check deauth attack
        if (tracker.deauth_count >= DEAUTH_ATTACK_THRESHOLD && 
            (now - tracker.last_reset) <= DEAUTH_ATTACK_WINDOW) {
            anomaly_detected = true;
            threat_type = "DEAUTH_ATTACK";
            count = tracker.deauth_count;
        }
        
        // Check beacon flood
        if (tracker.beacon_count >= BEACON_FLOOD_THRESHOLD && 
            (now - tracker.last_reset) <= BEACON_FLOOD_WINDOW) {
            anomaly_detected = true;
            threat_type = "BEACON_FLOOD";
            count = tracker.beacon_count;
        }
        
        // Check association flood
        if (tracker.assoc_count >= ASSOC_FLOOD_THRESHOLD && 
            (now - tracker.last_reset) <= ASSOC_FLOOD_WINDOW) {
            anomaly_detected = true;
            threat_type = "ASSOC_FLOOD";
            count = tracker.assoc_count;
        }
        
        // Check channel hopping
        if (tracker.channels_seen.size() >= CHANNEL_HOPPING_THRESHOLD && 
            (now - tracker.last_reset) <= CHANNEL_HOPPING_WINDOW) {
            anomaly_detected = true;
            threat_type = "CHANNEL_HOPPING";
            count = tracker.channels_seen.size();
        }
        
        if (anomaly_detected && !tracker.is_flagged) {
            // Generate alert
            AnomalyAlert alert;
            alert.mac = tracker.mac;
            alert.threat_type = threat_type;
            alert.count = count;
            alert.timestamp = now;
            alert.details = "Threshold exceeded";
            
            anomaly_alerts.push_back(alert);
            if (anomaly_alerts.size() > 20) {
                anomaly_alerts.erase(anomaly_alerts.begin());
            }
            
            tracker.is_flagged = true;
            tracker.threat_type = threat_type;
            total_threats++;
            flagged_macs++;
            
            // Use new notification system for anomaly alerts
            String alert_msg = String(threat_type) + " from " + tracker.mac.substring(9) + 
                             " (count: " + count + ")";
            add_notification("THREAT_DETECTED", alert_msg, 1); // Critical priority
        }
    }
    
    // Reset counters periodically
    for (auto& kv : anomaly_trackers) {
        AnomalyTracker& tracker = kv.second;
        if ((now - tracker.last_reset) > 60000) { // Reset every minute
            tracker.probe_count = 0;
            tracker.deauth_count = 0;
            tracker.beacon_count = 0;
            tracker.assoc_count = 0;
            tracker.channels_seen.clear();
            tracker.last_reset = now;
        }
    }
}

// Smart rate limiting function
bool can_print_with_rate_limit(SerialRateLimit& limiter) {
    unsigned long now = millis();
    
    // Reset window if needed
    if (now - limiter.window_start >= SerialRateLimit::WINDOW_SIZE_MS) {
        limiter.window_start = now;
        limiter.print_count = 0;
    }
    
    // Check if we can print
    if (limiter.print_count < SerialRateLimit::MAX_PRINTS_PER_SECOND) {
        limiter.print_count++;
        limiter.last_print_time = now;
        return true;
    }
    
    return false;
}

// Add notification event to queue
void add_notification(const String& type, const String& message, int priority) {
    // SILENT mode: NO NOTIFICATIONS AT ALL
    if (current_serial_mode == SILENT) return;
    
    NotificationEvent event;
    event.type = type;
    event.message = message;
    event.timestamp = millis();
    event.priority = priority;
    
    recent_events.push_back(event);
    
    // Keep only recent events (max 20)
    if (recent_events.size() > 20) {
        recent_events.erase(recent_events.begin());
    }
    
    // Print immediately if important enough for current mode
    if (should_print_event(priority)) {
        print_notification(event);
    }
}

// Professional notification formatter
void print_notification(const NotificationEvent& event) {
    // SILENT mode: NO NOTIFICATIONS AT ALL
    if (current_serial_mode == SILENT) return;
    
    if (!can_print_with_rate_limit(event_rate_limiter)) return;
    
    char time_str[16];
    unsigned long seconds = event.timestamp / 1000;
    int hours = seconds / 3600;
    int minutes = (seconds % 3600) / 60;
    int secs = seconds % 60;
    sprintf(time_str, "%02d:%02d:%02d", hours, minutes, secs);
    
    String priority_icon;
    switch (event.priority) {
        case 1: priority_icon = "🚨"; break; // Critical
        case 2: priority_icon = "⚠️ "; break; // Important  
        case 3: priority_icon = "ℹ️ "; break; // Info
        default: priority_icon = "🔸"; break;
    }
    
    Serial.printf("[%s] %s %s: %s\n", time_str, priority_icon.c_str(), 
                  event.type.c_str(), event.message.c_str());
}

// Enhanced serial mode control
void set_serial_mode(OutputMode mode) {
    current_serial_mode = mode;
    
    // Clear screen for better readability
    Serial.print("\033[2J\033[H");
    
    Serial.println("\n" + String(60, '='));
    Serial.printf("📱 SERIAL MODE CHANGED\n");
    Serial.println(String(60, '='));
    
    switch (mode) {
        case SILENT:
            Serial.println("🔇 SILENT: Only critical system alerts");
            break;
        case QUIET:
            Serial.println("🤫 QUIET: Anomalies + new device discoveries");
            break;
        case NORMAL:
            Serial.println("📊 NORMAL: Intelligent summaries + important events");
            break;
        case VERBOSE:
            Serial.println("📋 VERBOSE: Rate-limited packet samples + analysis");
            break;
        case DEBUG:
            Serial.println("🔧 DEBUG: Full technical details (rate-limited)");
            break;
        case ANALYST:
            Serial.println("🕵️ ANALYST: Professional network intelligence format");
            break;
    }
    
    Serial.printf("Rate Limit: Max %d prints per second\n", SerialRateLimit::MAX_PRINTS_PER_SECOND);
    Serial.println(String(60, '='));
    
    // Reset rate limiters
    packet_rate_limiter = SerialRateLimit();
    event_rate_limiter = SerialRateLimit();
}

// Smart filtering for events
bool should_print_event(int priority) {
    // SILENT mode: NO EVENTS AT ALL (not even critical)
    if (current_serial_mode == SILENT) return false;
    
    switch (current_serial_mode) {
        case QUIET: return priority <= 2; // Critical + important
        case NORMAL: return priority <= 2; // Critical + important
        case VERBOSE: return priority <= 3; // All events
        case DEBUG: return priority <= 3; // All events
        case ANALYST: return priority <= 2; // Critical + important
        default: return false;
    }
}

// Smart packet filtering - only print significant packets
bool should_print_packet() {
    // COMPLETELY DISABLE ALL PACKET PRINTING IN SILENT MODE
    if (current_serial_mode == SILENT) return false;
    if (current_serial_mode == QUIET) return false;
    if (current_serial_mode == NORMAL) return false; // Normal mode doesn't show individual packets
    
    // Only allow in VERBOSE/DEBUG modes with strict rate limiting
    if (current_serial_mode == VERBOSE || current_serial_mode == DEBUG) {
        return can_print_with_rate_limit(packet_rate_limiter);
    }
    
    return false; // Default: no packet printing
}

bool should_print_summary() {
    return current_serial_mode != SILENT;
}

// Professional live dashboard
void print_live_dashboard() {
    // SILENT mode: NO DASHBOARD AT ALL
    if (current_serial_mode == SILENT) return;
    if (current_serial_mode != ANALYST && millis() - last_dashboard_update < 10000) return;
    
    last_dashboard_update = millis();
    
    // Dashboard header
    Serial.print("\033[2J\033[H"); // Clear screen
    Serial.println("┌─ ESP32 WiFi Intelligence System ────────────────────┐");
    
    // Time and uptime
    unsigned long uptime = millis() / 1000;
    int hours = uptime / 3600;
    int minutes = (uptime % 3600) / 60;
    int secs = uptime % 60;
    
    char time_str[32];
    sprintf(time_str, "🕐 %02d:%02d:%02d | Uptime: %02d:%02d:%02d", 
            hours, minutes, secs, hours, minutes, secs);
    
    Serial.printf("│ %-52s │\n", time_str);
    Serial.println("├─────────────────────────────────────────────────────┤");
    
    // Channel and activity
    int activity_level = min(10, total_frames / max(1, (int)(millis()/1000)));
    String activity_bar = "";
    for (int i = 0; i < 10; i++) {
        activity_bar += (i < activity_level) ? "█" : "▒";
    }
    
    char activity_str[64];
    sprintf(activity_str, "📡 CH: %d/13 | 🔥 Activity: %s %d/min", 
            current_channel, activity_bar.c_str(), (total_frames * 60) / max(1, (int)(millis()/1000)));
    Serial.printf("│ %-52s │\n", activity_str);
    
    // Target and devices
    char target_str[64];
    if (target_found) {
        int age_sec = (millis() - target_last_seen) / 1000;
        sprintf(target_str, "🎯 Target: FOUND (-%ddBm, %ds ago) | 📱 Devices: %d", 
                abs(target_rssi), age_sec, client_registry.size());
    } else {
        sprintf(target_str, "🎯 Target: SEARCHING... | 📱 Devices: %d", 
                client_registry.size());
    }
    Serial.printf("│ %-52s │\n", target_str);
    
    // Security analysis
    int secure = 0, open = 0;
    for (const auto& kv : ap_registry) {
        if (kv.second.security == "Open") open++;
        else secure++;
    }
    int security_pct = (secure + open > 0) ? (secure * 100) / (secure + open) : 0;
    
    char security_str[64];
    sprintf(security_str, "🏢 APs: %d | 🚨 Threats: %d | 🔒 Security: %d%%", 
            ap_registry.size(), total_threats, security_pct);
    Serial.printf("│ %-52s │\n", security_str);
    
    Serial.println("└─────────────────────────────────────────────────────┘");
}

// Network intelligence report
void print_intelligence_report() {
    // SILENT mode: NO REPORTS AT ALL
    if (current_serial_mode == SILENT) return;
    if (current_serial_mode == QUIET) return;
    if (millis() - last_intelligence_report < 30000) return; // Every 30 seconds
    
    last_intelligence_report = millis();
    
    Serial.println("\n" + String(60, '='));
    Serial.println("📊 NETWORK INTELLIGENCE REPORT");
    Serial.println(String(60, '='));
    
    // Overview
    float fps = (float)total_frames / max(1.0f, (float)(millis()/1000));
    Serial.printf("🔸 Activity: %d frames (%.1f/sec, %s trend)\n", 
                  total_frames, fps, fps > 10 ? "HIGH" : fps > 5 ? "NORMAL" : "LOW");
    
    // New discoveries notification
    static int last_ap_count = 0;
    static int last_client_count = 0;
    
    if (ap_registry.size() > last_ap_count) {
        add_notification("NEW_DISCOVERY", 
                        String("New AP discovered (total: ") + ap_registry.size() + ")", 2);
    }
    if (client_registry.size() > last_client_count) {
        add_notification("NEW_DISCOVERY", 
                        String("New device discovered (total: ") + client_registry.size() + ")", 2);
    }
    
    last_ap_count = ap_registry.size();
    last_client_count = client_registry.size();
    
    // Security assessment
    int secure = 0, open = 0, wep = 0;
    for (const auto& kv : ap_registry) {
        if (kv.second.security == "Open") open++;
        else if (kv.second.security == "WEP") wep++;
        else secure++;
    }
    
    if (open > 0) {
        Serial.printf("🔸 Security WARNING: %d open networks detected!\n", open);
        add_notification("SECURITY_RISK", 
                        String("Open networks detected: ") + open, 2);
    }
    
    // Channel analysis
    Serial.printf("🔸 Channel distribution: ");
    for (int ch = 1; ch <= 13; ch++) {
        if (channel_stats[ch].ap_count > 0) {
            Serial.printf("CH%d(%d) ", ch, channel_stats[ch].ap_count);
        }
    }
    Serial.println();
    
    // Target status
    if (target_found) {
        int age_sec = (millis() - target_last_seen) / 1000;
        Serial.printf("🔸 Target status: ACTIVE (%d dBm, %ds ago, %d TX/%d RX)\n", 
                      target_rssi, age_sec, target_tx_packets, target_rx_packets);
    } else {
        Serial.println("🔸 Target status: SEARCHING... (scanning all channels)");
    }
    
    Serial.println(String(60, '='));
}

// Device discovery notification
void notify_new_device_smart(const String& mac, const String& vendor, const String& type, int rssi) {
    // SILENT mode: NO DEVICE NOTIFICATIONS AT ALL
    if (current_serial_mode == SILENT) return;
    
    static std::set<String> notified_devices;
    
    if (notified_devices.find(mac) == notified_devices.end()) {
        notified_devices.insert(mac);
        
        String signal_quality = rssi > -50 ? "Excellent" : rssi > -60 ? "Good" : rssi > -70 ? "Fair" : "Poor";
        String message = vendor + " device (" + signal_quality + " signal, " + type + ")";
        
        add_notification("NEW_DEVICE", message, 2);
        
        // Cleanup old notifications to prevent memory leak
        if (notified_devices.size() > 100) {
            notified_devices.clear();
        }
    }
}

// Display flush callback
void my_disp_flush(lv_disp_drv_t *disp, const lv_area_t *area, lv_color_t *color_p) {
    uint32_t w = (area->x2 - area->x1 + 1);
    uint32_t h = (area->y2 - area->y1 + 1);
    
    tft.startWrite();
    tft.setAddrWindow(area->x1, area->y1, w, h);
    tft.writePixels((lgfx::rgb565_t *)&color_p->full, w * h);
    tft.endWrite();
    
    lv_disp_flush_ready(disp);
}

// Create main UI structure
void create_main_ui() {
    main_screen = lv_scr_act();
    
    // Dark gradient background
    lv_obj_set_style_bg_color(main_screen, lv_color_hex(0x0a0a2e), LV_PART_MAIN);
    lv_obj_set_style_bg_grad_color(main_screen, lv_color_hex(0x16213e), LV_PART_MAIN);
    lv_obj_set_style_bg_grad_dir(main_screen, LV_GRAD_DIR_VER, LV_PART_MAIN);
    
    // Title area
    title_label = lv_label_create(main_screen);
    lv_obj_set_pos(title_label, 10, 5);
    lv_obj_set_size(title_label, 220, 25);
    lv_obj_set_style_text_color(title_label, lv_color_hex(0x00ffff), LV_PART_MAIN);
    lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    
    // Content area
    content_area = lv_obj_create(main_screen);
    lv_obj_set_pos(content_area, 5, 35);
    lv_obj_set_size(content_area, 230, 200);
    lv_obj_set_style_bg_opa(content_area, LV_OPA_0, LV_PART_MAIN);
    lv_obj_set_style_border_opa(content_area, LV_OPA_0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(content_area, 5, LV_PART_MAIN);
}

// Update card content with cool animations and better design
void update_card_content() {
    lv_obj_clean(content_area);
    animation_counter = (animation_counter + 1) % 100;
    
    // Update AP-client associations before displaying
    update_ap_client_associations();
    
    switch(current_card) {
        case AP_HOTSPOTS: {
            lv_label_set_text(title_label, "🔥 ACCESS POINTS");
            
            // Single AP per screen
            int count = 0;
            bool found_ap = false;
            
            for (const auto& kv : ap_registry) {
                const APInfo& ap = kv.second;
                if (count < scroll_pos) { count++; continue; }
                
                found_ap = true;
                bool is_active = (millis() - ap.last_seen < 30000);
                
                // Main AP name - BIG FONT
                lv_obj_t* ap_name = lv_label_create(content_area);
                lv_obj_set_pos(ap_name, 10, 20);
                lv_obj_set_width(ap_name, 220);
                lv_label_set_text_fmt(ap_name, "\"%s\"", 
                                     ap.ssid.length() > 0 ? ap.ssid.c_str() : "Hidden Network");
                lv_obj_set_style_text_color(ap_name, is_active ? 
                    lv_color_hex(COLOR_PRIMARY) : lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                lv_obj_set_style_text_font(ap_name, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_label_set_long_mode(ap_name, LV_LABEL_LONG_SCROLL_CIRCULAR);
                
                // Signal strength bars
                create_signal_bars(content_area, 180, 65, ap.rssi);
                
                // Channel indicator with animation
                lv_obj_t* channel_box = lv_obj_create(content_area);
                lv_obj_set_size(channel_box, 40, 30);
                lv_obj_set_pos(channel_box, 10, 60);
                lv_obj_set_style_bg_color(channel_box, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_radius(channel_box, 8, LV_PART_MAIN);
                lv_obj_set_style_border_width(channel_box, 0, LV_PART_MAIN);
                
                lv_obj_t* ch_label = lv_label_create(channel_box);
                lv_obj_center(ch_label);
                lv_label_set_text_fmt(ch_label, "CH%d", ap.channel);
                lv_obj_set_style_text_color(ch_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                
                // Security badge
                lv_obj_t* sec_box = lv_obj_create(content_area);
                lv_obj_set_size(sec_box, 80, 30);
                lv_obj_set_pos(sec_box, 60, 60);
                lv_color_t sec_color = ap.security == "Open" ? 
                    lv_color_hex(COLOR_DANGER) : lv_color_hex(COLOR_PRIMARY);
                lv_obj_set_style_bg_color(sec_box, sec_color, LV_PART_MAIN);
                lv_obj_set_style_radius(sec_box, 8, LV_PART_MAIN);
                lv_obj_set_style_border_width(sec_box, 0, LV_PART_MAIN);
                
                lv_obj_t* sec_label = lv_label_create(sec_box);
                lv_obj_center(sec_label);
                lv_label_set_text(sec_label, ap.security.c_str());
                lv_obj_set_style_text_color(sec_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                
                // Client count with animated icon
                lv_obj_t* client_info = lv_label_create(content_area);
                lv_obj_set_pos(client_info, 10, 110);
                float pulse = sin(animation_counter * 0.1) * 0.3 + 0.7;
                lv_label_set_text_fmt(client_info, "Devices: %d", ap.client_count);
                lv_obj_set_style_text_color(client_info, lv_color_hex((int)(COLOR_ACCENT * pulse)), LV_PART_MAIN);
                lv_obj_set_style_text_font(client_info, &lv_font_montserrat_14, LV_PART_MAIN);
                
                // RSSI value
                lv_obj_t* rssi_label = lv_label_create(content_area);
                lv_obj_set_pos(rssi_label, 10, 140);
                lv_label_set_text_fmt(rssi_label, "Signal: %d dBm", ap.rssi);
                lv_obj_set_style_text_color(rssi_label, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
                // Age indicator
                char age_str[20];
                int age_sec = (millis() - ap.last_seen) / 1000;
                if (age_sec < 60) sprintf(age_str, "Active %ds ago", age_sec);
                else sprintf(age_str, "Active %dm ago", age_sec/60);
                
                lv_obj_t* age_label = lv_label_create(content_area);
                lv_obj_set_pos(age_label, 10, 165);
                lv_label_set_text(age_label, age_str);
                lv_obj_set_style_text_color(age_label, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
                // Navigation indicator
                lv_obj_t* nav_label = lv_label_create(content_area);
                lv_obj_set_pos(nav_label, 150, 200);
                lv_label_set_text_fmt(nav_label, "%d/%d", scroll_pos + 1, ap_registry.size());
                lv_obj_set_style_text_color(nav_label, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
                break;
            }
            
            if (!found_ap) {
                lv_obj_t* scanning = lv_label_create(content_area);
                lv_obj_set_pos(scanning, 10, 60);
                lv_obj_set_width(scanning, 220);
                float pulse = sin(animation_counter * 0.2) * 0.5 + 0.5;
                lv_label_set_text_fmt(scanning, "SCANNING...\n\nChannel: %d\nAPs found: %d", 
                                     current_channel, ap_registry.size());
                lv_obj_set_style_text_color(scanning, lv_color_hex((int)(COLOR_WARNING * pulse)), LV_PART_MAIN);
                lv_obj_set_style_text_font(scanning, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(scanning, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            }
            break;
        }
        
        case CLIENT_ANALYSIS: {
            lv_label_set_text(title_label, "📱 DEVICES");
            
            // Single client per screen
            int count = 0;
            bool found_client = false;
            
            for (const auto& kv : client_registry) {
                const ClientInfo& client = kv.second;
                if (count < scroll_pos) { count++; continue; }
                
                found_client = true;
                bool is_active = (millis() - client.last_seen < 20000);
                
                // Device MAC - BIG FONT
                lv_obj_t* mac_label = lv_label_create(content_area);
                lv_obj_set_pos(mac_label, 10, 20);
                lv_obj_set_width(mac_label, 220);
                lv_label_set_text_fmt(mac_label, "%s", client.mac.substring(9).c_str());
                lv_obj_set_style_text_color(mac_label, is_active ? 
                    lv_color_hex(COLOR_SECONDARY) : lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                lv_obj_set_style_text_font(mac_label, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(mac_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Signal strength bars
                create_signal_bars(content_area, 90, 75, client.rssi);
                
                // Vendor badge
                lv_obj_t* vendor_box = lv_obj_create(content_area);
                lv_obj_set_size(vendor_box, 100, 35);
                lv_obj_set_pos(vendor_box, 65, 85);
                lv_color_t vendor_color;
                if (client.vendor == "Apple") vendor_color = lv_color_hex(0x666666);
                else if (client.vendor == "Samsung") vendor_color = lv_color_hex(0x1f4788);
                else if (client.vendor == "RaspPi") vendor_color = lv_color_hex(0x8cc04b);
                else vendor_color = lv_color_hex(COLOR_ACCENT);
                
                lv_obj_set_style_bg_color(vendor_box, vendor_color, LV_PART_MAIN);
                lv_obj_set_style_radius(vendor_box, 10, LV_PART_MAIN);
                lv_obj_set_style_border_width(vendor_box, 0, LV_PART_MAIN);
                
                lv_obj_t* vendor_label = lv_label_create(vendor_box);
                lv_obj_center(vendor_label);
                lv_label_set_text(vendor_label, client.vendor.c_str());
                lv_obj_set_style_text_color(vendor_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                
                // Connected AP
                String ap_name = "Scanning...";
                String closest_ap = find_closest_ap(client.mac, client.rssi, client.last_seen);
                if (closest_ap.length() > 0 && ap_registry.find(closest_ap) != ap_registry.end()) {
                    ap_name = ap_registry[closest_ap].ssid;
                    if (ap_name.length() == 0) ap_name = "Hidden AP";
                }
                
                lv_obj_t* ap_info = lv_label_create(content_area);
                lv_obj_set_pos(ap_info, 10, 135);
                lv_obj_set_width(ap_info, 220);
                lv_label_set_text_fmt(ap_info, "Connected: %s", ap_name.c_str());
                lv_obj_set_style_text_color(ap_info, lv_color_hex(COLOR_PRIMARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(ap_info, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_label_set_long_mode(ap_info, LV_LABEL_LONG_SCROLL_CIRCULAR);
                
                // RSSI and age
                char age_str[20];
                int age_sec = (millis() - client.last_seen) / 1000;
                if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
                else sprintf(age_str, "%dm ago", age_sec/60);
                
                lv_obj_t* details = lv_label_create(content_area);
                lv_obj_set_pos(details, 10, 165);
                lv_label_set_text_fmt(details, "%d dBm • %s", client.rssi, age_str);
                lv_obj_set_style_text_color(details, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
                // Navigation indicator
                lv_obj_t* nav_label = lv_label_create(content_area);
                lv_obj_set_pos(nav_label, 150, 200);
                lv_label_set_text_fmt(nav_label, "%d/%d", scroll_pos + 1, client_registry.size());
                lv_obj_set_style_text_color(nav_label, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
                break;
            }
            
            if (!found_client) {
                lv_obj_t* scanning = lv_label_create(content_area);
                lv_obj_set_pos(scanning, 10, 60);
                lv_obj_set_width(scanning, 220);
                float pulse = sin(animation_counter * 0.2) * 0.5 + 0.5;
                lv_label_set_text_fmt(scanning, "DETECTING...\n\nDevices found: %d\nListening for probes", 
                                     client_registry.size());
                lv_obj_set_style_text_color(scanning, lv_color_hex((int)(COLOR_SECONDARY * pulse)), LV_PART_MAIN);
                lv_obj_set_style_text_font(scanning, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(scanning, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            }
            break;
        }
        
        case TARGET_HUNT: {
            lv_label_set_text(title_label, "🎯 TARGET HUNT");
            
            // Single clean page with all target info
            if (target_found) {
                // Status box at top
                lv_obj_t* status_box = lv_obj_create(content_area);
                lv_obj_set_size(status_box, 220, 40);
                lv_obj_set_pos(status_box, 10, 20);
                float pulse = sin(animation_counter * 0.3) * 0.3 + 0.7;
                lv_obj_set_style_bg_color(status_box, lv_color_hex((int)(COLOR_PRIMARY * pulse)), LV_PART_MAIN);
                lv_obj_set_style_radius(status_box, 10, LV_PART_MAIN);
                lv_obj_set_style_border_width(status_box, 0, LV_PART_MAIN);
                
                lv_obj_t* status_text = lv_label_create(status_box);
                lv_obj_center(status_text);
                lv_label_set_text(status_text, "TARGET ACQUIRED");
                lv_obj_set_style_text_color(status_text, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                lv_obj_set_style_text_font(status_text, &lv_font_montserrat_14, LV_PART_MAIN);
                
                // MAC address
                lv_obj_t* mac_info = lv_label_create(content_area);
                lv_obj_set_pos(mac_info, 10, 75);
                lv_obj_set_width(mac_info, 220);
                lv_label_set_text_fmt(mac_info, "MAC: %s", String(TARGET_PHONE).substring(9).c_str());
                lv_obj_set_style_text_color(mac_info, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(mac_info, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(mac_info, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Signal strength with visual bar
                lv_obj_t* signal_label = lv_label_create(content_area);
                lv_obj_set_pos(signal_label, 10, 100);
                lv_label_set_text_fmt(signal_label, "Signal: %d dBm", target_rssi);
                lv_obj_set_style_text_color(signal_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                
                // Signal strength bar
                lv_obj_t* signal_bg = lv_obj_create(content_area);
                lv_obj_set_size(signal_bg, 180, 8);
                lv_obj_set_pos(signal_bg, 120, 105);
                lv_obj_set_style_bg_color(signal_bg, lv_color_hex(0x333333), LV_PART_MAIN);
                lv_obj_set_style_radius(signal_bg, 4, LV_PART_MAIN);
                lv_obj_set_style_border_width(signal_bg, 0, LV_PART_MAIN);
                
                int signal_width = (target_rssi + 100) * 180 / 100;
                if (signal_width < 0) signal_width = 0;
                if (signal_width > 180) signal_width = 180;
                
                lv_obj_t* signal_fill = lv_obj_create(content_area);
                lv_obj_set_size(signal_fill, signal_width, 8);
                lv_obj_set_pos(signal_fill, 120, 105);
                lv_color_t signal_color = signal_width > 120 ? lv_color_hex(COLOR_PRIMARY) :
                                         signal_width > 60 ? lv_color_hex(COLOR_WARNING) : lv_color_hex(COLOR_DANGER);
                lv_obj_set_style_bg_color(signal_fill, signal_color, LV_PART_MAIN);
                lv_obj_set_style_radius(signal_fill, 4, LV_PART_MAIN);
                lv_obj_set_style_border_width(signal_fill, 0, LV_PART_MAIN);
                
                // Network info
                lv_obj_t* network_info = lv_label_create(content_area);
                lv_obj_set_pos(network_info, 10, 125);
                lv_obj_set_width(network_info, 220);
                String network_text = target_ssid.length() > 0 ? target_ssid : "Unknown Network";
                lv_label_set_text_fmt(network_info, "Network: %s", network_text.c_str());
                lv_obj_set_style_text_color(network_info, lv_color_hex(COLOR_ACCENT), LV_PART_MAIN);
                lv_obj_set_style_text_align(network_info, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // IP address
                lv_obj_t* ip_info = lv_label_create(content_area);
                lv_obj_set_pos(ip_info, 10, 145);
                lv_obj_set_width(ip_info, 220);
                lv_label_set_text_fmt(ip_info, "IP: %s", target_ip.c_str());
                lv_obj_set_style_text_color(ip_info, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_text_align(ip_info, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Activity counters
                lv_obj_t* activity_box = lv_obj_create(content_area);
                lv_obj_set_size(activity_box, 220, 30);
                lv_obj_set_pos(activity_box, 10, 170);
                lv_obj_set_style_bg_color(activity_box, lv_color_hex(0x2a2a2a), LV_PART_MAIN);
                lv_obj_set_style_radius(activity_box, 8, LV_PART_MAIN);
                lv_obj_set_style_border_width(activity_box, 0, LV_PART_MAIN);
                
                lv_obj_t* activity_text = lv_label_create(activity_box);
                lv_obj_center(activity_text);
                char age_str[10];
                int age_sec = (millis() - target_last_seen) / 1000;
                if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
                else sprintf(age_str, "%dm ago", age_sec/60);
                lv_label_set_text_fmt(activity_text, "TX: %d | RX: %d | Last: %s", 
                                     target_tx_packets, target_rx_packets, age_str);
                lv_obj_set_style_text_color(activity_text, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                
            } else {
                // Not found - clean searching display
                lv_obj_t* search_box = lv_obj_create(content_area);
                lv_obj_set_size(search_box, 220, 80);
                lv_obj_set_pos(search_box, 10, 60);
                float pulse = sin(animation_counter * 0.4) * 0.5 + 0.5;
                lv_obj_set_style_bg_color(search_box, lv_color_hex((int)(COLOR_WARNING * pulse)), LV_PART_MAIN);
                lv_obj_set_style_radius(search_box, 15, LV_PART_MAIN);
                lv_obj_set_style_border_width(search_box, 0, LV_PART_MAIN);
                
                lv_obj_t* search_text = lv_label_create(search_box);
                lv_obj_center(search_text);
                lv_label_set_text_fmt(search_text, "SCANNING...\n\nChannel: %d\nTargeting: %s", 
                                     current_channel, String(TARGET_PHONE).substring(9).c_str());
                lv_obj_set_style_text_color(search_text, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                lv_obj_set_style_text_font(search_text, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(search_text, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Scanning progress bar
                lv_obj_t* progress_bg = lv_obj_create(content_area);
                lv_obj_set_size(progress_bg, 200, 10);
                lv_obj_set_pos(progress_bg, 20, 160);
                lv_obj_set_style_bg_color(progress_bg, lv_color_hex(0x333333), LV_PART_MAIN);
                lv_obj_set_style_radius(progress_bg, 5, LV_PART_MAIN);
                lv_obj_set_style_border_width(progress_bg, 0, LV_PART_MAIN);
                
                int progress_width = ((animation_counter * 4) % 200);
                lv_obj_t* progress_fill = lv_obj_create(content_area);
                lv_obj_set_size(progress_fill, progress_width, 10);
                lv_obj_set_pos(progress_fill, 20, 160);
                lv_obj_set_style_bg_color(progress_fill, lv_color_hex(COLOR_WARNING), LV_PART_MAIN);
                lv_obj_set_style_radius(progress_fill, 5, LV_PART_MAIN);
                lv_obj_set_style_border_width(progress_fill, 0, LV_PART_MAIN);
                
                // Search stats
                lv_obj_t* stats_text = lv_label_create(content_area);
                lv_obj_set_pos(stats_text, 10, 185);
                lv_obj_set_width(stats_text, 220);
                lv_label_set_text_fmt(stats_text, "Packets seen: TX %d | RX %d", target_tx_packets, target_rx_packets);
                lv_obj_set_style_text_color(stats_text, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
                lv_obj_set_style_text_align(stats_text, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            }
            break;
        }
        
        case SIGNAL_MAP: {
            lv_label_set_text(title_label, "📊 SIGNAL MAP");
            
            // Channel activity graph
            lv_obj_t* graph_title = lv_label_create(content_area);
            lv_obj_set_pos(graph_title, 10, 25);
            lv_label_set_text(graph_title, "Channel Activity:");
            lv_obj_set_style_text_color(graph_title, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
            lv_obj_set_style_text_font(graph_title, &lv_font_montserrat_14, LV_PART_MAIN);
            
            // Graph background
            lv_obj_t* graph_bg = lv_obj_create(content_area);
            lv_obj_set_size(graph_bg, 220, 120);
            lv_obj_set_pos(graph_bg, 10, 50);
            lv_obj_set_style_bg_color(graph_bg, lv_color_hex(0x1a1a1a), LV_PART_MAIN);
            lv_obj_set_style_radius(graph_bg, 8, LV_PART_MAIN);
            lv_obj_set_style_border_width(graph_bg, 1, LV_PART_MAIN);
            lv_obj_set_style_border_color(graph_bg, lv_color_hex(0x444444), LV_PART_MAIN);
            
            // Draw channel bars (channels 1-13)
            int bar_width = 15;
            int bar_spacing = 2;
            int start_x = 15;
            int max_height = 100;
            
            // Find max activity for scaling
            int max_activity = 1;
            for (int ch = 1; ch <= 13; ch++) {
                if (channel_stats[ch].total_frames > max_activity) {
                    max_activity = channel_stats[ch].total_frames;
                }
            }
            
            for (int ch = 1; ch <= 13; ch++) {
                int x_pos = start_x + (ch - 1) * (bar_width + bar_spacing);
                int activity = channel_stats[ch].total_frames;
                int bar_height = max_activity > 0 ? (activity * max_height / max_activity) : 0;
                if (bar_height < 2 && activity > 0) bar_height = 2; // Minimum visible height
                
                // Bar background
                lv_obj_t* bar_bg = lv_obj_create(graph_bg);
                lv_obj_set_size(bar_bg, bar_width, max_height);
                lv_obj_set_pos(bar_bg, x_pos - 10, 110 - max_height);
                lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x333333), LV_PART_MAIN);
                lv_obj_set_style_radius(bar_bg, 2, LV_PART_MAIN);
                lv_obj_set_style_border_width(bar_bg, 0, LV_PART_MAIN);
                
                // Activity bar
                if (bar_height > 0) {
                    lv_obj_t* bar = lv_obj_create(graph_bg);
                    lv_obj_set_size(bar, bar_width, bar_height);
                    lv_obj_set_pos(bar, x_pos - 10, 110 - bar_height);
                    
                    // Color based on current channel and activity level
                    lv_color_t bar_color;
                    if (ch == current_channel) {
                        bar_color = lv_color_hex(COLOR_PRIMARY); // Current channel
                    } else if (activity > max_activity * 0.7) {
                        bar_color = lv_color_hex(COLOR_DANGER); // High activity
                    } else if (activity > max_activity * 0.3) {
                        bar_color = lv_color_hex(COLOR_WARNING); // Medium activity
                    } else {
                        bar_color = lv_color_hex(COLOR_SECONDARY); // Low activity
                    }
                    
                    lv_obj_set_style_bg_color(bar, bar_color, LV_PART_MAIN);
                    lv_obj_set_style_radius(bar, 2, LV_PART_MAIN);
                    lv_obj_set_style_border_width(bar, 0, LV_PART_MAIN);
                }
                
                // Channel number label
                lv_obj_t* ch_label = lv_label_create(content_area);
                lv_obj_set_pos(ch_label, x_pos + 8, 175);
                lv_label_set_text_fmt(ch_label, "%d", ch);
                lv_color_t label_color = (ch == current_channel) ? 
                    lv_color_hex(COLOR_PRIMARY) : lv_color_hex(COLOR_TEXT_DIM);
                lv_obj_set_style_text_color(ch_label, label_color, LV_PART_MAIN);
            }
            
            // Current channel indicator
            lv_obj_t* current_info = lv_label_create(content_area);
            lv_obj_set_pos(current_info, 10, 195);
            lv_obj_set_width(current_info, 220);
            lv_label_set_text_fmt(current_info, "Current: CH%d | Max Activity: %d frames", 
                                 current_channel, max_activity);
            lv_obj_set_style_text_color(current_info, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
            lv_obj_set_style_text_align(current_info, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            
            break;
        }
        
        case NETWORK_INTEL: {
            lv_label_set_text(title_label, "🧠 INTEL");
            
            if (scroll_pos == 0) {
                // Main stats with big numbers
                lv_obj_t* stats_grid = lv_label_create(content_area);
                lv_obj_set_pos(stats_grid, 10, 20);
                lv_obj_set_width(stats_grid, 220);
                lv_label_set_text_fmt(stats_grid, "APs: %d\nDevices: %d\nFrames: %d", 
                                     ap_registry.size(), client_registry.size(), total_frames);
                lv_obj_set_style_text_color(stats_grid, lv_color_hex(COLOR_PRIMARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(stats_grid, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(stats_grid, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Frame type breakdown
                lv_obj_t* frames_info = lv_label_create(content_area);
                lv_obj_set_pos(frames_info, 10, 130);
                lv_obj_set_width(frames_info, 220);
                lv_label_set_text_fmt(frames_info, "MGMT: %d | DATA: %d | CTRL: %d", 
                                     mgmt_frames, data_frames, ctrl_frames);
                lv_obj_set_style_text_color(frames_info, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_text_align(frames_info, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
                // Frame rate
                float fps = (float)total_frames / max(1.0f, (float)(millis()/1000));
                lv_obj_t* fps_label = lv_label_create(content_area);
                lv_obj_set_pos(fps_label, 10, 160);
                lv_obj_set_width(fps_label, 220);
                lv_label_set_text_fmt(fps_label, "Rate: %.1f frames/sec", fps);
                lv_obj_set_style_text_color(fps_label, lv_color_hex(COLOR_ACCENT), LV_PART_MAIN);
                lv_obj_set_style_text_font(fps_label, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(fps_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
                
            } else if (scroll_pos == 1) {
                // Security analysis
                int secure = 0, open = 0;
                for (const auto& kv : ap_registry) {
                    if (kv.second.security == "Open") open++;
                    else secure++;
                }
                
                lv_obj_t* sec_header = lv_label_create(content_area);
                lv_obj_set_pos(sec_header, 10, 20);
                lv_label_set_text(sec_header, "SECURITY");
                lv_obj_set_style_text_color(sec_header, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(sec_header, &lv_font_montserrat_14, LV_PART_MAIN);
                
                // Security pie chart representation
                if (secure + open > 0) {
                    int secure_pct = (secure * 100) / (secure + open);
                    create_progress_arc(content_area, 85, 60, secure_pct, lv_color_hex(COLOR_PRIMARY));
                    
                    lv_obj_t* pct_label = lv_label_create(content_area);
                    lv_obj_set_pos(pct_label, 105, 85);
                    lv_label_set_text_fmt(pct_label, "%d%%", secure_pct);
                    lv_obj_set_style_text_color(pct_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                    lv_obj_set_style_text_font(pct_label, &lv_font_montserrat_14, LV_PART_MAIN);
                }
                
                lv_obj_t* sec_stats = lv_label_create(content_area);
                lv_obj_set_pos(sec_stats, 10, 140);
                lv_obj_set_width(sec_stats, 220);
                lv_label_set_text_fmt(sec_stats, "Secure: %d\nOpen: %d", secure, open);
                lv_obj_set_style_text_color(sec_stats, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
                lv_obj_set_style_text_font(sec_stats, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(sec_stats, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            }
            break;
        }
        
        case THREATS: {
            lv_label_set_text(title_label, "🚨 THREATS");
            
            // Threat statistics
            lv_obj_t* stats_label = lv_label_create(content_area);
            lv_obj_set_pos(stats_label, 10, 20);
            lv_obj_set_width(stats_label, 220);
            lv_label_set_text_fmt(stats_label, "Active Threats: %d\nFlagged MACs: %d", total_threats, flagged_macs);
            lv_obj_set_style_text_color(stats_label, lv_color_hex(COLOR_DANGER), LV_PART_MAIN);
            lv_obj_set_style_text_font(stats_label, &lv_font_montserrat_14, LV_PART_MAIN);
            lv_obj_set_style_text_align(stats_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            
            // Recent alerts
            if (!anomaly_alerts.empty()) {
                lv_obj_t* alerts_label = lv_label_create(content_area);
                lv_obj_set_pos(alerts_label, 10, 80);
                lv_obj_set_width(alerts_label, 220);
                lv_label_set_text(alerts_label, "Recent Alerts:");
                lv_obj_set_style_text_color(alerts_label, lv_color_hex(COLOR_SECONDARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(alerts_label, &lv_font_montserrat_14, LV_PART_MAIN);
                
                int y_pos = 110;
                int count = 0;
                for (auto it = anomaly_alerts.rbegin(); it != anomaly_alerts.rend() && count < 5; ++it) {
                    lv_obj_t* alert_label = lv_label_create(content_area);
                    lv_obj_set_pos(alert_label, 10, y_pos);
                    lv_obj_set_width(alert_label, 220);
                    
                    char age_str[10];
                    int age_sec = (millis() - it->timestamp) / 1000;
                    if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
                    else sprintf(age_str, "%dm ago", age_sec/60);
                    
                    lv_label_set_text_fmt(alert_label, "%s: %s (%s)", 
                                         it->mac.substring(9).c_str(), it->threat_type.c_str(), age_str);
                    lv_obj_set_style_text_color(alert_label, lv_color_hex(COLOR_WARNING), LV_PART_MAIN);
                    lv_obj_set_style_text_font(alert_label, &lv_font_montserrat_12, LV_PART_MAIN);
                    
                    y_pos += 25;
                    count++;
                }
            } else {
                lv_obj_t* no_alerts = lv_label_create(content_area);
                lv_obj_set_pos(no_alerts, 10, 80);
                lv_obj_set_width(no_alerts, 220);
                lv_label_set_text(no_alerts, "No threats detected\nSystem is secure");
                lv_obj_set_style_text_color(no_alerts, lv_color_hex(COLOR_PRIMARY), LV_PART_MAIN);
                lv_obj_set_style_text_font(no_alerts, &lv_font_montserrat_14, LV_PART_MAIN);
                lv_obj_set_style_text_align(no_alerts, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            }
            break;
        }
        
        case SYSTEM_STATUS: {
            lv_label_set_text(title_label, "⚙️ SYSTEM");
            
            // System status with animated elements
            unsigned long uptime = millis() / 1000;
            int hours = uptime / 3600;
            int minutes = (uptime % 3600) / 60;
            int seconds = uptime % 60;
            
            lv_obj_t* uptime_label = lv_label_create(content_area);
            lv_obj_set_pos(uptime_label, 10, 30);
            lv_obj_set_width(uptime_label, 220);
            lv_label_set_text_fmt(uptime_label, "UPTIME\n%02d:%02d:%02d", hours, minutes, seconds);
            lv_obj_set_style_text_color(uptime_label, lv_color_hex(COLOR_PRIMARY), LV_PART_MAIN);
            lv_obj_set_style_text_font(uptime_label, &lv_font_montserrat_14, LV_PART_MAIN);
            lv_obj_set_style_text_align(uptime_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            
            // Memory usage (simulated)
            int memory_used = 45; // Approximate
            create_progress_arc(content_area, 85, 100, memory_used, lv_color_hex(COLOR_SECONDARY));
            
            lv_obj_t* mem_label = lv_label_create(content_area);
            lv_obj_set_pos(mem_label, 105, 125);
            lv_label_set_text_fmt(mem_label, "%d%%", memory_used);
            lv_obj_set_style_text_color(mem_label, lv_color_hex(COLOR_TEXT_BRIGHT), LV_PART_MAIN);
            
            lv_obj_t* mem_text = lv_label_create(content_area);
            lv_obj_set_pos(mem_text, 10, 170);
            lv_obj_set_width(mem_text, 220);
            lv_label_set_text(mem_text, "Memory Usage");
            lv_obj_set_style_text_color(mem_text, lv_color_hex(COLOR_TEXT_DIM), LV_PART_MAIN);
            lv_obj_set_style_text_align(mem_text, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            
            // Version info
            lv_obj_t* version = lv_label_create(content_area);
            lv_obj_set_pos(version, 10, 200);
            lv_obj_set_width(version, 220);
            lv_label_set_text(version, "ESP32 Sniffer v2.0");
            lv_obj_set_style_text_color(version, lv_color_hex(COLOR_ACCENT), LV_PART_MAIN);
            lv_obj_set_style_text_align(version, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
            break;
        }
    }
}

// Handle touch inputs
void handle_touch_input() {
    uint16_t pin32_val = touchRead(PIN_NEXT);
    uint16_t pin33_val = touchRead(PIN_SCROLL);
    
    unsigned long now = millis();
    
    // PIN 32 handling (Next card)
    if (pin32_val < 40 && !pin32_pressed) {
        pin32_pressed = true;
        pin32_press_time = now;
        last_touch_time = now;
    } else if (pin32_val >= 40 && pin32_pressed) {
        pin32_pressed = false;
        unsigned long press_duration = now - pin32_press_time;
        
        if (press_duration < 1000) {
            // Short press: Next card
            current_card = (UICard)((current_card + 1) % 7);
            scroll_pos = 0;
            update_card_content();
        } else {
            // Long press: Refresh current card
            update_card_content();
        }
    }
    
    // PIN 33 handling (Scroll)
    if (pin33_val < 40 && !pin33_pressed) {
        pin33_pressed = true;
        pin33_press_time = now;
        last_touch_time = now;
    } else if (pin33_val >= 40 && pin33_pressed) {
        pin33_pressed = false;
        unsigned long press_duration = now - pin33_press_time;
        
        if (press_duration < 1000) {
            // Short press: Scroll down
            scroll_pos++;
            if (scroll_pos > 20) scroll_pos = 0; // Wrap around
            update_card_content();
        }
    }
}

// Enhanced packet handler with target phone analysis
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
    wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
    
    total_frames++;
    channel_stats[current_channel].total_frames++;
    channel_stats[current_channel].last_activity = millis();
    
    if (type == WIFI_PKT_MGMT) {
        mgmt_frames++;
        
    uint16_t frame_control = pkt->payload[0] | (pkt->payload[1] << 8);
    uint8_t frame_type = (frame_control >> 2) & 0x03;
    uint8_t frame_subtype = (frame_control >> 4) & 0x0F;
    
        uint8_t* addr1 = &pkt->payload[4];  // Destination
        uint8_t* addr2 = &pkt->payload[10]; // Source  
        uint8_t* addr3 = &pkt->payload[16]; // BSSID
        
        String src_mac = mac_to_str(addr2);
        String dst_mac = mac_to_str(addr1);
        String bssid = mac_to_str(addr3);
        
        // Print detailed management frame info
        String frame_type_str = "";
        switch (frame_subtype) {
            case WIFI_BEACON_FRAME: frame_type_str = "BEACON"; break;
            case WIFI_PROBE_REQUEST: frame_type_str = "PROBE_REQ"; break;
            case WIFI_PROBE_RESPONSE: frame_type_str = "PROBE_RESP"; break;
            case WIFI_ASSOCIATION_REQUEST: frame_type_str = "ASSOC_REQ"; break;
            case WIFI_ASSOCIATION_RESPONSE: frame_type_str = "ASSOC_RESP"; break;
            case WIFI_REASSOCIATION_REQUEST: frame_type_str = "REASSOC_REQ"; break;
            case WIFI_REASSOCIATION_RESPONSE: frame_type_str = "REASSOC_RESP"; break;
            case WIFI_DISASSOCIATION: frame_type_str = "DISASSOC"; break;
            case WIFI_AUTHENTICATION: frame_type_str = "AUTH"; break;
            case WIFI_DEAUTHENTICATION: frame_type_str = "DEAUTH"; break;
            default: frame_type_str = "MGMT"; break;
        }
        
        // Track anomaly
        track_anomaly(src_mac, frame_type_str, current_channel);
        
        // Smart packet printing - only for debug/verbose modes with rate limiting
        if (should_print_packet()) {
            Serial.printf("[MGMT:%s] CH%d | RSSI:%d | %s→%s", 
                         frame_type_str.c_str(), current_channel, ctrl.rssi, 
                         src_mac.substring(9).c_str(), dst_mac.substring(9).c_str());
        }
        
        // Enhanced target phone detection and analysis
        bool is_target_involved = false;
        String direction = "";
        
        if (src_mac.equals(TARGET_PHONE) || dst_mac.equals(TARGET_PHONE)) {
            is_target_involved = true;
            
            // First time target detection
            if (!target_found) {
            target_found = true;
                add_notification("TARGET_FOUND", 
                               String("Target device detected! Signal: ") + ctrl.rssi + "dBm", 1);
            }
            
            target_rssi = ctrl.rssi;
            target_last_seen = millis();
            
            // Determine direction and frame type
            if (src_mac.equals(TARGET_PHONE)) {
                direction = "TX";
                target_tx_packets++;
            } else {
                direction = "RX";
                target_rx_packets++;
            }
            
            // Only print target info in debug/verbose modes
            if (should_print_packet()) {
                Serial.printf(" [🎯%s", direction.c_str());
            }
            
            // Try to extract SSID from probe requests
            if (frame_subtype == WIFI_PROBE_REQUEST && src_mac.equals(TARGET_PHONE)) {
                if (pkt->rx_ctrl.sig_len > 24) {
                    uint8_t ssid_len = pkt->payload[25];
                    if (ssid_len > 0 && ssid_len <= 32) {
                        char ssid[33] = {0};
                        memcpy(ssid, &pkt->payload[26], ssid_len);
                        String new_ssid = String(ssid);
                        
                        if (target_ssid != new_ssid) {
                            target_ssid = new_ssid;
                            if (current_serial_mode != SILENT) {
                                add_notification("TARGET_NETWORK", 
                                               String("Target probing: ") + ssid, 2);
                            }
                        }
                        
                        if (should_print_packet()) {
                        Serial.printf(" SSID:%s", ssid);
                        }
                    }
                }
            }
            
            // Try to extract association info
            if (frame_subtype == WIFI_ASSOCIATION_REQUEST && src_mac.equals(TARGET_PHONE)) {
                if (target_ap != bssid) {
                target_ap = bssid;
                    if (current_serial_mode != SILENT) {
                        add_notification("TARGET_CONNECT", 
                                       String("Target associating to AP: ") + bssid.substring(9), 2);
                    }
                }
                
                if (should_print_packet()) {
                    Serial.printf(" AP:%s", bssid.substring(9).c_str());
                }
            }
            
            if (should_print_packet()) {
    Serial.print("]");
            }
    
            // Store packet info for display
            if (target_packets.size() >= MAX_TARGET_PACKETS) {
                target_packets.erase(target_packets.begin());
            }
            
            TargetPacketInfo packet_info;
            packet_info.timestamp = millis();
            packet_info.frame_type = frame_type_str;
            packet_info.rssi = ctrl.rssi;
            packet_info.direction = direction;
            packet_info.details = "";
            target_packets.push_back(packet_info);
        }
        
        // Process different management frame types
      if (frame_subtype == WIFI_BEACON_FRAME) {
            // Check if this is a new AP
            bool is_new_ap = ap_registry.find(bssid) == ap_registry.end();
            
            // Update AP registry
            APInfo& ap = ap_registry[bssid];
            ap.bssid = bssid;
            ap.channel = current_channel;
            ap.rssi = ctrl.rssi;
            ap.last_seen = millis();
            ap.beacon_count++;
            
            String old_ssid = ap.ssid;
            String old_security = ap.security;
            
            // Parse SSID
        if (pkt->rx_ctrl.sig_len > 36) {
          uint8_t ssid_len = pkt->payload[37];
          if (ssid_len > 0 && ssid_len <= 32) {
                    char ssid[33] = {0};
                    memcpy(ssid, &pkt->payload[38], ssid_len);
                    ap.ssid = String(ssid);
                    
                    if (should_print_packet()) {
                    Serial.printf(" SSID:\"%s\"", ssid);
                    }
                }
            }
            
            // Parse security
            ap.security = get_security_from_beacon(pkt->payload, pkt->rx_ctrl.sig_len);
            
            if (should_print_packet()) {
            Serial.printf(" SEC:%s", ap.security.c_str());
            }
            
            // Notify about new AP discovery
            if (is_new_ap && current_serial_mode != SILENT) {
                String ap_name = ap.ssid.length() > 0 ? ap.ssid : "Hidden Network";
                String message = String("\"") + ap_name + "\" (" + ap.security + ", CH" + current_channel + ")";
                add_notification("NEW_AP", message, 2);
                
                // Security warning for open networks
                if (ap.security == "Open") {
                    add_notification("SECURITY_RISK", 
                                   String("Open network detected: ") + ap_name, 2);
                }
            }
            
            // Update channel stats
            if (is_new_ap) {
            channel_stats[current_channel].ap_count++;
            }
            
            // Track in device registry for serial output
            DeviceInfo& device = device_registry[bssid];
            device.mac = bssid;
            device.rssi = ctrl.rssi;
            device.last_seen = millis();
            device.frame_count++;
            device.device_type = "AP";
            
      } else if (frame_subtype == WIFI_PROBE_REQUEST) {
            // Check if this is a new client device
            bool is_new_client = client_registry.find(src_mac) == client_registry.end();
            
            // Track client devices
            ClientInfo& client = client_registry[src_mac];
            client.mac = src_mac;
            client.rssi = ctrl.rssi;
            client.last_seen = millis();
            client.frame_count++;
            client.vendor = get_vendor_from_mac(src_mac);
            client.is_associated = false;
            
            if (should_print_packet()) {
            Serial.printf(" VENDOR:%s", client.vendor.c_str());
            }
            
            // Notify about new device discovery
            if (is_new_client && src_mac != TARGET_PHONE && current_serial_mode != SILENT) {
                notify_new_device_smart(src_mac, client.vendor, "Client", ctrl.rssi);
            }
            
            // Try to associate with nearby APs based on timing and signal strength
            String nearest_ap = find_closest_ap(src_mac, ctrl.rssi, millis());
            if (nearest_ap.length() > 0) {
                client.connected_ap = nearest_ap;
            }
            
            // Track in device registry for serial output
            DeviceInfo& device = device_registry[src_mac];
            device.mac = src_mac;
            device.rssi = ctrl.rssi;
            device.last_seen = millis();
            device.frame_count++;
            device.device_type = "Client";
            
        } else if (frame_subtype == WIFI_ASSOCIATION_REQUEST || frame_subtype == WIFI_REASSOCIATION_REQUEST) {
            // Client associating to AP
            ClientInfo& client = client_registry[src_mac];
            client.mac = src_mac;
            client.connected_ap = bssid;
            client.rssi = ctrl.rssi;
            client.last_seen = millis();
            client.frame_count++;
            client.vendor = get_vendor_from_mac(src_mac);
            client.is_associated = true;
            
            if (should_print_packet()) {
            Serial.printf(" ASSOCIATING");
            }
            
            // Notify about device association (not for target phone to avoid spam)
            if (src_mac != TARGET_PHONE && current_serial_mode != SILENT) {
                String ap_name = "Unknown AP";
                if (ap_registry.find(bssid) != ap_registry.end()) {
                    ap_name = ap_registry[bssid].ssid.length() > 0 ? 
                             ap_registry[bssid].ssid : "Hidden AP";
                }
                add_notification("ASSOCIATION", 
                               client.vendor + " device → " + ap_name, 3);
            }
            
            // Track in device registry for serial output
            DeviceInfo& device = device_registry[src_mac];
            device.mac = src_mac;
            device.rssi = ctrl.rssi;
            device.last_seen = millis();
            device.frame_count++;
            device.device_type = "Client";
            
        } else if (frame_subtype == WIFI_ASSOCIATION_RESPONSE || frame_subtype == WIFI_REASSOCIATION_RESPONSE) {
            // AP responding to association
            if (client_registry.find(dst_mac) != client_registry.end()) {
                client_registry[dst_mac].connected_ap = src_mac;
                client_registry[dst_mac].is_associated = true;
            }
            
            if (should_print_packet()) {
            Serial.printf(" ASSOCIATED");
            }
            
        } else if (frame_subtype == WIFI_DISASSOCIATION) {
            // Client disconnecting
            if (client_registry.find(src_mac) != client_registry.end()) {
                client_registry[src_mac].is_associated = false;
                client_registry[src_mac].connected_ap = "";
                
                // Notify about disconnection for non-target devices
                if (src_mac != TARGET_PHONE && current_serial_mode != SILENT) {
                    add_notification("DISCONNECTION", 
                                   client_registry[src_mac].vendor + " device disconnected", 3);
                }
            }
            
            if (should_print_packet()) {
            Serial.printf(" DISASSOCIATED");
            }
        }
        
        // Only add newline if we actually printed something
        if (should_print_packet()) {
        Serial.println();
        }
        
    } else if (type == WIFI_PKT_DATA) {
        data_frames++;
        
        // Track data frame activity
        uint8_t* addr1 = &pkt->payload[4];  // Destination
        uint8_t* addr2 = &pkt->payload[10]; // Source
        
        String src_mac = mac_to_str(addr2);
        String dst_mac = mac_to_str(addr1);
        
        // Track anomaly
        track_anomaly(src_mac, "DATA", current_channel);
        
        // Smart data frame printing - rate limited
        if (should_print_packet()) {
            Serial.printf("[DATA] CH%d | RSSI:%d | %s→%s", 
                         current_channel, ctrl.rssi, 
                         src_mac.substring(9).c_str(), dst_mac.substring(9).c_str());
        }
        
        // Enhanced target phone data frame analysis
        if (src_mac.equals(TARGET_PHONE) || dst_mac.equals(TARGET_PHONE)) {
            // First time target detection
            if (!target_found) {
            target_found = true;
                if (current_serial_mode != SILENT) {
                    add_notification("TARGET_FOUND", 
                                   String("Target device detected! Signal: ") + ctrl.rssi + "dBm", 1);
                }
            }
            
            target_rssi = ctrl.rssi;
            target_last_seen = millis();
            
            String direction = src_mac.equals(TARGET_PHONE) ? "TX" : "RX";
            if (src_mac.equals(TARGET_PHONE)) {
                target_tx_packets++;
            } else {
                target_rx_packets++;
            }
            
            if (should_print_packet()) {
                Serial.printf(" [🎯%s", direction.c_str());
            }
            
            // Try to extract IP from data frame payload
            if (pkt->rx_ctrl.sig_len > 30) {
                // Look for IP patterns in payload (simplified)
                for (int i = 30; i < min(pkt->rx_ctrl.sig_len - 4, 50); i++) {
                    // Look for common IP patterns
                    if (pkt->payload[i] == 192 && pkt->payload[i+1] == 168) {
                        char ip_str[16];
                        sprintf(ip_str, "%d.%d.%d.%d", 
                                pkt->payload[i], pkt->payload[i+1], 
                                pkt->payload[i+2], pkt->payload[i+3]);
                        String new_ip = String(ip_str);
                        
                        if (target_ip != new_ip) {
                            target_ip = new_ip;
                            if (current_serial_mode != SILENT) {
                                add_notification("TARGET_IP", 
                                               String("Target IP detected: ") + ip_str, 2);
                            }
                        }
                        
                        if (should_print_packet()) {
                        Serial.printf(" IP:%s", ip_str);
                        }
                        break;
                    }
                }
            }
            
            if (should_print_packet()) {
            Serial.print("]");
            }
            
            // Store data packet info
            if (target_packets.size() >= MAX_TARGET_PACKETS) {
                target_packets.erase(target_packets.begin());
            }
            
            TargetPacketInfo packet_info;
            packet_info.timestamp = millis();
            packet_info.frame_type = "DATA";
            packet_info.rssi = ctrl.rssi;
            packet_info.direction = direction;
            packet_info.details = "";
            target_packets.push_back(packet_info);
        }
        
        // Update or create client entry for source
        ClientInfo& src_client = client_registry[src_mac];
        src_client.mac = src_mac;
        src_client.frame_count++;
        src_client.last_seen = millis();
        src_client.rssi = ctrl.rssi;
        if (src_client.vendor.length() == 0) {
            src_client.vendor = get_vendor_from_mac(src_mac);
        }
        
        // Associate with nearby AP if not already associated
        if (src_client.connected_ap.length() == 0) {
            String nearest_ap = find_closest_ap(src_mac, ctrl.rssi, millis());
            if (nearest_ap.length() > 0) {
                src_client.connected_ap = nearest_ap;
            }
        }
        
        // Track in device registry for serial output
        DeviceInfo& device = device_registry[src_mac];
        device.mac = src_mac;
        device.rssi = ctrl.rssi;
        device.last_seen = millis();
        device.frame_count++;
        device.device_type = "Client";
    
        // Only add newline if we actually printed something
        if (should_print_packet()) {
    Serial.println();
        }
        
    } else if (type == WIFI_PKT_CTRL) {
        ctrl_frames++;
        // Control frames are rarely interesting, only show in debug mode
        if (current_serial_mode == DEBUG && should_print_packet()) {
            Serial.printf("[CTRL] CH%d | RSSI:%d\n", current_channel, ctrl.rssi);
        }
        
    } else {
        // Catch any other packet types
        ctrl_frames++; // Count as control for now
        if (current_serial_mode == DEBUG && should_print_packet()) {
            Serial.printf("[MISC] CH%d | RSSI:%d\n", current_channel, ctrl.rssi);
        }
    }
}

// Print device summary table
void print_device_summary() {
    Serial.println("\n" + String(50, '='));
    Serial.println("📱 DEVICE SUMMARY TABLE");
    Serial.println(String(50, '='));
    
    if (device_registry.empty()) {
        Serial.println("No devices detected yet...");
        return;
    }
    
    Serial.printf("%-18s %-8s %-12s %-8s %s\n", "MAC Address", "RSSI", "Last Seen", "Frames", "Type");
    Serial.println(String(60, '-'));
    
    for (const auto& kv : device_registry) {
        const DeviceInfo& device = kv.second;
        char age_str[10];
        int age_sec = (millis() - device.last_seen) / 1000;
        if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
        else sprintf(age_str, "%dm ago", age_sec/60);
        
        String rssi_str;
        if (device.rssi > -50) rssi_str = "Excellent";
        else if (device.rssi > -60) rssi_str = "Good";
        else if (device.rssi > -70) rssi_str = "Fair";
        else rssi_str = "Poor";
        
        Serial.printf("%-18s %-8s %-12s %-8d %s\n", 
                     device.mac.c_str(), rssi_str.c_str(), age_str, device.frame_count, device.device_type.c_str());
    }
    
    Serial.printf("\nTotal Devices: %d | Active APs: %d | Total Frames: %d\n", 
                 device_registry.size(), ap_registry.size(), total_frames);
}

// Legacy notification functions - now use the smart notification system
void notify_new_device(const String& mac, int rssi, const String& type) {
    // This function is deprecated - use notify_new_device_smart() instead
    // Kept for compatibility but does nothing to avoid spam
}

void notify_lost_device(const String& mac) {
    // This function is deprecated - kept for compatibility but does nothing
}

// Handle serial commands
void handle_serial_commands() {
    if (Serial.available()) {
        char cmd = Serial.read();
        
        switch (cmd) {
            case 'h':
            case 'H':
                Serial.println("\n" + String(50, '='));
                Serial.println("🎯 ESP32 WiFi Sniffer - Help Menu");
                Serial.println(String(50, '='));
                Serial.println("Commands:");
                Serial.println("  h - Show this help menu");
                Serial.println("  s - Show device summary table");
                Serial.println("  f - Show frame statistics");
                Serial.println("  c - Show current channel info");
                Serial.println("  t - Show target phone status");
                Serial.println("  r - Reset all counters");
                Serial.println("  p - Print all APs");
                Serial.println("  d - Print all devices");
                Serial.println("  0 - SILENT mode (critical alerts only)");
                Serial.println("  q - QUIET mode (anomalies + discoveries)");
                Serial.println("  n - NORMAL mode (intelligent summaries)");
                Serial.println("  v - VERBOSE mode (rate-limited packets)");
                Serial.println("  x - DEBUG mode (full technical details)");
                Serial.println("  z - ANALYST mode (professional intelligence)");
                Serial.println("  live - Show live dashboard");
                Serial.println("  scan - Manual intelligence report");
                Serial.println("  clear - Clear all notifications");
                Serial.println("  modes - Show available serial modes");
                Serial.println("  a - Show anomaly log");
                Serial.println("  l - Show flagged MACs");
                Serial.println(String(50, '='));
                break;
                
            case 's':
            case 'S':
                print_device_summary();
                break;
                
            case 'f':
            case 'F':
                Serial.println("\n" + String(40, '='));
                Serial.println("📊 FRAME STATISTICS");
                Serial.println(String(40, '='));
                Serial.printf("Total Frames: %d\n", total_frames);
                Serial.printf("Management: %d\n", mgmt_frames);
                Serial.printf("Data: %d\n", data_frames);
                Serial.printf("Control: %d\n", ctrl_frames);
                Serial.printf("Current Channel: %d\n", current_channel);
                Serial.printf("Uptime: %d seconds\n", millis()/1000);
                Serial.println(String(40, '='));
                break;
                
            case 'c':
            case 'C':
                Serial.println("\n" + String(40, '='));
                Serial.println("📡 CHANNEL INFORMATION");
                Serial.println(String(40, '='));
                Serial.printf("Current Channel: %d\n", current_channel);
                Serial.printf("Channel Switch Interval: %d ms\n", WIFI_CHANNEL_SWITCH_INTERVAL);
                Serial.printf("Next Switch In: %d ms\n", WIFI_CHANNEL_SWITCH_INTERVAL - (millis() - last_channel_switch));
                Serial.println(String(40, '='));
                break;
                
            case 't':
            case 'T':
                Serial.println("\n" + String(40, '='));
                Serial.println("🎯 TARGET PHONE STATUS");
                Serial.println(String(40, '='));
                if (target_found) {
                    Serial.printf("Status: FOUND!\n");
                    Serial.printf("MAC: %s\n", TARGET_PHONE);
                    Serial.printf("Signal: %d dBm\n", target_rssi);
                    Serial.printf("IP: %s\n", target_ip.c_str());
                    Serial.printf("Network: %s\n", target_ssid.c_str());
                    Serial.printf("TX Packets: %d\n", target_tx_packets);
                    Serial.printf("RX Packets: %d\n", target_rx_packets);
                    char age_str[20];
                    int age_sec = (millis() - target_last_seen) / 1000;
                    if (age_sec < 60) sprintf(age_str, "%d seconds ago", age_sec);
                    else sprintf(age_str, "%d minutes ago", age_sec/60);
                    Serial.printf("Last Seen: %s\n", age_str);
                } else {
                    Serial.println("Status: SEARCHING...");
                    Serial.printf("Target MAC: %s\n", TARGET_PHONE);
                    Serial.printf("Current Channel: %d\n", current_channel);
                }
                Serial.println(String(40, '='));
                break;
                
            case 'r':
            case 'R':
                total_frames = 0;
                mgmt_frames = 0;
                data_frames = 0;
                ctrl_frames = 0;
                device_registry.clear();
                Serial.println("\n🔄 All counters reset!");
                break;
                
            case 'p':
            case 'P':
                Serial.println("\n" + String(50, '='));
                Serial.println("📡 ACCESS POINTS");
                Serial.println(String(50, '='));
                for (const auto& kv : ap_registry) {
                    const APInfo& ap = kv.second;
                    char age_str[10];
                    int age_sec = (millis() - ap.last_seen) / 1000;
                    if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
                    else sprintf(age_str, "%dm ago", age_sec/60);
                    
                    Serial.printf("SSID: %s\n", ap.ssid.c_str());
                    Serial.printf("BSSID: %s\n", ap.bssid.c_str());
                    Serial.printf("Channel: %d | RSSI: %d dBm\n", ap.channel, ap.rssi);
                    Serial.printf("Security: %s | Clients: %d\n", ap.security.c_str(), ap.client_count);
                    Serial.printf("Last Seen: %s\n", age_str);
                    Serial.println(String(30, '-'));
                }
                break;
                
            case 'd':
            case 'D':
                Serial.println("\n" + String(50, '='));
                Serial.println("📱 CLIENT DEVICES");
                Serial.println(String(50, '='));
                for (const auto& kv : client_registry) {
                    const ClientInfo& client = kv.second;
                    char age_str[10];
                    int age_sec = (millis() - client.last_seen) / 1000;
                    if (age_sec < 60) sprintf(age_str, "%ds ago", age_sec);
                    else sprintf(age_str, "%dm ago", age_sec/60);
                    
                    Serial.printf("MAC: %s\n", client.mac.c_str());
                    Serial.printf("Vendor: %s\n", client.vendor.c_str());
                    Serial.printf("RSSI: %d dBm | Frames: %d\n", client.rssi, client.frame_count);
                    Serial.printf("Connected AP: %s\n", client.connected_ap.c_str());
                    Serial.printf("Associated: %s\n", client.is_associated ? "Yes" : "No");
                    Serial.printf("Last Seen: %s\n", age_str);
                    Serial.println(String(30, '-'));
                }
                break;
                
            case '0':
                set_serial_mode(SILENT);
                break;
                
            case 'q':
            case 'Q':
                set_serial_mode(QUIET);
                break;
                
            case 'n':
            case 'N':
                set_serial_mode(NORMAL);
                break;
                
            case 'v':
            case 'V':
                set_serial_mode(VERBOSE);
                break;
                
            case 'x':
            case 'X':
                set_serial_mode(DEBUG);
                break;
                
            case 'z':
            case 'Z':
                set_serial_mode(ANALYST);
                break;
                
            case 'a':
            case 'A':
                Serial.println("\n" + String(50, '='));
                Serial.println("🚨 ANOMALY LOG");
                Serial.println(String(50, '='));
                if (anomaly_alerts.empty()) {
                    Serial.println("No anomalies detected yet.");
                } else {
                    for (auto it = anomaly_alerts.rbegin(); it != anomaly_alerts.rend(); ++it) {
                        char age_str[20];
                        int age_sec = (millis() - it->timestamp) / 1000;
                        if (age_sec < 60) sprintf(age_str, "%d seconds ago", age_sec);
                        else sprintf(age_str, "%d minutes ago", age_sec/60);
                        
                        Serial.printf("MAC: %s\n", it->mac.c_str());
                        Serial.printf("Threat: %s\n", it->threat_type.c_str());
                        Serial.printf("Count: %d\n", it->count);
                        Serial.printf("Time: %s\n", age_str);
                        Serial.println(String(30, '-'));
                    }
                }
                Serial.println(String(50, '='));
                break;
                
            case 'l':
            case 'L':
                {
                Serial.println("\n" + String(50, '='));
                Serial.println("🚩 FLAGGED MACs");
                Serial.println(String(50, '='));
                int flagged_count = 0;
                for (const auto& kv : anomaly_trackers) {
                    if (kv.second.is_flagged) {
                        Serial.printf("MAC: %s\n", kv.second.mac.c_str());
                        Serial.printf("Threat: %s\n", kv.second.threat_type.c_str());
                        Serial.printf("Last Seen: %d seconds ago\n", (millis() - kv.second.last_seen) / 1000);
                        Serial.println(String(30, '-'));
                        flagged_count++;
                    }
                }
                if (flagged_count == 0) {
                    Serial.println("No flagged MACs.");
                }
                Serial.println(String(50, '='));
                }
                break;
                
            default:
                {
                    // Check for multi-character commands
                    String command = "";
                    command += cmd;
                    
                    // Read additional characters for multi-char commands
                    unsigned long cmd_start = millis();
                    while (Serial.available() && millis() - cmd_start < 100) {
                        char c = Serial.read();
                        if (c == '\n' || c == '\r') break;
                        command += c;
                    }
                    
                    if (command == "live") {
                        print_live_dashboard();
                    } else if (command == "scan") {
                        print_intelligence_report();
                                    } else if (command == "clear") {
                    recent_events.clear();
                    Serial.println("📋 Notification history cleared!");
                } else if (command == "modes") {
                    Serial.println("\n🎛️  SERIAL OUTPUT MODES:");
                    Serial.println("0 - SILENT:  Only critical alerts");
                    Serial.println("q - QUIET:   Anomalies + new discoveries");  
                    Serial.println("n - NORMAL:  Intelligent summaries (DEFAULT)");
                    Serial.println("v - VERBOSE: Rate-limited packets");
                    Serial.println("x - DEBUG:   Full technical details");
                    Serial.println("z - ANALYST: Live dashboard");
                    Serial.printf("\nCurrent mode: ");
                    switch(current_serial_mode) {
                        case SILENT: Serial.println("SILENT"); break;
                        case QUIET: Serial.println("QUIET"); break;
                        case NORMAL: Serial.println("NORMAL"); break;
                        case VERBOSE: Serial.println("VERBOSE"); break;
                        case DEBUG: Serial.println("DEBUG"); break;
                        case ANALYST: Serial.println("ANALYST"); break;
                    }
                    } else if (command.length() > 1) {
                        Serial.println("❌ Unknown command: " + command);
                        Serial.println("Type 'h' for help");
                    }
                }
                break;
        }
    }
}

void setup() {
    // CRITICAL: Deinitialize RTC domain FIRST before any GPIO operations
    rtc_gpio_deinit(GPIO_NUM_25);
    rtc_gpio_deinit(GPIO_NUM_26);
    
    // Force GPIO states with stronger drive configuration
    gpio_config_t io_conf = {};
    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (1ULL << 25) | (1ULL << 26);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    gpio_config(&io_conf);
    
    gpio_set_level(GPIO_NUM_25, 1); // VCC
    gpio_set_level(GPIO_NUM_26, 0); // GND
    
    // Longer stabilization delay for power ramp
    delay(200);
    
    Serial.begin(115200);
    
    // DIAGNOSTIC: Log reset reason and GPIO states
    esp_reset_reason_t reset_reason = esp_reset_reason();
    Serial.print("Reset reason: ");
    Serial.println(reset_reason);
    Serial.print("GPIO 25: ");
    Serial.println(digitalRead(25));
    Serial.print("GPIO 26: ");
    Serial.println(digitalRead(26));
    
    delay(5000); // POWER FIX: Extra delay for power stabilization
    
    // FINAL SOFTWARE WORKAROUND: Auto-restart if display fails
    static int restart_count = 0;
    restart_count++;
    
    Serial.printf("Boot attempt #%d\n", restart_count);
    
    // HARDWARE FIX: Initialize GPIO pins early, no manual reset
    pinMode(4, OUTPUT);  // RST pin  
    pinMode(5, OUTPUT);  // DC pin
    digitalWrite(4, HIGH); // Keep RST high (not in reset)
    digitalWrite(5, HIGH); // DC high for data
    
    // POWER FIX: Create VCC and GND pins for capacitor connection
    pinMode(25, OUTPUT);  // VCC pin (3.3V)
    pinMode(26, OUTPUT);  // GND pin (0V)
    digitalWrite(25, HIGH); // Output 3.3V
    digitalWrite(26, LOW);  // Output 0V (GND)
    delay(100);
    
    // Print startup banner
    Serial.println("\n" + String(60, '='));
    Serial.println("🎯 ESP32 WiFi Packet Sniffer + Display Interface");
    Serial.println("📡 Professional Network Intelligence System");
    Serial.println("🔍 Target Phone: " + String(TARGET_PHONE));
    Serial.println(String(60, '='));
    Serial.println("🎛️  INTELLIGENT SERIAL MODES:");
    Serial.println("   0=SILENT | q=QUIET | n=NORMAL | v=VERBOSE | x=DEBUG | z=ANALYST");
    Serial.println("📋 COMMANDS: h(help) live(dashboard) scan(report) clear(notifications)");
    Serial.println("            s(summary) f(stats) t(target) r(reset) a(anomalies)");
    Serial.println(String(60, '='));
    
    Serial.println("WiFi Sniffer + Display starting...");
    
    // FIX: Display initialization after reset sequence
    Serial.println("Initializing display...");
    tft.init();
    tft.setRotation(0);  // Ensure correct orientation
    tft.fillScreen(TFT_BLACK);
    delay(500);  // Give display time to settle
    
    // Initialize display with failure detection
    if (!tft.begin()) {
        Serial.println("Display failed!");
        if (restart_count < 3) {
            Serial.println("Auto-restarting ESP32...");
            delay(1000);
            esp_restart();
        } else {
            Serial.println("Display initialization failed after 3 attempts - continuing without display");
        }
    } else {
        Serial.println("Display initialized successfully!");
    }
    
    // Initialize LVGL
    lv_init();
    lv_disp_draw_buf_init(&draw_buf, buf, NULL, 240 * 20);
    
    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res = 240;
    disp_drv.ver_res = 240;
    disp_drv.flush_cb = my_disp_flush;
    disp_drv.draw_buf = &draw_buf;
    lv_disp_drv_register(&disp_drv);
    
    create_main_ui();
    update_card_content();
    
    // Initialize WiFi sniffer
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
    ESP_ERROR_CHECK(esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE));
    
    // Initialize channel stats
    for (int i = 1; i <= 13; i++) {
        channel_stats[i].ap_count = 0;
        channel_stats[i].total_frames = 0;
        channel_stats[i].avg_rssi = 0;
        channel_stats[i].last_activity = 0;
    }
    
    Serial.println("System ready! Starting WiFi sniffer...");
    Serial.printf("🔇 Serial Mode: NORMAL (intelligent output) | Use 'h' for help\n");
    Serial.printf("🔄 Channel hopping: %d ms intervals | Starting on CH%d\n", WIFI_CHANNEL_SWITCH_INTERVAL, current_channel);
    Serial.println("📡 Monitoring for network intelligence...\n");
}

void loop() {
    frame_count++;
    
    // Handle touch inputs
    handle_touch_input();
    
    // Handle serial commands
    handle_serial_commands();
    
    // Channel hopping
    if (millis() - last_channel_switch > WIFI_CHANNEL_SWITCH_INTERVAL) {
  current_channel = (current_channel % WIFI_CHANNEL_MAX) + 1;
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  last_channel_switch = millis();
        
        // Notify about channel switching using the notification system
        if (current_serial_mode == DEBUG && current_serial_mode != SILENT) {
            add_notification("CHANNEL_SWITCH", String("Channel ") + current_channel, 3);
        }
    }
    
    // Update display every 2 seconds
    if (millis() - last_display_update > 2000) {
        update_card_content();
        last_display_update = millis();
    }
    
    // Check for anomalies every 5 seconds
    if (millis() - last_anomaly_check > 5000) {
        check_anomaly_thresholds();
        last_anomaly_check = millis();
    }
    
    // Smart dashboard and intelligence reporting
    if (current_serial_mode == SILENT) {
        // SILENT mode: NO OUTPUT AT ALL
        // Do nothing - completely silent
    } else if (current_serial_mode == ANALYST) {
        // Live dashboard mode - update every 10 seconds
        if (millis() - last_dashboard_update > 10000) {
            print_live_dashboard();
        }
    } else {
        // Intelligence reports based on mode
        print_intelligence_report(); // Has its own 30-second rate limiting
    }
    
    // Animate title
    float pulse = sin(frame_count * 0.05) * 0.3 + 0.7;
    lv_color_t color;
    color.ch.red = 0;
    color.ch.green = (uint8_t)(pulse * 255);
    color.ch.blue = (uint8_t)(pulse * 255);
    lv_obj_set_style_text_color(title_label, color, LV_PART_MAIN);
    
    // Clean up only very old entries every 60 seconds (KEEP MORE HISTORY)
    static unsigned long last_cleanup = 0;
    if (millis() - last_cleanup > 60000) {
        // Remove only very old APs (5 minutes)
        for (auto it = ap_registry.begin(); it != ap_registry.end();) {
            if (millis() - it->second.last_seen > 300000) {
                it = ap_registry.erase(it);
            } else {
                ++it;
            }
        }
        // Remove only very old clients (2 minutes)  
        for (auto it = client_registry.begin(); it != client_registry.end();) {
            if (millis() - it->second.last_seen > 120000) {
                it = client_registry.erase(it);
            } else {
                ++it;
            }
        }
        
        // Reset channel stats only if very old
        for (int i = 1; i <= 13; i++) {
            if (millis() - channel_stats[i].last_activity > 60000) {
                channel_stats[i].ap_count = 0;
                channel_stats[i].total_frames = 0;
            }
        }
        
        // Check if target is still active (longer timeout)
        if (target_found && millis() - target_last_seen > 60000) {
            target_found = false;
        }
        
        last_cleanup = millis();
    }
    
    lv_timer_handler();
    delay(30);
} 