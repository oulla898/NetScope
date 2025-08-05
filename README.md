# ESP32 WiFi Packet Sniffer with Professional Display Interface

A sophisticated WiFi packet sniffer for the ESP32 Wrover Dev board with a 1.3" ST7789 display, featuring professional network intelligence capabilities.

## 🎯 Features

### Core Functionality
- **WiFi Packet Capture**: Captures management frames (beacons, probe requests/responses, association, authentication, etc.)
- **Channel Hopping**: Automatically switches between WiFi channels (1-13) every 3 seconds
- **Target Device Tracking**: Monitors specific MAC addresses with TX/RX packet analysis
- **Real-time Display**: Professional 240x240 ST7789 display interface with touch navigation

### Advanced Intelligence
- **Anomaly Detection**: Identifies probe floods, deauth attacks, beacon floods, and channel hopping
- **Device Classification**: Automatic vendor detection (Apple, Samsung, Raspberry Pi, etc.)
- **Security Analysis**: Identifies open networks and security vulnerabilities
- **Network Mapping**: Tracks AP-client associations and signal strength analysis

### Professional UI
- **7 Interactive Cards**: Access Points, Devices, Target Hunt, Signal Map, Network Intel, Threats, System Status
- **Animated Visualizations**: Signal strength bars, progress arcs, channel activity graphs
- **Touch Navigation**: PIN 32 (next card) and PIN 33 (scroll) for easy navigation
- **Real-time Updates**: Live statistics and professional color-coded information

### Serial Output Modes
- **SILENT**: Only critical alerts
- **QUIET**: Anomalies + new device discoveries
- **NORMAL**: Intelligent summaries (default)
- **VERBOSE**: Rate-limited packet samples with classic format
- **DEBUG**: Full technical details
- **ANALYST**: Professional network intelligence dashboard

## 🛠️ Hardware Requirements

- **ESP32 Wrover Dev board** (or compatible ESP32)
- **1.3" ST7789 Display** (240x240 resolution)
- **Touch sensors** on GPIO 32 and 33 (optional)

### Pin Connections
- **Display**: SPI pins (18, 23, 5, 4)
- **Touch**: GPIO 32 (next card), GPIO 33 (scroll)
- **Power**: GPIO 25 (VCC), GPIO 26 (GND)

## 📦 Installation & Usage

### 1. Build & Upload
```bash
# Using PlatformIO
platformio run --target upload

# Or using Arduino IDE
# Upload the main.cpp file
```

### 2. Monitor Output
```bash
# PlatformIO
platformio device monitor

# Or use any serial monitor at 115200 baud
```

### 3. Serial Commands
- `h` - Help menu
- `s` - Device summary table
- `f` - Frame statistics
- `t` - Target phone status
- `r` - Reset counters
- `0` - SILENT mode
- `q` - QUIET mode
- `n` - NORMAL mode
- `v` - VERBOSE mode
- `x` - DEBUG mode
- `z` - ANALYST mode
- `live` - Show live dashboard
- `scan` - Manual intelligence report

## 📊 Output Examples

### Classic Packet Format (VERBOSE Mode)
```
[CH1] [BEACON] [RSSI:-45] [SRC:AA:BB:CC:DD:EE:FF] [DST:FF:FF:FF:FF:FF:FF] [SSID:MyWiFi]
[CH1] [PROBE_REQ] [RSSI:-52] [SRC:11:22:33:44:55:66] [DST:FF:FF:FF:FF:FF:FF] [SSID:TargetNetwork]
```

### Professional Notifications (NORMAL Mode)
```
[12:34:56] ⚠️ NEW_AP: "MyWiFi" (WPA2, CH1)
[12:34:57] ℹ️ NEW_DEVICE: Apple device (Good signal, Client)
[12:34:58] 🚨 THREAT_DETECTED: PROBE_FLOOD from 11:22:33 (count: 15)
```

### Live Dashboard (ANALYST Mode)
```
┌─ ESP32 WiFi Intelligence System ────────────────────┐
│ 🕐 12:34:56 | Uptime: 00:05:23                      │
├─────────────────────────────────────────────────────┤
│ 📡 CH: 1/13 | 🔥 Activity: ████████▒▒ 45/min       │
│ 🎯 Target: FOUND (-45dBm, 2s ago) | 📱 Devices: 12 │
│ 🏢 APs: 8 | 🚨 Threats: 2 | 🔒 Security: 75%       │
└─────────────────────────────────────────────────────┘
```

## 🎨 Display Interface

The device features a professional touchscreen interface with:

- **Access Points Card**: Shows AP details with signal strength bars and security badges
- **Devices Card**: Lists client devices with vendor identification and connection status
- **Target Hunt Card**: Real-time target device tracking with signal visualization
- **Signal Map Card**: Channel activity graph showing network distribution
- **Network Intel Card**: Security analysis and frame statistics
- **Threats Card**: Anomaly alerts and flagged devices
- **System Status Card**: Uptime, memory usage, and system information

## 🔍 Target Device Tracking

Configure your target device MAC address in the code:
```cpp
const char* TARGET_PHONE = "C4:EF:3D:B3:23:BD";  // Your device's MAC
```

The system will:
- Track TX/RX packets from the target
- Monitor signal strength changes
- Detect network associations
- Provide real-time status updates

## ⚠️ Legal & Ethical Notice

- **This tool is for educational and research purposes only.**
- Capturing WiFi traffic may be illegal or unethical in some jurisdictions.
- **Do not use to intercept private communications.**
- Always have permission to monitor networks you do not own.
- Use responsibly and in compliance with local laws.

## 📁 Project Structure

```
esp32-sniffer/
├── src/
│   ├── main.cpp          # Main application code
│   └── lv_conf.h         # LVGL configuration
├── include/              # Header files
├── lib/                  # Library files
├── platformio.ini        # PlatformIO configuration
├── cpp.cpp              # Simple WiFi sniffer (basic version)
├── cp.cpp               # Advanced version with enhanced features
└── README.md            # This file
```

## 🤝 Contributing

This project was developed as part of an IAESTE internship at Ege University. Contributions are welcome!

## 📄 License

This project is for educational purposes. Please use responsibly.

---

**Author:** Almoulla Al Maawali  
**Institution:** IAESTE Internship - Ege University  
**Project:** Professional WiFi Network Intelligence System 