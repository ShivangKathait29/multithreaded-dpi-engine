# 🔍 Multithreaded DPI Engine

A high-performance, **Multi-Threaded Deep Packet Inspection (DPI)** system built in modern C++17. It reads PCAP traffic captures, classifies flows by application using SNI/HTTP inspection, and applies configurable blocking rules — all through a pipelined, multi-threaded architecture.

```
  ┌─────────────┐
  │ PCAP Reader  │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer│  N LB threads distribute to FPs
  │  LB0 │ LB1  │
  └──┬────┴───┬─┘
     │        │  hash(5-tuple) % fps_per_lb
     ▼        ▼
  ┌──┴──┐  ┌──┴──┐
  │FP0-1│  │FP2-3│  M FP threads: DPI, classification, blocking
  └──┬──┘  └──┬──┘
     │        │
     ▼        ▼
  ┌──┴────────┴──┐
  │ Output Writer │  Writes forwarded packets to output PCAP
  └──────────────┘
```

---

## ✨ Features

- **Multi-threaded pipeline** — Configurable Load Balancer (LB) and Fast Path (FP) thread pools
- **Deep Packet Inspection** — TLS Client Hello SNI extraction, HTTP Host header parsing, DNS query detection
- **Application classification** — Identifies 16+ apps including Google, YouTube, Facebook, Instagram, Netflix, Spotify, Discord, GitHub, and more
- **Flexible blocking rules** — Block by source IP, application name, or domain pattern (wildcard support: `*.facebook.com`)
- **Connection tracking** — Per-flow state machine (NEW → ESTABLISHED → CLASSIFIED → CLOSED) with consistent hashing
- **PCAP I/O** — Reads and writes standard `.pcap` files for offline analysis
- **Rule persistence** — Save/load blocking rules from text files
- **Verbose logging** — Optional `--verbose` flag for detailed per-packet diagnostics
- **Cross-platform** — Portable byte-order handling; builds on Windows, macOS, and Linux

---

## 🛠️ Technologies

| Category | Details |
|----------|---------|
| **Language** | C++17 |
| **Build System** | CMake 3.16+ |
| **Threading** | `std::thread`, `std::mutex`, `std::atomic`, `std::condition_variable` |
| **Compilers** | MSVC 19+ (Visual Studio 2022), GCC 7+, Clang 5+ |
| **Test Data** | Python 3 script to generate synthetic PCAP files |

---

## 📋 Prerequisites

- **CMake** 3.16 or later
- **C++17-capable compiler**:
  - Windows: Visual Studio 2022 Build Tools (recommended) or MinGW-w64 with GCC 7+
  - Linux/macOS: GCC 7+ or Clang 5+
- **Python 3** (optional, for generating test PCAP files)

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/ShivangKathait29/multithreaded-dpi-engine.git
cd multithreaded-dpi-engine
```

### 2. Build

**Windows (Visual Studio):**
```powershell
cmake -B build -S . -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

**Windows (MinGW-w64 with GCC 7+):**
```powershell
cmake -B build -S . -G "MinGW Makefiles"
cmake --build build
```

**Linux / macOS:**
```bash
cmake -B build -S .
cmake --build build
```

### 3. Generate test data

```bash
python generate_test_pcap.py
```

This creates `test_dpi.pcap` with 16 TLS connections (with SNI), 2 HTTP connections, 4 DNS queries, and traffic from a blocked IP.

### 4. Run

**Linux / macOS / MinGW:**
```bash
# Modular engine (v1.0)
./build/dpi_engine_app test_dpi.pcap output.pcap --verbose

# Standalone multithreaded engine (v2.0)
./build/dpi_mt test_dpi.pcap output.pcap --block-app YouTube --verbose
```

**Windows (Visual Studio):**
```powershell
.\build\Release\dpi_engine_app.exe test_dpi.pcap output.pcap --verbose
.\build\Release\dpi_mt.exe test_dpi.pcap output.pcap --block-app YouTube --verbose
```

---

## 📖 Usage

### Command-Line Options

```
Usage: <executable> <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file (dpi_engine_app only)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output
```

### Examples

```bash
# Basic processing (no blocking)
./dpi_engine_app capture.pcap filtered.pcap

# Block YouTube and a specific IP
./dpi_mt capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50

# Block all Facebook subdomains with 4 LBs and 3 FPs per LB
./dpi_mt capture.pcap filtered.pcap --block-domain *.facebook.com --lbs 4 --fps 3

# Load rules from file
./dpi_engine_app capture.pcap filtered.pcap --rules blocking_rules.txt
```

### Supported Applications for Blocking

Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare

---

## 📁 Project Structure

```
multithreaded-dpi-engine/
├── CMakeLists.txt              # Build configuration (4 executable targets)
├── generate_test_pcap.py       # Python script to generate test PCAP data
├── .gitignore
│
├── include/                    # Header files
│   ├── types.h                 # Core types: FiveTuple, AppType, Connection, PacketJob
│   ├── dpi_engine.h            # Modular DPIEngine orchestrator (v1.0)
│   ├── fast_path.h             # FastPathProcessor & FPManager
│   ├── load_balancer.h         # LoadBalancer & LBManager
│   ├── connection_tracker.h    # Per-FP connection table & global aggregator
│   ├── rule_manager.h          # Thread-safe blocking rules (IP/App/Domain/Port)
│   ├── sni_extractor.h         # TLS SNI, HTTP Host, DNS, QUIC extractors
│   ├── pcap_reader.h           # PCAP file reader
│   ├── packet_parser.h         # Ethernet/IP/TCP/UDP packet parser
│   ├── thread_safe_queue.h     # Lock-based bounded MPMC queue
│   └── platform.h              # Portable byte-order conversion utilities
│
├── src/                        # Source files
│   ├── dpi_engine.cpp          # DPIEngine implementation (modular, v1.0)
│   ├── dpi_mt.cpp              # Standalone multithreaded engine (self-contained, v2.0)
│   ├── fast_path.cpp           # FastPathProcessor implementation
│   ├── load_balancer.cpp       # LoadBalancer implementation
│   ├── connection_tracker.cpp  # ConnectionTracker implementation
│   ├── rule_manager.cpp        # RuleManager implementation
│   ├── sni_extractor.cpp       # SNI/HTTP/DNS extraction logic
│   ├── pcap_reader.cpp         # PCAP reader implementation
│   ├── packet_parser.cpp       # Packet parser implementation
│   ├── types.cpp               # AppType helpers, SNI-to-app mapping
│   ├── main_dpi.cpp            # Entry point for dpi_engine_app
│   ├── main.cpp                # Entry point for packet_analyzer
│   ├── main_simple.cpp         # Entry point for simple_analyzer
│   └── main_working.cpp        # Alternate working implementation
│
└── build/                      # CMake build output (gitignored)
```

### Build Targets

| Target | Entry Point | Description |
|--------|-------------|-------------|
| `dpi_engine_app` | `main_dpi.cpp` | Modular DPI engine using separate component classes |
| `dpi_mt` | `dpi_mt.cpp` | Self-contained multithreaded engine (single file) |
| `packet_analyzer` | `main.cpp` | Basic packet analyzer |
| `simple_analyzer` | `main_simple.cpp` | Simplified analysis tool |

---

## ⚙️ Architecture Deep Dive

### Threading Model

The engine uses a **pipeline architecture** with configurable parallelism:

1. **Reader Thread** — Reads packets from the input PCAP file and distributes them to Load Balancers using consistent hashing on the five-tuple (`src_ip, dst_ip, src_port, dst_port, protocol`).

2. **Load Balancer Threads** — Each LB receives packets and further distributes them to its assigned Fast Path threads using another hash. This ensures all packets belonging to the same flow are processed by the same FP thread.

3. **Fast Path Threads** — The core DPI workhorses. Each FP thread:
   - Maintains its own **connection tracking table** (no locking needed)
   - Performs **SNI extraction** from TLS Client Hello messages
   - Parses **HTTP Host headers** for unencrypted traffic
   - Detects **DNS queries** for domain correlation
   - Applies **blocking rules** and forwards or drops packets

4. **Output Writer Thread** — Collects forwarded packets from all FP threads and writes them to the output PCAP file.

### Thread Safety

- **Thread-safe queues** (`ThreadSafeQueue`) are bounded MPMC queues using `std::mutex` and `std::condition_variable`
- **Connection tables** are per-FP (no sharing), enabled by consistent hashing
- **Rule manager** uses `std::shared_mutex` for concurrent read access from FP threads
- **Statistics** use `std::atomic` counters for lock-free updates

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

### Coding Standards

- Use **C++17** features (`std::optional`, structured bindings, etc.)
- Follow the existing naming conventions (snake_case for variables, PascalCase for classes)
- Add thread-safety annotations where applicable
- Test with the generated PCAP data before submitting

---

## 📄 License

This project is open source. See the repository for license details.

---

## 👤 Author

**Shivang Kathait** — [@ShivangKathait29](https://github.com/ShivangKathait29)
