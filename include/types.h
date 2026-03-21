#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>
#include <mutex>

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow
// ============================================================================
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;  // TCP=6, UDP=17
    
    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    // Create reverse tuple (for matching bidirectional flows)
    FiveTuple reverse() const {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;
};

// Hash function for FiveTuple (used for load balancing)
struct FiveTupleHash {
    size_t operator()(const FiveTuple& tuple) const {
        // Simple but effective hash combining all fields
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(tuple.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(tuple.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(tuple.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(tuple.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    // Specific applications (detected via SNI)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    // Add more as needed
    APP_COUNT  // Keep this last for counting
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);

// ============================================================================
// Connection State
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
};

// ============================================================================
// Packet Action (what to do with the packet)
// ============================================================================
enum class PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
};

// ============================================================================
// Connection Entry (tracked per flow)
// ============================================================================
struct Connection {
    FiveTuple tuple;
    std::atomic<ConnectionState> state{ConnectionState::NEW};
    AppType app_type = AppType::UNKNOWN;
    std::string sni;  // Server Name Indication (if detected)
    
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action = PacketAction::FORWARD;
    
    // For TCP state tracking
    std::atomic<bool> syn_seen{false};
    std::atomic<bool> syn_ack_seen{false};
    std::atomic<bool> fin_seen{false};

    mutable std::mutex flow_mutex;

    Connection() = default;

    Connection(const Connection& other) {
        std::lock_guard<std::mutex> lock(other.flow_mutex);
        tuple = other.tuple;
        state.store(other.state.load());
        app_type = other.app_type;
        sni = other.sni;
        packets_in = other.packets_in;
        packets_out = other.packets_out;
        bytes_in = other.bytes_in;
        bytes_out = other.bytes_out;
        first_seen = other.first_seen;
        last_seen = other.last_seen;
        action = other.action;
        syn_seen.store(other.syn_seen.load());
        syn_ack_seen.store(other.syn_ack_seen.load());
        fin_seen.store(other.fin_seen.load());
    }

    Connection& operator=(const Connection& other) {
        if (this == &other) return *this;
        std::lock(flow_mutex, other.flow_mutex);
        std::lock_guard<std::mutex> lock1(flow_mutex, std::adopt_lock);
        std::lock_guard<std::mutex> lock2(other.flow_mutex, std::adopt_lock);

        tuple = other.tuple;
        state.store(other.state.load());
        app_type = other.app_type;
        sni = other.sni;
        packets_in = other.packets_in;
        packets_out = other.packets_out;
        bytes_in = other.bytes_in;
        bytes_out = other.bytes_out;
        first_seen = other.first_seen;
        last_seen = other.last_seen;
        action = other.action;
        syn_seen.store(other.syn_seen.load());
        syn_ack_seen.store(other.syn_ack_seen.load());
        fin_seen.store(other.fin_seen.load());
        return *this;
    }
};

// ============================================================================
// Packet wrapper for queue passing
// ============================================================================
struct PacketJob {
    uint32_t packet_id;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset = 0;
    size_t ip_offset = 0;
    size_t transport_offset = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    uint8_t tcp_flags = 0;
    const uint8_t* payload_data = nullptr;
    
    // Timestamps
    uint32_t ts_sec;
    uint32_t ts_usec;
};

// ============================================================================
// Statistics - uses regular uint64_t, protected by mutex externally
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};
    
    // Non-copyable due to atomics
    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
