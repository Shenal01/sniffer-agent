#pragma once

#include "common/types.h"
#include "running_stats.h"
#include <map>
#include <string>
#include <mutex>
#include <chrono>
#include <functional>

namespace flows {

struct FlowKey {
    std::string client_ip;
    uint16_t client_port;
    std::string server_ip;
    uint16_t server_port;

    bool operator<(const FlowKey& other) const {
        if (client_ip != other.client_ip) return client_ip < other.client_ip;
        if (client_port != other.client_port) return client_port < other.client_port;
        if (server_ip != other.server_ip) return server_ip < other.server_ip;
        return server_port < other.server_port;
    }
};

struct FlowState {
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point last_seen;
    
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;

    RunningStats packet_lengths;
    RunningStats inter_arrival_times;
};

class FlowTracker {
public:
    using FlowCallback = std::function<void(const FlowRecord&)>;

    FlowTracker(FlowCallback callback);
    
    void process_packet(const std::string& src_ip, uint16_t src_port, 
                        const std::string& dst_ip, uint16_t dst_port, 
                        size_t length, uint8_t flags);

    void cleanup_idle_flows(int timeout_seconds = 60);

private:
    void emit_flow(const FlowKey& key, const FlowState& state);

    FlowCallback callback_;
    std::map<FlowKey, FlowState> flows_;
    std::mutex mutex_;
};

} // namespace flows
