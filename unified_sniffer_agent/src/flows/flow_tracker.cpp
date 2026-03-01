#include "flow_tracker.h"
#include "common/time_utils.h"
#include <fmt/core.h>

namespace flows {

FlowTracker::FlowTracker(FlowCallback callback) : callback_(callback) {}

void FlowTracker::process_packet(const std::string& src_ip, uint16_t src_port, 
                                 const std::string& dst_ip, uint16_t dst_port, 
                                 size_t length, uint8_t flags) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    FlowKey key;
    bool is_sent;
    if (dst_port == 443) {
        key.client_ip = src_ip;
        key.client_port = src_port;
        key.server_ip = dst_ip;
        key.server_port = dst_port;
        is_sent = true;
    } else {
        key.client_ip = dst_ip;
        key.client_port = dst_port;
        key.server_ip = src_ip;
        key.server_port = src_port;
        is_sent = false;
    }

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowState state;
        state.start_time = std::chrono::system_clock::now();
        state.last_seen = state.start_time;
        it = flows_.emplace(key, state).first;
    }

    auto& state = it->second;
    auto now = std::chrono::system_clock::now();
    
    // Inter-arrival time
    if (state.packets_sent + state.packets_received > 0) {
        std::chrono::duration<double> iat = now - state.last_seen;
        state.inter_arrival_times.push(iat.count());
    }
    
    state.last_seen = now;
    state.packet_lengths.push((double)length);

    if (is_sent) {
        state.bytes_sent += length;
        state.packets_sent++;
    } else {
        state.bytes_received += length;
        state.packets_received++;
    }

    // Finalize on FIN (0x01) or RST (0x04)
    if (flags & 0x01 || flags & 0x04) {
        emit_flow(key, state);
        flows_.erase(it);
    }
}

void FlowTracker::cleanup_idle_flows(int timeout_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();
    
    for (auto it = flows_.begin(); it != flows_.end(); ) {
        std::chrono::duration<double> idle_time = now - it->second.last_seen;
        if (idle_time.count() > timeout_seconds) {
            emit_flow(it->first, it->second);
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

void FlowTracker::emit_flow(const FlowKey& key, const FlowState& state) {
    FlowRecord record;
    record.client_ip = key.client_ip;
    record.client_port = key.client_port;
    record.server_ip = key.server_ip;
    record.server_port = key.server_port;
    record.traffic_type = "doh";

    auto now = std::chrono::system_clock::now();
    record.timestamp = common::format_timestamp(now);
    record.start_ts = common::format_timestamp(state.start_time);
    record.end_ts = common::format_timestamp(state.last_seen);

    std::chrono::duration<double> duration = state.last_seen - state.start_time;
    record.duration = (float)duration.count();
    
    record.flow_bytes_received = (double)state.bytes_received;
    record.flow_bytes_sent = (double)state.bytes_sent;
    
    if (record.duration > 0) {
        record.flow_received_rate = (float)(state.bytes_received / record.duration);
        record.flow_sent_rate = (float)(state.bytes_sent / record.duration);
    } else {
        record.flow_received_rate = 0;
        record.flow_sent_rate = 0;
    }

    record.packet_len_mean = (float)state.packet_lengths.mean();
    record.packet_len_std = (float)state.packet_lengths.stddev();
    record.packet_time_mean = (float)state.inter_arrival_times.mean();
    record.packet_time_std = (float)state.inter_arrival_times.stddev();

    callback_(record);
}

} // namespace flows
