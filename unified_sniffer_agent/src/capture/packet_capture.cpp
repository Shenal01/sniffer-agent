#include "packet_capture.h"
#include "packet_dispatcher.h"
#include <iostream>
#include <fmt/core.h>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <pcap.h>

namespace capture {

static pcap_t* g_pcap_handle = nullptr;
static std::mutex g_pcap_mutex;

void packet_handler_internal(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketDispatcher* dispatcher = reinterpret_cast<PacketDispatcher*>(user_data);
    if (dispatcher) {
        dispatcher->handle_packet(pkthdr, packet);
    }
}

void stop_capture() {
    std::lock_guard<std::mutex> lock(g_pcap_mutex);
    if (g_pcap_handle) {
        pcap_breakloop(g_pcap_handle);
    }
}

bool start_capture(const std::string& adapter_name, PacketDispatcher& dispatcher) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    handle = pcap_open_live(adapter_name.c_str(), 65536, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        fmt::print(stderr, "Could not open device {}: {}\n", adapter_name, errbuf);
        return false;
    }

    struct bpf_program fp;
    const char filter_exp[] = "udp port 53 or tcp port 53 or tcp port 443";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fmt::print(stderr, "Could not parse filter '{}': {}\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fmt::print(stderr, "Could not install filter '{}': {}\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return false;
    }
    pcap_freecode(&fp);

    {
        std::lock_guard<std::mutex> lock(g_pcap_mutex);
        g_pcap_handle = handle;
    }

    fmt::print("Listening on {} (Filter: '{}')...\n", adapter_name, filter_exp);

    pcap_loop(handle, 0, packet_handler_internal, reinterpret_cast<u_char*>(&dispatcher));

    {
        std::lock_guard<std::mutex> lock(g_pcap_mutex);
        g_pcap_handle = nullptr;
    }

    pcap_close(handle);
    return true;
}

} // namespace capture
