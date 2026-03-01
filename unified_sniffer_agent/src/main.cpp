#include "capture/packet_capture.h"
#include "capture/packet_dispatcher.h"
#include "storage/db_writer.h"
#include "app/gui.h"
#include <iostream>
#include <string>
#include <vector>
#include <fmt/core.h>
#include <pcap.h>
#include <csignal>
#include <atomic>
#include <iostream>

std::atomic<bool> g_running(true);

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        fmt::print("\nShutdown signal received. Exiting gracefully...\n");
        g_running = false;
        capture::stop_capture();
    }
}

void print_interfaces(pcap_if_t* alldevs) {
    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        fmt::print("{}. {} ", ++i, d->name);
        if (d->description)
            fmt::print("({})", d->description);
        fmt::print("\n");
    }
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    fmt::print("========================================\n");
    fmt::print("   Unified Sniffer Agent - Windows      \n");
    fmt::print("========================================\n\n");

    // DB Configuration (TODO: Move to config file)
    std::string db_host = "127.0.0.1";
    std::string db_user = "root";
    std::string db_pass = "Aleththa_4";
    std::string db_name = "exfiltrap";

    storage::DbWriter db_writer;
    fmt::print("Initializing Database Writer...\n");
    db_writer.start(db_host, db_user, db_pass, db_name);
    // Note: start() prints its own success/fail message.

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fmt::print(stderr, "Error in pcap_findalldevs: {}\n", errbuf);
        return 1;
    }

    if (alldevs == nullptr) {
        fmt::print(stderr, "No interfaces found! Make sure Npcap is installed.\n");
        return 1;
    }

    pcap_if_t* alldevs_ptr = alldevs; // Save for GUI

    std::string adapter_name;
    bool show_gui = true;

    if (argc > 1) {
        // If an argument is provided, skip GUI and try to use it
        try {
            int selection = std::stoi(argv[1]);
            pcap_if_t* selected_dev = alldevs;
            for (int j = 1; j < selection && selected_dev != nullptr; ++j) {
                selected_dev = selected_dev->next;
            }
            if (selected_dev) {
                adapter_name = selected_dev->name;
                show_gui = false;
            }
        } catch (...) {
            adapter_name = argv[1];
            show_gui = false;
        }
    } 

    if (show_gui) {
        // START GUI SELECTION
        auto gui_result = app::Gui::show_setup_dialog(alldevs);
        if (!gui_result.start_requested) {
            fmt::print("Setup cancelled or window closed. Exiting.\n");
            db_writer.stop();
            pcap_freealldevs(alldevs);
            return 0;
        }
        adapter_name = gui_result.selected_interface;
    }

    pcap_freealldevs(alldevs);

    capture::PacketDispatcher dispatcher(db_writer);
    fmt::print("Starting packet capture engine on {}...\n", adapter_name);
    
    // Start a background thread for flow cleanup
    std::thread cleanup_thread([&dispatcher]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            dispatcher.cleanup_flows();
        }
    });

    if (!capture::start_capture(adapter_name, dispatcher)) {
        fmt::print(stderr, "Failed to start capture.\n");
    }

    fmt::print("Cleaning up resources...\n");
    g_running = false; // Ensure background thread sees it if capture loop broke early
    if (cleanup_thread.joinable()) cleanup_thread.join();
    
    // Final flush of active flows
    dispatcher.cleanup_flows();
    
    db_writer.stop();

    return 0;
}

