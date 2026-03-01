#include <pcap.h>
#include <iostream>
#include <iomanip>

void packet_handler_minimal(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "[Packet Captured] Length: " << pkthdr->len << " bytes" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    std::cout << "--- Minimal Sniffer Test ---" << std::endl;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    if (alldevs == nullptr) {
        std::cerr << "No interfaces found! Check Npcap installation." << std::endl;
        return 1;
    }

    std::cout << "Available interfaces:" << std::endl;
    int i = 0;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << d->name;
        if (d->description) std::cout << " (" << d->description << ")";
        std::cout << std::endl;
    }

    std::cout << "\nEnter the interface number to listen on: ";
    int selection = 0;
    std::cin >> selection;

    pcap_if_t* selected_dev = alldevs;
    for (int j = 1; j < selection && selected_dev != nullptr; ++j) {
        selected_dev = selected_dev->next;
    }

    if (selected_dev == nullptr) {
        std::cerr << "Invalid selection." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_t* handle = pcap_open_live(selected_dev->name, 65536, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << selected_dev->name << ": " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\nListening on: " << (selected_dev->description ? selected_dev->description : selected_dev->name) << "..." << std::endl;
    std::cout << "(Capturing packets... Press Ctrl+C to stop if it hangs)" << std::endl;

    pcap_loop(handle, 5, packet_handler_minimal, nullptr);


    std::cout << "\nTest Complete. Successfully captured 5 packets." << std::endl;

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
