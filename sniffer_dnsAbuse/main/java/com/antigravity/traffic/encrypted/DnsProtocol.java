package com.antigravity.traffic.encrypted;

import java.util.Set;

/**
 * Enum representing DNS protocol types for unified analysis.
 * Supports Traditional DNS (53), DoT (853), and DoH (443).
 */
public enum DnsProtocol {
    TRADITIONAL("TRADITIONAL"), // Port 53, UDP/TCP
    DOT("DOT"), // Port 853, TCP+TLS
    DOH("DOH"), // Port 443, HTTPS + Known Server
    UNKNOWN("UNKNOWN");

    private final String value;

    DnsProtocol(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return value;
    }

    /**
     * Detect protocol based on flow characteristics.
     * 
     * @param srcPort     Source port
     * @param dstPort     Destination port
     * @param hasTLS      Whether flow has TLS handshake
     * @param sniHostname SNI hostname if available (null if none)
     * @param destIp      Destination IP address (for DoH check)
     * @return Detected DNS protocol
     */
    public static DnsProtocol detect(int srcPort, int dstPort, boolean hasTLS, String sniHostname, String destIp) {
        // DoT is easiest - dedicated port
        if (srcPort == 853 || dstPort == 853) {
            return DOT;
        }

        // Traditional DNS
        if (srcPort == 53 || dstPort == 53) {
            return TRADITIONAL;
        }

        // DoH detection - port 443 + TLS + known server
        if (srcPort == 443 || dstPort == 443) {
            // Strong indicator: Known DoH Server (by IP or SNI)
            if (DoHServerDatabase.isKnownDoHServer(sniHostname, destIp)) {
                return DOH;
            }

            // Weak indicator: 443 + TLS (might be DoH, might be web)
            // For now, we only classify confirmed DoH servers to avoid FPs
            // Future: Traffic analysis (size/timing) to detect unknown DoH
        }

        // Return UNKNOWN if not identified as DNS
        // Note: Flow might default to TRADITIONAL if created on port 53 elsewhere
        return UNKNOWN;
    }
}
