package com.antigravity.traffic;

import com.antigravity.traffic.encrypted.DnsProtocol;
import com.antigravity.traffic.encrypted.DoHServerDatabase;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.HashMap;
import java.util.Map;

public class Flow {
    private final FlowKey key;
    private final long startTime;
    private long lastPacketTime;

    // Direction stats
    private BasicStats fwdPayloadStats = new BasicStats();
    private BasicStats bwdPayloadStats = new BasicStats();
    private BasicStats fwdIatStats = new BasicStats();
    private BasicStats bwdIatStats = new BasicStats();
    private BasicStats flowIatStats = new BasicStats();
    private BasicStats flowLengthStats = new BasicStats();

    // Packet timestamps for IAT
    private long lastFwdTime = 0;
    private long lastBwdTime = 0;

    private long fwdCount = 0;
    private long bwdCount = 0;

    // DNS Feature Extractor
    private DnsFeatureExtractor dnsExtractor;

    // Label for ML training (ATTACK or BENIGN)
    private final String label;

    // --- NEW: Encrypted DNS Features ---
    private DnsProtocol protocol;
    private boolean hasTLS = false;
    private String sniHostname = null;

    // Packet size distribution counters
    private long smallPacketCount = 0; // <400 bytes
    private long mediumPacketCount = 0; // 400-600 bytes
    private long largePacketCount = 0; // >600 bytes

    // TLS analysis
    private BasicStats tlsPayloadStats = new BasicStats();

    public Flow(FlowKey key, long startTime, boolean isDnsPort, String label) {
        this.key = key;
        this.startTime = startTime;
        this.lastPacketTime = startTime;
        this.label = label;

        // Initialize DNS extractor if relevant (Port 53)
        if (isDnsPort) {
            this.dnsExtractor = new DnsFeatureExtractor();
        }

        // NEW: Detect initial protocol based on ports
        // TLS/SNI will be refined as packets arrive
        this.protocol = DnsProtocol.detect(
                key.getSrcPort(),
                key.getDstPort(),
                false,
                null,
                key.getDstIp().getHostAddress());
    }

    public void addPacket(Packet packet, long timestamp, boolean isForward) {
        long currentLast = lastPacketTime;

        // Check ordering
        if (timestamp < lastPacketTime) {
            // Out-of-order packet detected - skip IAT update
        } else {
            if (fwdCount + bwdCount > 0) {
                flowIatStats.addValue(timestamp - currentLast);
            }
        }

        int length = packet.length();
        flowLengthStats.addValue(length);

        // --- NEW: Packet Size Categorization ---
        if (length < 400) {
            smallPacketCount++;
        } else if (length <= 600) {
            mediumPacketCount++;
        } else {
            largePacketCount++;
        }

        // --- NEW: TLS Processing (Simplified) ---
        if (packet.contains(TcpPacket.class)) {
            processTLSPacket(packet, timestamp, isForward);
        }

        if (isForward) {
            if (fwdCount > 0 && timestamp >= lastFwdTime) {
                fwdIatStats.addValue(timestamp - lastFwdTime);
            }
            lastFwdTime = timestamp;
            fwdPayloadStats.addValue(length);
            fwdCount++;
        } else {
            if (bwdCount > 0 && timestamp >= lastBwdTime) {
                bwdIatStats.addValue(timestamp - lastBwdTime);
            }
            lastBwdTime = timestamp;
            bwdPayloadStats.addValue(length);
            bwdCount++;
        }

        if (timestamp >= lastPacketTime) {
            lastPacketTime = timestamp;
        }

        // DNS Inspection
        if (dnsExtractor != null) {
            dnsExtractor.processPacket(packet, length, timestamp);
        }
    }

    /**
     * Process TLS-related features from TCP packet.
     */
    /**
     * Process TLS-related features from TCP packet.
     */
    private void processTLSPacket(Packet packet, long timestamp, boolean isForward) {
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        byte[] payload = tcpPacket.getPayload() != null ? tcpPacket.getPayload().getRawData() : null;

        if (payload == null || payload.length < 6)
            return;

        byte contentType = payload[0];

        // TLS Handshake (0x16)
        if (contentType == 0x16) {
            hasTLS = true;

            // Client Hello (0x01) - Check Handshake Type
            // Record Header (5 bytes) + Handshake Type (1 byte)
            if (payload.length > 9 && payload[5] == 0x01) {
                try {
                    String extractedSni = extractSni(payload);
                    if (extractedSni != null && !extractedSni.isEmpty()) {
                        this.sniHostname = extractedSni;
                    }
                } catch (Exception e) {
                    // Ignore parsing errors, packet might be fragmented or malformed
                }
            }

            // Re-detect protocol with TLS info
            // If we found SNI or confirmed TLS, update protocol
            if (protocol == DnsProtocol.UNKNOWN || protocol == DnsProtocol.TRADITIONAL) {
                protocol = DnsProtocol.detect(
                        key.getSrcPort(),
                        key.getDstPort(),
                        hasTLS,
                        sniHostname,
                        key.getDstIp().getHostAddress());
            }
        }

        // TLS Application Data (0x17) - encrypted DNS payload
        else if (contentType == 0x17 && payload.length >= 5) {
            // Extract record length (Bytes 3-4)
            int recordLength = ((payload[3] & 0xFF) << 8) | (payload[4] & 0xFF);
            tlsPayloadStats.addValue(recordLength);
        }
    }

    /**
     * Parses TLS Client Hello to extract SNI Hostname.
     */
    private String extractSni(byte[] payload) {
        // Pointer to current position. payload[0] is ContentType.
        // Record Header: Type(1), Ver(2), Len(2) -> 5 bytes
        int p = 5;

        // Handshake Header: Type(1), Len(3) -> 4 bytes
        if (p + 4 > payload.length)
            return null;
        int handshakeType = payload[p] & 0xFF; // Should be 0x01 (Client Hello)
        if (handshakeType != 1)
            return null;
        p += 4;

        // Client Version (2) + Random (32) -> 34 bytes
        if (p + 34 > payload.length)
            return null;
        p += 34;

        // Session ID
        if (p + 1 > payload.length)
            return null;
        int sessionIdLen = payload[p] & 0xFF;
        p += 1;
        if (p + sessionIdLen > payload.length)
            return null;
        p += sessionIdLen;

        // Cipher Suites
        if (p + 2 > payload.length)
            return null;
        int cipherSuitesLen = ((payload[p] & 0xFF) << 8) | (payload[p + 1] & 0xFF);
        p += 2;
        if (p + cipherSuitesLen > payload.length)
            return null;
        p += cipherSuitesLen;

        // Compression Methods
        if (p + 1 > payload.length)
            return null;
        int compMethodsLen = payload[p] & 0xFF;
        p += 1;
        if (p + compMethodsLen > payload.length)
            return null;
        p += compMethodsLen;

        // Extensions
        if (p + 2 > payload.length)
            return null;
        int extensionsLen = ((payload[p] & 0xFF) << 8) | (payload[p + 1] & 0xFF);
        p += 2;

        int endOfExtensions = p + extensionsLen;
        if (endOfExtensions > payload.length)
            endOfExtensions = payload.length;

        while (p + 4 <= endOfExtensions) {
            int extType = ((payload[p] & 0xFF) << 8) | (payload[p + 1] & 0xFF);
            int extLen = ((payload[p + 2] & 0xFF) << 8) | (payload[p + 3] & 0xFF);
            p += 4;

            // SNI Extension Type is 0x0000
            if (extType == 0) {
                if (p + 2 > endOfExtensions)
                    return null;
                // SNI List Length
                int listLen = ((payload[p] & 0xFF) << 8) | (payload[p + 1] & 0xFF);
                p += 2;

                if (p + 1 > endOfExtensions)
                    return null;
                int nameType = payload[p] & 0xFF; // Should be 0 (host_name)
                p += 1;

                if (nameType == 0) {
                    if (p + 2 > endOfExtensions)
                        return null;
                    int nameLen = ((payload[p] & 0xFF) << 8) | (payload[p + 1] & 0xFF);
                    p += 2;

                    if (p + nameLen <= endOfExtensions) {
                        return new String(payload, p, nameLen);
                    }
                }
            } else {
                p += extLen;
            }
        }
        return null;
    }

    // --- New Feature Getters ---

    public double getLargePacketRatio() {
        long total = fwdCount + bwdCount;
        return total > 0 ? (double) largePacketCount / total : 0.0;
    }

    public double getMediumPacketRatio() {
        long total = fwdCount + bwdCount;
        return total > 0 ? (double) mediumPacketCount / total : 0.0;
    }

    public double getSmallPacketRatio() {
        long total = fwdCount + bwdCount;
        return total > 0 ? (double) smallPacketCount / total : 0.0;
    }

    /**
     * Check if this flow is to a known DoH server.
     */
    public boolean isKnownDoHServer() {
        // If protocol is ALREADY detected as DoH, it's likely a known server
        if (protocol == DnsProtocol.DOH) {
            return true;
        }

        String destIP = key.getDstIp().getHostAddress();
        if (DoHServerDatabase.isKnownDoHServer(sniHostname, destIP)) {
            // Update protocol if matched
            if (protocol == DnsProtocol.UNKNOWN)
                protocol = DnsProtocol.DOH;
            return true;
        }
        return false;
    }

    /**
     * Calculate entropy of SNI hostname for DGA detection.
     */
    public double getSniEntropy() {
        if (sniHostname == null || protocol == DnsProtocol.TRADITIONAL) {
            return 0.0;
        }
        return calculateShannonEntropy(sniHostname);
    }

    private double calculateShannonEntropy(String str) {
        if (str == null || str.isEmpty())
            return 0.0;

        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : str.toLowerCase().toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }

        double entropy = 0.0;
        int length = str.length();

        for (Integer count : freqMap.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }

        return entropy;
    }

    public double getEncryptedPayloadSizeVariance() {
        if (protocol == DnsProtocol.TRADITIONAL) {
            return 0.0;
        }
        return tlsPayloadStats.getVariance();
    }

    public FlowKey getKey() {
        return key;
    }

    public long getLastPacketTime() {
        return lastPacketTime;
    }

    public long getStartTime() {
        return startTime;
    }

    public long getFlowDuration() {
        return lastPacketTime - startTime;
    }

    // UPDATED: Export to CSV for v2.0
    public String toCsvRow() {
        StringBuilder sb = new StringBuilder();

        // --- NEW: Protocol (Column 1) ---
        sb.append(protocol != null ? protocol.toString() : "UNKNOWN").append(",");

        // --- Identity (5) ---
        sb.append(key.getSrcIp().getHostAddress()).append(",");
        sb.append(key.getDstIp().getHostAddress()).append(",");
        sb.append(key.getSrcPort()).append(",");
        sb.append(key.getDstPort()).append(",");
        sb.append(key.getProtocol()).append(",");

        // Calculate Duration in Seconds
        double durationSec = getFlowDuration() / 1000.0;
        if (durationSec <= 0) {
            durationSec = 1.0;
        }

        // --- Category 1: DNS Critical (7 features - REMOVED 3) ---
        if (dnsExtractor != null && dnsExtractor.isDnsFlow()) {
            sb.append(String.format("%.4f,", dnsExtractor.getDnsAmplificationFactor()));
            sb.append(String.format("%.4f,", dnsExtractor.getQueryResponseRatio()));
            sb.append(String.format("%.4f,", dnsExtractor.getDnsAnyQueryRatio())); // Traditional Only
            sb.append(String.format("%.4f,", dnsExtractor.getDnsTxtQueryRatio())); // Traditional Only
            // REMOVED: dns_server_fanout
            long diff = Math.abs(dnsExtractor.getDnsTotalQueries() - dnsExtractor.getDnsTotalResponses());
            sb.append(diff).append(","); // dns_response_inconsistency
            // REMOVED: ttl_violation_rate
            sb.append(String.format("%.4f,", dnsExtractor.getQueriesPerSecond(durationSec)));
            // REMOVED: dns_mean_answers_per_query

            // port_53_traffic_ratio
            long totalFlowBytes = (long) flowLengthStats.getSum();
            if (totalFlowBytes > 0) {
                long dnsTrafficBytes = dnsExtractor.getTotalQueryBytes() + dnsExtractor.getDnsResponseSize();
                sb.append(String.format("%.4f,", (double) dnsTrafficBytes / totalFlowBytes));
            } else {
                sb.append("0.0,");
            }
        } else {
            // Fill with 0s for non-traditional-DNS flows
            sb.append("0,0,0,0,0,0,0,");
        }

        // --- Category 2: Flow Rates (4) ---
        sb.append(String.format("%.4f,", flowLengthStats.getSum() / durationSec)); // flow_bytes_per_sec
        sb.append(String.format("%.4f,", (fwdCount + bwdCount) / durationSec)); // flow_packets_per_sec
        sb.append(String.format("%.4f,", fwdCount / durationSec)); // fwd_packets_per_sec
        sb.append(String.format("%.4f,", bwdCount / durationSec)); // bwd_packets_per_sec

        // --- Category 3: Flow Statistics (5) ---
        sb.append(getFlowDuration()).append(",");
        sb.append(fwdCount).append(",");
        sb.append(bwdCount).append(",");
        sb.append(fwdPayloadStats.getSum()).append(","); // total_fwd_bytes
        sb.append(bwdPayloadStats.getSum()).append(","); // total_bwd_bytes

        // --- Category 4: DNS Aggregates (3) ---
        if (dnsExtractor != null) {
            sb.append(dnsExtractor.getDnsTotalQueries()).append(",");
            sb.append(dnsExtractor.getDnsTotalResponses()).append(",");
            sb.append(dnsExtractor.getDnsResponseSize()).append(",");
        } else {
            sb.append("0,0,0,");
        }

        // --- Category 5: Timing (6) ---
        sb.append(String.format("%.4f,", flowIatStats.getMean()));
        sb.append(String.format("%.4f,", flowIatStats.getStdDev()));
        sb.append(String.format("%.4f,", flowIatStats.getMin()));
        sb.append(String.format("%.4f,", flowIatStats.getMax()));
        sb.append(String.format("%.4f,", fwdIatStats.getMean()));
        sb.append(String.format("%.4f,", bwdIatStats.getMean()));

        // --- Category 6: Packet Sizes (5) ---
        sb.append(String.format("%.4f,", fwdPayloadStats.getMean()));
        sb.append(String.format("%.4f,", bwdPayloadStats.getMean()));
        sb.append(String.format("%.4f,", flowLengthStats.getStdDev())); // packet_size_std
        sb.append(String.format("%.4f,", flowLengthStats.getMin())); // flow_length_min
        sb.append(String.format("%.4f,", flowLengthStats.getMax())); // flow_length_max

        // --- Category 7: Advanced (2) ---
        if (dnsExtractor != null) {
            sb.append(String.format("%.4f,", dnsExtractor.getResponseTimeVariance()));
        } else {
            sb.append("0,");
        }
        sb.append(String.format("%.4f,", flowLengthStats.getMean())); // average_packet_size

        // --- NEW: Encrypted DNS Features (6) ---
        sb.append(String.format("%.4f,", getLargePacketRatio()));
        sb.append(String.format("%.4f,", getMediumPacketRatio()));
        sb.append(String.format("%.4f,", getSmallPacketRatio()));
        sb.append(String.format("%.4f,", getSniEntropy()));
        sb.append(isKnownDoHServer() ? "1" : "0").append(",");
        sb.append(String.format("%.4f,", getEncryptedPayloadSizeVariance()));

        // --- Category 8: Classification ---
        if (label != null) {
            sb.append(label);
        }

        return sb.toString();
    }

    public static String getCsvHeader(boolean includeLabel) {
        String header = "protocol," + // NEW COLUMN 1
                "src_ip,dst_ip,src_port,dst_port,protocol_number," +

                // Traditional DNS Features (Removed 3: mean_answers, fanout, ttl_violation)
                "dns_amplification_factor,query_response_ratio,dns_any_query_ratio,dns_txt_query_ratio," +
                "dns_response_inconsistency,dns_queries_per_second,port_53_traffic_ratio," +

                "flow_bytes_per_sec,flow_packets_per_sec,fwd_packets_per_sec,bwd_packets_per_sec," +
                "flow_duration,total_fwd_packets,total_bwd_packets,total_fwd_bytes,total_bwd_bytes," +
                "dns_total_queries,dns_total_responses,dns_response_bytes," +
                "flow_iat_mean,flow_iat_std,flow_iat_min,flow_iat_max,fwd_iat_mean,bwd_iat_mean," +
                "fwd_packet_length_mean,bwd_packet_length_mean,packet_size_std,flow_length_min,flow_length_max," +
                "response_time_variance,average_packet_size," +

                // NEW: Encrypted DNS Features
                "large_packet_ratio,medium_packet_ratio,small_packet_ratio," +
                "sni_entropy,is_known_doh_server,encrypted_payload_size_variance";

        if (includeLabel) {
            header += ",label";
        }

        return header;
    }
}
