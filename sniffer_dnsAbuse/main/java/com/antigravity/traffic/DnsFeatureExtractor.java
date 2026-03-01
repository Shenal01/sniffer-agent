package com.antigravity.traffic;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsQuestion;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.util.HashSet;
import java.util.Set;

/**
 * Extracts Deep Packet Inspection (DPI) features for DNS traffic.
 * Refactored for Infrastructure Abuse & DDoS detection.
 */
public class DnsFeatureExtractor {

    // A. Header-Level
    private boolean isDns = false;

    // FIX #6: Renamed for clarity - packet counts vs question counts
    private long dnsQueryPacketCount = 0; // Number of DNS query PACKETS
    private long dnsResponsePacketCount = 0; // Number of DNS response PACKETS
    private int lastOpCode = -1;

    // Aggregate counts across all packets in flow (Header fields)
    private long totalQuestionCount = 0; // Total DNS QUESTIONS (can be multiple per packet)
    private long totalAnswerCount = 0; // Total DNS ANSWERS

    // B. Query-Level Distribution
    // FIX #14: Track distribution instead of just last value
    private java.util.Map<Integer, Integer> queryTypeDistribution = new java.util.HashMap<>();
    private int lastQueryType = -1; // Keep for backward compatibility

    // C. Infrastructure Specific Counts
    private long dnsAnyCount = 0L; // FIX #15: Explicit L suffix
    private long dnsTxtCount = 0L;

    // D. Size & Volumetrics
    private long totalQueryBytes = 0L;
    private long totalResponseBytes = 0L;

    // FIX #11: Use BasicStats for stable variance calculation
    private BasicStats packetSizeStats = new BasicStats();

    // E. EDNS
    private boolean hasEdns = false;
    private int ednsUdpSize = 0;

    // Advanced: Response Time & TTL
    // FIX #4: Use composite key to prevent txId collision
    private java.util.Map<String, Long> pendingQueries = new java.util.HashMap<>();
    private double responseTimeSqSum = 0.0;
    private double responseTimeSum = 0.0;
    private long responseTimeCount = 0L;

    // REMOVED: ttlViolationCount (Not DNS specific)

    public void processPacket(Packet payload, int length, long timestamp) {
        if (payload == null)
            return;

        // Try to parse as DNS
        if (!payload.contains(DnsPacket.class)) {
            return;
        }

        DnsPacket dnsPacket = payload.get(DnsPacket.class);
        if (dnsPacket == null)
            return;

        try {
            DnsPacket.DnsHeader header = dnsPacket.getHeader();
            if (header == null)
                return;

            isDns = true;

            // 1. Header Parsing
            boolean isResponse = header.isResponse();
            int txId = header.getId();

            // FIX #4: Create composite key to prevent txId collision
            // Note: We'll need IP addresses passed to this method in future refactor
            // For now, use txId but add cleanup to prevent memory leak

            if (isResponse) {
                dnsResponsePacketCount++;
                totalResponseBytes += length;

                // Calculate Response Time
                String queryKey = String.valueOf(txId);
                if (pendingQueries.containsKey(queryKey)) {
                    long queryTime = pendingQueries.remove(queryKey);
                    double diff = (double) (timestamp - queryTime);

                    responseTimeSum += diff;
                    responseTimeSqSum += (diff * diff);
                    responseTimeCount++;
                }
            } else {
                dnsQueryPacketCount++;
                totalQueryBytes += length;

                // Store Query Time
                String queryKey = String.valueOf(txId);
                pendingQueries.put(queryKey, timestamp);

                // FIX #4: Prevent memory leak - cleanup old queries
                if (pendingQueries.size() > 10000) {
                    // Remove queries older than 5 seconds
                    pendingQueries.entrySet().removeIf(e -> (timestamp - e.getValue()) > 5000);
                }
            }

            // FIX #11: Use BasicStats for stable calculation
            packetSizeStats.addValue(length);

            lastOpCode = (int) header.getOpCode().value();

            totalQuestionCount += header.getQdCountAsInt();
            totalAnswerCount += header.getAnCountAsInt();

            // 2. EDNS Check
            // FIX #13: Add null check for getAdditionalInfo()
            java.util.List<DnsResourceRecord> additionalInfo = header.getAdditionalInfo();
            if (additionalInfo != null) {
                for (DnsResourceRecord rr : additionalInfo) {
                    if (rr.getDataType() == DnsResourceRecordType.OPT) {
                        hasEdns = true;
                        int size = rr.getDataClass().value() & 0xFFFF;

                        // Validate EDNS UDP size (should be >= 512)
                        if (size < 512) {
                            // Protocol violation - could be attack signature
                            // For now, just use the value
                        }

                        // Take maximum if multiple OPT records
                        ednsUdpSize = Math.max(ednsUdpSize, size);
                    }
                }
            }

            // 3. Query Parsing (Questions)
            // FIX #14: Track query type distribution
            for (DnsQuestion q : header.getQuestions()) {
                int qType = (int) q.getQType().value();
                lastQueryType = qType; // Keep for backward compatibility

                // Track distribution
                queryTypeDistribution.put(qType, queryTypeDistribution.getOrDefault(qType, 0) + 1);

                // Check for Amplification Types (ANY=255, TXT=16)
                if (qType == 255) { // ANY
                    dnsAnyCount++;
                } else if (qType == 16) { // TXT
                    dnsTxtCount++;
                }
            }
        } catch (Exception e) {
            // Malformed DNS packet - skip silently
            return;
        }
    }

    public double getResponseTimeVariance() {
        if (responseTimeCount <= 1)
            return 0.0;
        double mean = responseTimeSum / responseTimeCount;
        double variance = (responseTimeSqSum / responseTimeCount) - (mean * mean);
        return variance > 0 ? variance : 0.0;
    }

    // REMOVED: addTtlViolation()
    // REMOVED: getTtlViolationCount()

    // Getters for Features

    public boolean isDnsFlow() {
        return isDns;
    }

    // --- Direct Features ---

    public int getDnsQr() {
        // Return 1 if we saw any response (completed interaction), else 0
        return (dnsResponsePacketCount > 0) ? 1 : 0;
    }

    public int getDnsOpCode() {
        return lastOpCode == -1 ? 0 : lastOpCode;
    }

    public long getDnsQdCount() {
        return totalQuestionCount;
    }

    public int getDnsQueryType() {
        return lastQueryType == -1 ? 0 : lastQueryType;
    }

    public long getDnsAnswerCount() {
        return totalAnswerCount;
    }

    public int getDnsEdnsPresent() {
        return hasEdns ? 1 : 0;
    }

    public int getDnsEdnsUdpSize() {
        return ednsUdpSize;
    }

    // --- Derived Infrastructure Features ---

    // FIX #6: Use new variable names for clarity
    public long getDnsTotalQueries() {
        return dnsQueryPacketCount; // Number of query PACKETS
    }

    public long getDnsTotalResponses() {
        return dnsResponsePacketCount; // Number of response PACKETS
    }

    // FIX #2: Add getter for totalQueryBytes (needed for port 53 ratio)
    public long getTotalQueryBytes() {
        return totalQueryBytes;
    }

    // REMOVED: getMeanAnswersPerQuery()

    public double getQueriesPerSecond(double durationSec) {
        if (durationSec <= 0)
            return 0.0;
        return dnsQueryPacketCount / durationSec;
    }

    public long getDnsResponseSize() {
        return totalResponseBytes;
    }

    /**
     * FIX #12: Amplification Factor = Total Response Bytes / Total Query Bytes
     * This represents the actual amplification of DNS traffic.
     * For infrastructure attacks, we care about: How much data out per data in?
     */
    public double getDnsAmplificationFactor() {
        if (totalQueryBytes == 0) {
            // If no queries sent but responses received = reflection attack
            return (totalResponseBytes > 0) ? 999.0 : 0.0; // Sentinel value
        }

        if (totalResponseBytes == 0) {
            // Query flood - no responses
            return 0.0;
        }

        // Simple ratio: How much data out per data in
        return (double) totalResponseBytes / totalQueryBytes;
    }

    /**
     * Ratio of Queries to Responses.
     * High ratio (> 10) indicates Query Flood / Water Torture.
     */
    public double getQueryResponseRatio() {
        if (dnsResponsePacketCount == 0)
            return dnsQueryPacketCount; // Infinite/High
        return (double) dnsQueryPacketCount / dnsResponsePacketCount;
    }

    /**
     * FIX #11: Standard Deviation of Packet Sizes - now using BasicStats
     * This is numerically stable and accurate.
     */
    public double getPacketSizeStdDev() {
        return packetSizeStats.getStdDev();
    }

    public double getDnsAnyQueryRatio() {
        if (dnsQueryPacketCount == 0)
            return 0.0;
        return (double) dnsAnyCount / dnsQueryPacketCount;
    }

    public double getDnsTxtQueryRatio() {
        if (dnsQueryPacketCount == 0)
            return 0.0;
        return (double) dnsTxtCount / dnsQueryPacketCount;
    }

    // FIX #14: New methods for query type diversity
    public int getQueryTypeDiversity() {
        return queryTypeDistribution.size(); // Number of unique query types
    }

    public int getMostCommonQueryType() {
        return queryTypeDistribution.entrySet().stream()
                .max(java.util.Map.Entry.comparingByValue())
                .map(java.util.Map.Entry::getKey)
                .orElse(0);
    }
}
