package com.antigravity.traffic;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FlowManager {
    private static final Logger logger = LoggerFactory.getLogger(FlowManager.class);

    private final Map<FlowKey, Flow> activeFlows = new HashMap<>();
    private final PrintWriter csvWriter;
    private final GoogleSheetsWriter sheetsWriter; // Optional, can be null
    private final long flowTimeoutMillis = 120000; // 2 minutes timeout
    private long packetCounter = 0;
    private boolean isDumped = false; // Flag to ensure idempotent dump
    private final String label; // ATTACK or BENIGN

    // FIX #5: Add time-based timeout checking
    private long lastTimeoutCheck = 0;

    public FlowManager(PrintWriter csvWriter, String label, GoogleSheetsWriter sheetsWriter) {
        this.csvWriter = csvWriter;
        this.label = label;
        this.sheetsWriter = sheetsWriter;

        // Write Header to CSV
        String header = Flow.getCsvHeader(label != null);
        csvWriter.println(header);
        csvWriter.flush();

        // Write Header to Google Sheets if enabled
        if (sheetsWriter != null) {
            sheetsWriter.writeHeader(header);
        }
    }

    public synchronized void processPacket(Packet packet, Timestamp timestamp) {
        if (packet == null || timestamp == null)
            return;

        // FIX #9: Timestamp Validation
        long currentTime = timestamp.getTime();

        // Sanity check: Timestamp must be between 2017-01-01 and 2030-01-01
        if (currentTime < 1483228800000L || currentTime > 1893456000000L) {
            // Invalid timestamp - skip this packet
            logger.warn("Invalid timestamp detected and skipped: {}", timestamp);
            return;
        }

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);

        if (ipV4Packet == null && ipV6Packet == null)
            return;

        InetAddress srcIp;
        InetAddress dstIp;

        if (ipV4Packet != null) {
            srcIp = ipV4Packet.getHeader().getSrcAddr();
            dstIp = ipV4Packet.getHeader().getDstAddr();
        } else {
            srcIp = ipV6Packet.getHeader().getSrcAddr();
            dstIp = ipV6Packet.getHeader().getDstAddr();
        }

        int srcPort = 0;
        int dstPort = 0;
        String protocol = "";

        boolean isTcp = false;
        boolean isUdp = false;

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            dstPort = tcp.getHeader().getDstPort().valueAsInt();
            protocol = "TCP";
            isTcp = true;
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            srcPort = udp.getHeader().getSrcPort().valueAsInt();
            dstPort = udp.getHeader().getDstPort().valueAsInt();
            protocol = "UDP";
            isUdp = true;
        } else {
            return; // Ignore non-TCP/UDP
        }

        // Define Flow Keys
        FlowKey fwdKey = new FlowKey(srcIp, dstIp, srcPort, dstPort, protocol);
        FlowKey bwdKey = new FlowKey(dstIp, srcIp, dstPort, srcPort, protocol);

        Flow flow = null;
        boolean isForward = true;

        if (activeFlows.containsKey(fwdKey)) {
            flow = activeFlows.get(fwdKey);
            isForward = true;
        } else if (activeFlows.containsKey(bwdKey)) {
            flow = activeFlows.get(bwdKey);
            isForward = false;
        }

        // Optimization: Strict Timeout Check BEFORE updating
        if (flow != null) {
            long lastTime = flow.getLastPacketTime();
            // Use existing currentTime variable from line 43
            if ((currentTime - lastTime) > flowTimeoutMillis) {
                // Flow timed out. Export it and treat this packet as start of NEW flow.
                exportFlow(flow);

                // FIX #3: Find and remove the CORRECT key
                FlowKey keyToRemove = activeFlows.containsKey(fwdKey) ? fwdKey : bwdKey;
                activeFlows.remove(keyToRemove);

                flow = null; // Force creation of new flow below
            }
        }

        if (flow == null) {
            // New Flow
            boolean isDns = (srcPort == 53 || dstPort == 53);
            flow = new Flow(fwdKey, timestamp.getTime(), isDns, label);
            activeFlows.put(fwdKey, flow);
            isForward = true;
        }

        // Update Flow
        flow.addPacket(packet, timestamp.getTime(), isForward);

        // Check TCP FIN/RST for termination (Optional optimization)
        if (isTcp) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp.getHeader().getFin() || tcp.getHeader().getRst()) {
                // Terminate flow? Usually we wait for timeout or full handshake close,
                // but for simplicity we can just keep until timeout or aggressive close.
            }
        }

        packetCounter++;
        // FIX #5: Lazy Cleanup with both packet count AND time-based checks
        // Check timeout every 5000 packets OR every 30 seconds
        if (packetCounter % 5000 == 0 || (currentTime - lastTimeoutCheck) > 30000) {
            checkTimeout(currentTime);
            lastTimeoutCheck = currentTime;
        }
    }

    private void checkTimeout(long currentTime) {
        List<FlowKey> toRemove = new ArrayList<>();

        for (Map.Entry<FlowKey, Flow> entry : activeFlows.entrySet()) {
            Flow flow = entry.getValue();
            if ((currentTime - flow.getLastPacketTime()) > flowTimeoutMillis) {
                exportFlow(flow);
                toRemove.add(entry.getKey());
            }
        }

        for (FlowKey key : toRemove) {
            activeFlows.remove(key);
        }
    }

    public synchronized void dumpAll() {
        if (isDumped)
            return;

        // FIX #10: Create snapshot to avoid ConcurrentModificationException
        List<Flow> flowsToExport = new ArrayList<>(activeFlows.values());
        activeFlows.clear();

        for (Flow flow : flowsToExport) {
            try {
                exportFlow(flow);
            } catch (Exception e) {
                logger.error("Failed to export flow: " + flow.getKey(), e);
            }
        }

        csvWriter.flush();

        // Flush Google Sheets if enabled
        if (sheetsWriter != null) {
            try {
                sheetsWriter.flush();
            } catch (Exception e) {
                logger.error("Failed to flush Google Sheets data", e);
            }
        }

        isDumped = true;
    }

    private void exportFlow(Flow flow) {
        String csvRow = flow.toCsvRow();
        csvWriter.println(csvRow);

        // Also write to Google Sheets if enabled
        if (sheetsWriter != null) {
            sheetsWriter.writeRow(csvRow);
        }
    }
}
