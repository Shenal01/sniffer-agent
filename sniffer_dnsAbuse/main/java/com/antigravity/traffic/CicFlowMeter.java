package com.antigravity.traffic;

import org.apache.commons.cli.*;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.Duration;
import java.time.format.DateTimeFormatter;

public class CicFlowMeter {

    public static void main(String[] args) {
        Options options = new Options();
        options.addOption("f", "file", true, "Input PCAP file");
        options.addOption("i", "interface", true, "Network Interface");
        options.addOption("o", "output", true, "Output CSV file (default: flow_output.csv)");
        options.addOption("l", "list", false, "List available interfaces");
        options.addOption("a", "attack", false, "Label flows as ATTACK (for training data)");
        options.addOption("b", "benign", false, "Label flows as BENIGN (default)");
        options.addOption("g", "google", true, "Enable Google Sheets output (provide credentials file path)");
        options.addOption("s", "sheet-id", true,
                "Google Sheet ID to append data (optional, creates new if not provided)");
        options.addOption("h", "help", false, "Show this help message");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter helpFormatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args);

            // Show help
            if (cmd.hasOption("h") || args.length == 0) {
                System.out.println("CIC-Flow-Meter-DNS: DNS Traffic Analysis Tool");
                System.out.println("============================================\n");
                helpFormatter.printHelp("java -jar net-traffic-analysis.jar [OPTIONS]", "\nOptions:", options,
                        "\nExamples:\n" +
                                "  List interfaces:\n" +
                                "    java -jar net-traffic-analysis.jar -l\n\n" +
                                "  Capture attack traffic:\n" +
                                "    java -jar net-traffic-analysis.jar -f attack.pcap -o attack.csv -a\n\n" +
                                "  Capture benign traffic:\n" +
                                "    java -jar net-traffic-analysis.jar -f normal.pcap -o benign.csv -b\n\n" +
                                "  Live capture from interface:\n" +
                                "    java -jar net-traffic-analysis.jar -i eth0 -o live.csv -b\n\n" +
                                "  Create CSV and new Google Sheet:\n" +
                                "    java -jar net-traffic-analysis.jar -f attack.pcap -o attack.csv -a --google creds.json\n\n"
                                +
                                "  Append to existing Google Sheet:\n" +
                                "    java -jar net-traffic-analysis.jar -f normal.pcap -o normal.csv -b --google creds.json --sheet-id 1AbC123XyZ\n");
                return;
            }

            if (cmd.hasOption("l")) {
                try {
                    System.out.println("Available Interfaces:");
                    for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                        System.out.printf("Name: [%s]\nDescription: [%s]\nMac Address: [%s]\n\n",
                                nif.getName(),
                                (nif.getDescription() != null ? nif.getDescription() : "No description"),
                                (nif.getLinkLayerAddresses().isEmpty() ? "Unknown"
                                        : nif.getLinkLayerAddresses().get(0)));
                    }
                } catch (PcapNativeException e) {
                    System.err.println("Error listing interfaces: " + e.getMessage());
                }
                return;
            }

            String pcapFile = cmd.getOptionValue("f");
            String ifaceName = cmd.getOptionValue("i");
            String outputFile = cmd.getOptionValue("o", "flow_output.csv");
            String googleCredsPath = cmd.getOptionValue("g");
            String sheetId = cmd.getOptionValue("s");
            boolean enableGoogleSheets = (googleCredsPath != null);

            // Determine label: ATTACK, BENIGN, or null (no label)
            String label = null; // No label by default
            if (cmd.hasOption("a")) {
                label = "ATTACK";
                System.out.println("[Label Mode] ATTACK - Flows will be labeled as attack traffic");
            } else if (cmd.hasOption("b")) {
                label = "BENIGN";
                System.out.println("[Label Mode] BENIGN - Flows will be labeled as benign traffic");
            } else {
                System.out.println("[No Label Mode] - Label column will not be created. Use -a or -b to add labels.");
            }

            if (pcapFile == null && ifaceName == null) {
                System.out.println("Please specify input file (-f), interface (-i), or use -h for help");
                return;
            }

            try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                // Initialize Google Sheets writer if enabled
                GoogleSheetsWriter sheetsWriter = null;
                if (enableGoogleSheets) {
                    try {
                        if (sheetId != null) {
                            // Append to existing sheet
                            System.out.println("Google Sheets output enabled. Appending to sheet ID: " + sheetId);
                            sheetsWriter = new GoogleSheetsWriter(googleCredsPath, sheetId, label != null);
                        } else {
                            // Create new sheet
                            String sheetName = "DNS_Traffic_"
                                    + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
                            System.out.println("Google Sheets output enabled. Creating new sheet: " + sheetName);
                            sheetsWriter = new GoogleSheetsWriter(googleCredsPath, sheetName, label != null);
                        }
                    } catch (Exception e) {
                        System.err.println("\nFailed to initialize Google Sheets: " + e.getMessage());
                        System.err.println("Continuing with CSV-only output...\n");
                        sheetsWriter = null; // Disable Google Sheets on error
                    }
                }

                FlowManager flowManager = new FlowManager(writer, label, sheetsWriter);
                PcapHandle handle;
                boolean isLiveCapture = (pcapFile == null); // Track mode

                // Record start time
                LocalDateTime startTime = LocalDateTime.now();
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

                if (pcapFile != null) {
                    System.out.println("Reading from file: " + pcapFile);
                    handle = Pcaps.openOffline(pcapFile);
                } else {
                    PcapNetworkInterface nif = Pcaps.getDevByName(ifaceName);
                    if (nif == null) {
                        System.out.println("Interface not found: " + ifaceName);
                        return;
                    }
                    System.out.println("Listening on interface: " + ifaceName);
                    System.out.println("Press Ctrl+C to stop capture...");
                    int snapLen = 65536;
                    PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
                    int timeout = 10;
                    handle = nif.openLive(snapLen, mode, timeout);
                }

                // Log start time
                System.out.println("Start time: " + startTime.format(formatter));

                PcapHandle finalHandle = handle;
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("\nStopping capture and dumping flows...");
                    try {
                        if (finalHandle != null && finalHandle.isOpen()) {
                            finalHandle.breakLoop();
                        }
                        flowManager.dumpAll();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }));

                // FIX #8: Track packet processing statistics
                long totalPackets = 0;
                long skippedPackets = 0;

                // Keep looping
                // Manual Loop for Robustness
                try {
                    while (handle.isOpen()) {
                        Packet packet = null;

                        try {
                            packet = handle.getNextPacket();
                        } catch (IllegalArgumentException e) {
                            // Malformed packet (e.g. invalid IPv6 options). Skip it.
                            skippedPackets++;
                            totalPackets++;

                            // FIX #8: Periodic logging
                            if (skippedPackets % 1000 == 0) {
                                System.err.printf("Warning: Skipped %d malformed packets so far (%.2f%%)%n",
                                        skippedPackets, 100.0 * skippedPackets / totalPackets);
                            }
                            continue;
                        } catch (Exception e) {
                            // Any other parsing error, skip.
                            skippedPackets++;
                            totalPackets++;
                            continue;
                        }

                        if (packet == null) {
                            if (isLiveCapture) {
                                // Live capture: null = no packet available right now, keep waiting
                                continue;
                            } else {
                                // File mode: null = end of file
                                break;
                            }
                        }

                        // Got a valid packet
                        totalPackets++;
                        Timestamp ts = handle.getTimestamp();
                        flowManager.processPacket(packet, ts);
                    }
                } catch (Exception e) {
                    System.err.println("Error in packet loop: " + e.getMessage());
                }

                flowManager.dumpAll();
                handle.close();

                // FIX #8: Report packet processing statistics
                System.out.printf("\nPacket Processing Summary:%n");
                System.out.printf("  Total packets: %d%n", totalPackets);
                System.out.printf("  Skipped packets: %d (%.2f%%)%n",
                        skippedPackets, 100.0 * skippedPackets / totalPackets);

                // Record end time and calculate duration
                LocalDateTime endTime = LocalDateTime.now();
                Duration duration = Duration.between(startTime, endTime);
                long hours = duration.toHours();
                long minutes = duration.toMinutesPart();
                long seconds = duration.toSecondsPart();

                System.out.println("Done. Output written to " + outputFile);

                // Print Google Sheets URL if enabled
                if (enableGoogleSheets && sheetsWriter != null) {
                    System.out.println("\nGoogle Sheet URL: " + sheetsWriter.getSpreadsheetUrl());
                }

                System.out.println("\nStart time: " + startTime.format(formatter));
                System.out.println("End time: " + endTime.format(formatter));
                System.out.printf("Duration: %02d:%02d:%02d%n", hours, minutes, seconds);

            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (ParseException e) {
            System.out.println("Command parsing failed: " + e.getMessage());
        }
    }
}
