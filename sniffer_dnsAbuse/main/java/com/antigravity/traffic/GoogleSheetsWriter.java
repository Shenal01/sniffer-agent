package com.antigravity.traffic;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.sheets.v4.Sheets;
import com.google.api.services.sheets.v4.SheetsScopes;
import com.google.api.services.sheets.v4.model.*;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Handles Google Sheets API operations for exporting DNS flow data.
 * Supports both creating new spreadsheets and appending to existing ones.
 */
public class GoogleSheetsWriter {
    private static final String APPLICATION_NAME = "CIC-Flow-Meter-DNS";
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();
    private static final List<String> SCOPES = Collections.singletonList(SheetsScopes.SPREADSHEETS);
    private static final int BATCH_SIZE = 100; // Write every 100 rows

    private final Sheets sheetsService;
    private final String spreadsheetId;
    private final String sheetName;
    private final boolean includeLabel;
    private final String serviceAccountEmail;

    private List<List<Object>> rowBuffer;
    private boolean headerWritten;
    private int nextRow;

    /**
     * Creates a GoogleSheetsWriter that can create a new sheet or append to
     * existing.
     * 
     * @param credentialsPath Path to the service account JSON credentials file
     * @param sheetIdOrName   If looks like a Sheet ID, appends to existing sheet.
     *                        Otherwise creates new sheet with this name.
     * @param includeLabel    Whether to include the Label column in the schema
     * @throws IOException              If credentials file cannot be read
     * @throws GeneralSecurityException If there's an issue with HTTP transport
     */
    public GoogleSheetsWriter(String credentialsPath, String sheetIdOrName, boolean includeLabel)
            throws IOException, GeneralSecurityException {
        this.includeLabel = includeLabel;
        this.rowBuffer = new ArrayList<>();
        this.headerWritten = false;

        // Initialize Google Sheets service
        NetHttpTransport httpTransport = GoogleNetHttpTransport.newTrustedTransport();

        // Extract service account email from credentials file
        this.serviceAccountEmail = extractServiceAccountEmail(credentialsPath);

        GoogleCredentials credentials = GoogleCredentials
                .fromStream(new FileInputStream(credentialsPath))
                .createScoped(SCOPES);

        this.sheetsService = new Sheets.Builder(
                httpTransport,
                JSON_FACTORY,
                new HttpCredentialsAdapter(credentials))
                .setApplicationName(APPLICATION_NAME)
                .build();

        // Determine if we're appending to existing sheet or creating new
        if (isSheetId(sheetIdOrName)) {
            // Append mode: use existing sheet
            this.spreadsheetId = sheetIdOrName;
            this.sheetName = getFirstSheetName(spreadsheetId);
            this.nextRow = findNextEmptyRow(spreadsheetId, sheetName);
            this.headerWritten = (nextRow > 1); // Header exists if we're not on row 1

            System.out.println("  → Appending to existing sheet (starting at row " + nextRow + ")");
        } else {
            // Create mode: create new spreadsheet
            this.sheetName = sheetIdOrName;
            this.spreadsheetId = createNewSpreadsheet(sheetIdOrName);
            this.nextRow = 1;
            this.headerWritten = false;

            System.out.println("  → Created new spreadsheet");
        }
    }

    /**
     * Determines if a string looks like a Sheet ID (alphanumeric) vs a sheet name.
     */
    private boolean isSheetId(String value) {
        // Sheet IDs are long alphanumeric strings with underscores/hyphens
        // Sheet names typically have spaces, are shorter, or start with specific
        // patterns
        return value != null &&
                value.length() > 20 &&
                value.matches("[a-zA-Z0-9_-]+");
    }

    /**
     * Extracts the service account email from the credentials JSON file.
     */
    private static String extractServiceAccountEmail(String credentialsPath) {
        try (FileReader reader = new FileReader(credentialsPath)) {
            JsonObject jsonObject = JsonParser.parseReader(reader).getAsJsonObject();
            String email = jsonObject.get("client_email").getAsString();
            return email != null ? email : "unknown@serviceaccount";
        } catch (Exception e) {
            return "unknown@serviceaccount"; // Fallback
        }
    }

    /**
     * Creates a new Google Spreadsheet with the given name.
     */
    private String createNewSpreadsheet(String title) throws IOException {
        try {
            Spreadsheet spreadsheet = new Spreadsheet()
                    .setProperties(new SpreadsheetProperties().setTitle(title));

            spreadsheet = sheetsService.spreadsheets().create(spreadsheet)
                    .setFields("spreadsheetId")
                    .execute();

            return spreadsheet.getSpreadsheetId();
        } catch (IOException e) {
            throw new IOException("Failed to create new spreadsheet. " +
                    "Ensure Google Sheets API is enabled and credentials are valid. " +
                    "Service account: " + serviceAccountEmail, e);
        }
    }

    /**
     * Gets the name of the first sheet in a spreadsheet.
     */
    private String getFirstSheetName(String spreadsheetId) throws IOException {
        try {
            Spreadsheet spreadsheet = sheetsService.spreadsheets()
                    .get(spreadsheetId)
                    .execute();

            if (spreadsheet.getSheets() != null && !spreadsheet.getSheets().isEmpty()) {
                return spreadsheet.getSheets().get(0).getProperties().getTitle();
            }
            return "Sheet1"; // Default fallback
        } catch (IOException e) {
            if (e.getMessage().contains("403") || e.getMessage().contains("PERMISSION_DENIED")) {
                throw new IOException("\n" +
                        "╔══════════════════════════════════════════════════════════════════════════╗\n" +
                        "║ ERROR: Permission Denied (403)                                           ║\n" +
                        "╠══════════════════════════════════════════════════════════════════════════╣\n" +
                        "║ The service account does not have access to this Google Sheet.          ║\n" +
                        "║                                                                          ║\n" +
                        "║ SOLUTION:                                                                ║\n" +
                        "║ 1. Open the Google Sheet in your browser                                ║\n" +
                        "║ 2. Click the 'Share' button (top-right)                                 ║\n" +
                        "║ 3. Add this email with 'Editor' permission:                             ║\n" +
                        "║                                                                          ║\n" +
                        "║    " + String.format("%-66s", serviceAccountEmail) + "║\n" +
                        "║                                                                          ║\n" +
                        "║ 4. Uncheck 'Notify people' and click 'Share'                            ║\n" +
                        "╚══════════════════════════════════════════════════════════════════════════╝\n", e);
            }
            throw new IOException("Failed to access spreadsheet: " + e.getMessage(), e);
        }
    }

    /**
     * Finds the next empty row in a sheet (for appending).
     */
    private int findNextEmptyRow(String spreadsheetId, String sheetName) throws IOException {
        try {
            ValueRange response = sheetsService.spreadsheets().values()
                    .get(spreadsheetId, sheetName + "!A:A")
                    .execute();

            List<List<Object>> values = response.getValues();
            if (values == null || values.isEmpty()) {
                return 1; // Sheet is empty
            }
            return values.size() + 1; // Next row after last data
        } catch (IOException e) {
            if (e.getMessage().contains("403") || e.getMessage().contains("PERMISSION_DENIED")) {
                throw new IOException("\n" +
                        "╔══════════════════════════════════════════════════════════════════════════╗\n" +
                        "║ ERROR: Permission Denied (403)                                           ║\n" +
                        "╠══════════════════════════════════════════════════════════════════════════╣\n" +
                        "║ The service account does not have access to this Google Sheet.          ║\n" +
                        "║                                                                          ║\n" +
                        "║ SOLUTION:                                                                ║\n" +
                        "║ 1. Open the Google Sheet in your browser                                ║\n" +
                        "║ 2. Click the 'Share' button (top-right)                                 ║\n" +
                        "║ 3. Add this email with 'Editor' permission:                             ║\n" +
                        "║                                                                          ║\n" +
                        "║    " + String.format("%-66s", serviceAccountEmail) + "║\n" +
                        "║                                                                          ║\n" +
                        "║ 4. Uncheck 'Notify people' and click 'Share'                            ║\n" +
                        "╚══════════════════════════════════════════════════════════════════════════╝\n", e);
            }
            return 1; // If can't read, assume empty
        }
    }

    /**
     * Writes the CSV header row to the sheet.
     */
    public void writeHeader(String headerRow) {
        if (headerWritten) {
            return; // Already has header, skip
        }

        List<Object> headerCells = new ArrayList<Object>(Arrays.asList(headerRow.split(",")));
        rowBuffer.add(headerCells);
        headerWritten = true;
    }

    /**
     * Buffers a CSV row for writing to Google Sheets.
     * Automatically flushes when buffer reaches BATCH_SIZE.
     */
    public void writeRow(String csvRow) {
        List<Object> cells = new ArrayList<Object>(Arrays.asList(csvRow.split(",")));
        rowBuffer.add(cells);

        // Auto-flush when buffer is full
        if (rowBuffer.size() >= BATCH_SIZE) {
            try {
                flush();
            } catch (IOException e) {
                System.err.println("Warning: Failed to write batch to Google Sheets: " + e.getMessage());
            }
        }
    }

    /**
     * Writes all buffered rows to Google Sheets.
     */
    public void flush() throws IOException {
        if (rowBuffer.isEmpty()) {
            return;
        }

        try {
            String range = sheetName + "!A" + nextRow;
            ValueRange body = new ValueRange().setValues(rowBuffer);

            sheetsService.spreadsheets().values()
                    .append(spreadsheetId, range, body)
                    .setValueInputOption("RAW")
                    .execute();

            nextRow += rowBuffer.size();
            System.out.println("  → Wrote " + rowBuffer.size() + " rows to Google Sheets");
            rowBuffer.clear();

        } catch (IOException e) {
            if (e.getMessage().contains("403") || e.getMessage().contains("PERMISSION_DENIED")) {
                throw new IOException("Permission denied. Please share the sheet with: " + serviceAccountEmail, e);
            }
            throw new IOException("Failed to write to Google Sheets: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the URL to view the spreadsheet in a browser.
     */
    public String getSpreadsheetUrl() {
        return "https://docs.google.com/spreadsheets/d/" + spreadsheetId + "/edit";
    }

    /**
     * Gets the spreadsheet ID.
     */
    public String getSpreadsheetId() {
        return spreadsheetId;
    }
}
