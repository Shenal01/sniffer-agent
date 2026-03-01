#include "gui.h"
#include "storage/mysql_client.h"
#include <windows.h>
#include <commctrl.h>
#include <fmt/core.h>

#pragma comment(lib, "comctl32.lib")

namespace app {

// Global/Statics for the callback
static pcap_if_t* g_interfaces = nullptr;
static GuiResult g_result;
static HWND g_hCombo = NULL;
static HWND g_hStatus = NULL;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Title
            CreateWindow("STATIC", "Select Network Interface:", 
                         WS_VISIBLE | WS_CHILD, 
                         20, 20, 300, 20, hwnd, NULL, NULL, NULL);

            // Interface Dropdown
            g_hCombo = CreateWindow(WC_COMBOBOX, "", 
                                    CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE | WS_VSCROLL, 
                                    20, 45, 340, 200, hwnd, (HMENU)101, NULL, NULL);

            int i = 0;
            for (pcap_if_t* d = g_interfaces; d != nullptr; d = d->next) {
                std::string name = d->name ? d->name : "";
                std::string description = d->description ? d->description : "";
                
                // --- FILTERING LOGIC ---
                // Skip if no description (usually internal/system devices)
                if (description.empty()) continue; 

                // Skip Virtual/Internal adapters that aren't useful for sniffing
                if (description.find("WAN Miniport") != std::string::npos ||
                    description.find("Microsoft Wi-Fi Direct") != std::string::npos ||
                    description.find("Microsoft IPP Class Driver") != std::string::npos ||
                    description.find("NPF_Loopback") != std::string::npos) {
                    continue;
                }

                // Check for IP address (active interface check)
                bool has_ip = false;
                for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
                    if (a->addr && a->addr->sa_family == AF_INET) {
                        has_ip = true;
                        break;
                    }
                }
                
                // Format: "Description (Port/Name)"
                std::string display;
                if (has_ip) {
                    display = fmt::format("{} [ACTIVE]", description);
                } else {
                    display = description;
                }

                SendMessage(g_hCombo, CB_ADDSTRING, 0, (LPARAM)display.c_str());
                
                // Store the actual device name for the start requested logic
                // (We'll need to mapping this back)
                SendMessage(g_hCombo, CB_SETITEMDATA, i, (LPARAM)d);

                // Auto-select the first ACTIVE interface
                if (has_ip && SendMessage(g_hCombo, CB_GETCURSEL, 0, 0) == -1) {
                    SendMessage(g_hCombo, CB_SETCURSEL, i, 0);
                }
                i++;
            }
            if (i > 0 && SendMessage(g_hCombo, CB_GETCURSEL, 0, 0) == -1) {
                SendMessage(g_hCombo, CB_SETCURSEL, 0, 0);
            }

            // Prerequisite Note
            CreateWindow("STATIC", "Prerequisites:", 
                         WS_VISIBLE | WS_CHILD, 
                         20, 85, 300, 20, hwnd, NULL, NULL, NULL);

            g_hStatus = CreateWindow("STATIC", "Checking system status...", 
                                     WS_VISIBLE | WS_CHILD, 
                                     20, 105, 340, 60, hwnd, NULL, NULL, NULL);

            // Notes
            CreateWindow("STATIC", "Note: Ensure Npcap is installed and Database is reachable.", 
                         WS_VISIBLE | WS_CHILD | SS_LEFT, 
                         20, 170, 340, 40, hwnd, NULL, NULL, NULL);

            // Start Button
            CreateWindow("BUTTON", "Start Sniffing", 
                         WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 
                         120, 220, 140, 35, hwnd, (HMENU)102, NULL, NULL);
            
            return 0;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == 102) { // Start Button
                int sel = (int)SendMessage(g_hCombo, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR) {
                    pcap_if_t* d = (pcap_if_t*)SendMessage(g_hCombo, CB_GETITEMDATA, sel, 0);
                    if (d) {
                        g_result.selected_interface = d->name;
                        g_result.start_requested = true;
                        DestroyWindow(hwnd);
                    }
                }
            }
            return 0;
        }

        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

GuiResult Gui::show_setup_dialog(pcap_if_t* interfaces) {
    g_interfaces = interfaces;
    g_result = GuiResult();

    HINSTANCE hInstance = GetModuleHandle(NULL);
    
    // Register Window Class
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ExfiltrapGuiClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    // Create Window centered
    int width = 400;
    int height = 310;
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    HWND hwnd = CreateWindowEx(
        0, "ExfiltrapGuiClass", "Exfiltrap Unified Sniffer Setup",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        (screenWidth - width) / 2, (screenHeight - height) / 2,
        width, height,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return g_result;

    // Set Font for all children
    HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    EnumChildWindows(hwnd, [](HWND child, LPARAM font) -> BOOL {
        SendMessage(child, WM_SETFONT, font, TRUE);
        return TRUE;
    }, (LPARAM)hFont);

    // Update Status
    std::string status = "Npcap Driver: INSTALLED";
    SetWindowText(g_hStatus, status.c_str());

    ShowWindow(hwnd, SW_SHOW);

    // Message Loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return g_result;
}

} // namespace app
