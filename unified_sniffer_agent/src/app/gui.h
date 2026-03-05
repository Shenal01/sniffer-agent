#pragma once

#include <pcap.h>
#include <string>
#include <vector>


namespace app {

struct GuiResult {
  bool start_requested = false;
  std::string selected_interface;
};

class Gui {
public:
  static GuiResult show_setup_dialog(pcap_if_t *interfaces, bool db_connected);
};

} // namespace app
