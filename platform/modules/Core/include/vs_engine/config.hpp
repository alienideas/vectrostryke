#pragma once
#include <string>
#include "vs_engine/vs_engine.h"

namespace vs {
struct Config {
  std::string config_path;
  std::string quarantine_dir;
  std::string signature_db;
  vs_response_mode_t mode = VS_MODE_AUTOMATIC;
  bool running_flag = false;
  bool auto_quarantine = true;
  size_t max_scan_files = 100000;
  static Config defaults(std::string config_path);
  bool load(const std::string& path);
  bool save(const std::string& path) const;
};
}
