#pragma once
#include <mutex>
#include <string>
#include "vs_engine/config.hpp"
#include "vs_engine/signature.hpp"
#include "vs_engine/vs_engine.h"
namespace vs {
class Engine {
 public:
  explicit Engine(std::string config_path);
  int load_config();
  int save_config();
  int set_mode(vs_response_mode_t mode);
  vs_response_mode_t mode() const;
  int start();
  int stop();
  bool running() const;
  void fill_status(vs_engine_status_t* out) const;
  int load_signatures(const std::string& path);
  int match_signatures(const std::string& path, vs_finding_t* out);
  int scan_path(const std::string& root, vs_scan_result_t* out);
 private:
  Config cfg_;
  SignatureDB sigs_;
  mutable std::mutex mu_;
  bool running_ = false;
  size_t last_scan_files_ = 0;
};
}
