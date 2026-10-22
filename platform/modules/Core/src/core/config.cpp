#include "vs_engine/config.hpp"
#include <fstream>
#include <sstream>

namespace vs {

Config Config::defaults(std::string config_path) {
  Config c;
  c.config_path = std::move(config_path);
  c.quarantine_dir = "./data/quarantine";
  c.signature_db = "./data/signatures.vdb";
  c.mode = VS_MODE_AUTOMATIC;
  c.auto_quarantine = true;
  c.max_scan_files = 100000;
  return c;
}

bool Config::load(const std::string& path) {
  std::ifstream in(path);
  if (!in) return false;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0]=='#') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    auto k = line.substr(0, eq);
    auto v = line.substr(eq + 1);
    if (k == "ResponseMode") mode = (v == "Manual") ? VS_MODE_MANUAL : VS_MODE_AUTOMATIC;
    else if (k == "QuarantineDir") quarantine_dir = v;
    else if (k == "SignatureDB") signature_db = v;
    else if (k == "Running") running_flag = (v == "1" || v == "true");
    else if (k == "AutoQuarantine") auto_quarantine = (v != "0" && v != "false");
  }
  return true;
}

bool Config::save(const std::string& path) const {
  std::ofstream out(path);
  if (!out) return false;
  out << "ResponseMode=" << (mode == VS_MODE_MANUAL ? "Manual" : "Automatic") << "\n";
  out << "QuarantineDir=" << quarantine_dir << "\n";
  out << "SignatureDB=" << signature_db << "\n";
  out << "Running=" << (running_flag ? "1" : "0") << "\n";
  out << "AutoQuarantine=" << (auto_quarantine ? "1" : "0") << "\n";
  return true;
}

}  // namespace vs
