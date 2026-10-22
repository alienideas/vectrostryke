#include "vs_engine/scan.hpp"
#include "vs_engine/detect.hpp"
#include "vs_engine/signature.hpp"
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

namespace fs = std::filesystem;
namespace vs {

std::string quarantine_file(const Config& cfg, const std::string& path) {
  try {
    fs::create_directories(cfg.quarantine_dir);
    std::string name = fs::path(path).filename().string();
    std::ostringstream oss;
    oss << cfg.quarantine_dir << "/" << name << "." << std::hex << std::random_device{}();
    std::string dest = oss.str();
    fs::rename(path, dest);
    std::ofstream man(cfg.quarantine_dir + "/quarantine.log", std::ios::app);
    if (man) man << path << " -> " << dest << "\n";
    return dest;
  } catch (...) { return {}; }
}

ScanStats scan_path(const Config& cfg, const std::string& root, FindingEmitter emit) {
  ScanStats st;
  if (root.empty()) return st;
  auto handle_file = [&](const fs::path& p) {
    if (st.files_scanned >= cfg.max_scan_files) return;
    ++st.files_scanned;
    vs_finding_t f{};
    bool hit = heuristic_analyze(p.string(), &f);
    if (!hit) return;
    ++st.findings_count;
    if (emit) emit(f);
    if (cfg.auto_quarantine && f.tier >= VS_TIER_SUSPICIOUS) {
      auto q = quarantine_file(cfg, p.string());
      if (!q.empty()) ++st.quarantined;
    }
  };
  try {
    fs::path rp(root);
    if (fs::is_regular_file(rp)) { handle_file(rp); return st; }
    if (!fs::is_directory(rp)) return st;
    for (auto it = fs::recursive_directory_iterator(rp, fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
      if (st.files_scanned >= cfg.max_scan_files) break;
      if (!it->is_regular_file()) continue;
      handle_file(it->path());
    }
  } catch (...) {}
  return st;
}
}  // namespace vs
