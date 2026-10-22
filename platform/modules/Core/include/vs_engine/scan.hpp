#pragma once
#include <functional>
#include <string>
#include "vs_engine/config.hpp"
#include "vs_engine/vs_engine.h"
namespace vs {
struct ScanStats { size_t files_scanned=0; size_t findings_count=0; size_t quarantined=0; };
using FindingEmitter = std::function<void(const vs_finding_t&)>;
ScanStats scan_path(const Config& cfg, const std::string& root, FindingEmitter emit);
std::string quarantine_file(const Config& cfg, const std::string& path);
}
