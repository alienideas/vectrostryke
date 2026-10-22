#pragma once
#include <string>
#include "vs_engine/vs_engine.h"
namespace vs {
bool heuristic_analyze(const std::string& path, vs_finding_t* out);
}
