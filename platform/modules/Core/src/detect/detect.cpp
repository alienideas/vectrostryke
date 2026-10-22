#include "vs_engine/detect.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>

namespace vs {

bool heuristic_analyze(const std::string& path, vs_finding_t* out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  char buf[4096];
  in.read(buf, sizeof(buf));
  auto n = static_cast<size_t>(in.gcount());
  if (n == 0) return false;
  // Simple entropy/heuristic markers (Sprint depth)
  int high = 0;
  for (size_t i = 0; i < n; ++i) if ((unsigned char)buf[i] > 200) ++high;
  double ratio = (double)high / (double)n;
  if (ratio < 0.35) return false;
  if (out) {
    std::memset(out, 0, sizeof(*out));
    out->kind = VS_KIND_HEURISTIC;
    out->tier = (ratio > 0.55) ? VS_TIER_MALICIOUS : VS_TIER_SUSPICIOUS;
    out->score = (int)(ratio * 100);
    std::snprintf(out->path, sizeof(out->path), "%s", path.c_str());
    std::snprintf(out->rule_id, sizeof(out->rule_id), "entropy_high");
    std::snprintf(out->message, sizeof(out->message), "High entropy content ratio=%.2f", ratio);
  }
  return true;
}

}  // namespace vs
