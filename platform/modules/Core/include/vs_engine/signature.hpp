#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "vs_engine/vs_engine.h"
namespace vs {
struct SigRule { std::string id; std::string pattern; int score=70; vs_threat_tier_t tier=VS_TIER_SUSPICIOUS; };
class SignatureDB {
 public:
  void clear();
  bool load_file(const std::string& path);
  bool match_buffer(const uint8_t* data, size_t len, const char* path_for_finding, vs_finding_t* out) const;
  bool match_file(const std::string& path, vs_finding_t* out) const;
 private:
  std::vector<SigRule> rules_;
};
const uint8_t* pattern_search(const uint8_t* hay, size_t hay_len, const uint8_t* needle, size_t needle_len);
}
