#include "vs_engine/signature.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace vs {

void SignatureDB::clear() { rules_.clear(); }

bool SignatureDB::load_file(const std::string& path) {
  clear();
  std::ifstream in(path);
  if (!in) return false;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream iss(line);
    std::string id, score_s, tier_s, pattern;
    if (!std::getline(iss, id, '|')) continue;
    if (!std::getline(iss, score_s, '|')) continue;
    if (!std::getline(iss, tier_s, '|')) continue;
    if (!std::getline(iss, pattern)) continue;
    SigRule r;
    r.id = id;
    r.pattern = pattern;
    try { r.score = std::stoi(score_s); } catch (...) { r.score = 70; }
    int t = 1;
    try { t = std::stoi(tier_s); } catch (...) {}
    r.tier = (t >= 2) ? VS_TIER_MALICIOUS : VS_TIER_SUSPICIOUS;
    if (!r.pattern.empty()) rules_.push_back(std::move(r));
  }
  return !rules_.empty();
}

bool SignatureDB::match_buffer(const uint8_t* data, size_t len, const char* path_for_finding,
                               vs_finding_t* out) const {
  if (!data || len == 0) return false;
  const SigRule* best = nullptr;
  for (const auto& r : rules_) {
    auto* n = reinterpret_cast<const uint8_t*>(r.pattern.data());
    if (pattern_search(data, len, n, r.pattern.size())) {
      if (!best || r.score > best->score) best = &r;
    }
  }
  if (!best) return false;
  if (out) {
    std::memset(out, 0, sizeof(*out));
    out->kind = VS_KIND_SIGNATURE;
    out->tier = best->tier;
    out->score = best->score;
    if (path_for_finding)
      std::snprintf(out->path, sizeof(out->path), "%s", path_for_finding);
    std::snprintf(out->rule_id, sizeof(out->rule_id), "%s", best->id.c_str());
    std::snprintf(out->message, sizeof(out->message), "Signature matched: %s", best->id.c_str());
  }
  return true;
}

bool SignatureDB::match_file(const std::string& path, vs_finding_t* out) const {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::string buf(1 << 20, '\0');
  in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
  auto got = static_cast<size_t>(in.gcount());
  return match_buffer(reinterpret_cast<const uint8_t*>(buf.data()), got, path.c_str(), out);
}

}  // namespace vs
