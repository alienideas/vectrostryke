#include "vs_engine/signature.hpp"
#include <cstring>

namespace vs {

#if defined(VS_ENGINE_USE_ASM) && defined(__x86_64__) && defined(__GNUC__)
extern "C" const uint8_t* vs_asm_pattern_search(const uint8_t* hay, size_t hay_len,
                                                const uint8_t* needle, size_t needle_len);
#endif

const uint8_t* pattern_search(const uint8_t* hay, size_t hay_len, const uint8_t* needle,
                              size_t needle_len) {
  if (!hay || !needle || needle_len == 0 || hay_len < needle_len) return nullptr;
#if defined(VS_ENGINE_USE_ASM) && defined(__x86_64__) && defined(__GNUC__)
  if (const uint8_t* p = vs_asm_pattern_search(hay, hay_len, needle, needle_len)) return p;
#endif
  for (size_t i = 0; i + needle_len <= hay_len; ++i) {
    if (hay[i] != needle[0]) continue;
    if (std::memcmp(hay + i, needle, needle_len) == 0) return hay + i;
  }
  return nullptr;
}

}  // namespace vs
