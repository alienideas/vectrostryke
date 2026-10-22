#include "vs_engine/vs_engine.h"
#include <cstdio>
#include <cstring>

static int fails = 0;
#define EXPECT(cond) do { if (!(cond)) { std::fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__); ++fails; } } while (0)

int main() {
  vs_engine_t* e = vs_engine_create("/tmp/vs_e2_engine.conf");
  EXPECT(e != nullptr);
  EXPECT(std::strcmp(vs_engine_version(), "0.2.0-e4") == 0);
  vs_engine_destroy(e);
  if (fails) return 1;
  std::printf("test_detect_scan OK\n");
  return 0;
}
