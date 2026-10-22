#include "vs_engine/vs_engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

static int fails = 0;
#define EXPECT(cond) do { if (!(cond)) { std::fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__); ++fails; } } while (0)

int main() {
  const char* path = "/tmp/vs_test_engine.conf";
  vs_engine_t* e = vs_engine_create(path);
  EXPECT(e != nullptr);
  vs_response_mode_t m = VS_MODE_MANUAL;
  EXPECT(vs_engine_get_mode(e, &m) == VS_OK);
  EXPECT(vs_engine_set_mode(e, VS_MODE_MANUAL) == VS_OK);
  EXPECT(vs_engine_set_mode(e, VS_MODE_AUTOMATIC) == VS_OK);
  EXPECT(vs_engine_start(e) == VS_OK);
  vs_engine_status_t st{};
  EXPECT(vs_engine_get_status(e, &st) == VS_OK);
  EXPECT(vs_engine_stop(e) == VS_OK);
  EXPECT(std::strcmp(vs_engine_version(), "0.2.0-e4") == 0);
  vs_engine_destroy(e);
  if (fails) return 1;
  std::printf("test_mode OK\n");
  return 0;
}
