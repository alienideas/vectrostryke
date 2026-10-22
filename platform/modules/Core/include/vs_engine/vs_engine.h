#pragma once
#ifdef __cplusplus
extern "C" {
#endif
int vs_engine_init(void);
int vs_engine_scan(const char *path);
void vs_engine_shutdown(void);
#ifdef __cplusplus
}
#endif
