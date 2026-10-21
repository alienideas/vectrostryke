#ifndef VSBK_COMMON_H
#define VSBK_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#ifdef _WIN32
  #define VSBK_PATH_SEP '\\'
  #define VSBK_PATH_SEP_STR "\\"
#else
  #define VSBK_PATH_SEP '/'
  #define VSBK_PATH_SEP_STR "/"
#endif

#define VSBK_MAX_PATH 4096
#define VSBK_SHA256_HEX 65
#define VSBK_JOB_ID_LEN 64

typedef struct {
  char mode[32];
  char agent_id[128];
  char storage_path[VSBK_MAX_PATH];
  char data_dir[VSBK_MAX_PATH];
  int  respect_quarantine;
  char hook_url[512];
  int  log_level;
} vsbk_config_t;

void vsbk_config_from_env(vsbk_config_t *cfg);
void vsbk_log(int level, const char *fmt, ...);
int  vsbk_mkdir_p(const char *path);
int  vsbk_path_join(char *out, size_t out_sz, const char *a, const char *b);
bool vsbk_is_quarantine_path(const char *rel_path);

#endif /* VSBK_COMMON_H */
