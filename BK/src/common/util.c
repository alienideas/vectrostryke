#include "vsbk/common.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#ifdef _WIN32
  #include <direct.h>
  #define mkdir(path, mode) _mkdir(path)
#else
  #include <unistd.h>
#endif

void vsbk_log(int level, const char *fmt, ...) {
  (void)level;
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
}

int vsbk_path_join(char *out, size_t out_sz, const char *a, const char *b) {
  if (!out || out_sz == 0 || !a || !b) return -1;
  size_t la = strlen(a);
  int need_sep = (la > 0 && a[la - 1] != '/' && a[la - 1] != '\\');
  int n = snprintf(out, out_sz, need_sep ? "%s" VSBK_PATH_SEP_STR "%s" : "%s%s", a, b);
  return (n < 0 || (size_t)n >= out_sz) ? -1 : 0;
}

int vsbk_mkdir_p(const char *path) {
  char tmp[VSBK_MAX_PATH];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(tmp)) return -1;
  memcpy(tmp, path, len + 1);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/' || *p == '\\') {
      *p = '\0';
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
      }
      *p = VSBK_PATH_SEP;
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
  return 0;
}

bool vsbk_is_quarantine_path(const char *rel_path) {
  static const char *hints[] = {
    "quarantine", "vectorsstryke", "vectorstryke", ".vsbk_skip", NULL
  };
  char lower[VSBK_MAX_PATH];
  size_t n = strlen(rel_path);
  if (n >= sizeof(lower)) n = sizeof(lower) - 1;
  for (size_t i = 0; i < n; i++)
    lower[i] = (char)tolower((unsigned char)rel_path[i]);
  lower[n] = '\0';
  for (int i = 0; hints[i]; i++) {
    if (strstr(lower, hints[i]) != NULL) return true;
  }
  return false;
}
