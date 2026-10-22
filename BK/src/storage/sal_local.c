#include "vsbk/sal.h"
#include "vsbk/pipeline.h"
#include <errno.h>
#include <sys/stat.h>

struct vsbk_storage {
  char root[VSBK_MAX_PATH];
};

vsbk_storage_t *vsbk_storage_open_local(const char *root) {
  vsbk_storage_t *s = calloc(1, sizeof(*s));
  if (!s) return NULL;
  snprintf(s->root, sizeof(s->root), "%s", root);
  if (vsbk_mkdir_p(s->root) != 0) { free(s); return NULL; }
  return s;
}

void vsbk_storage_close(vsbk_storage_t *s) { free(s); }

static int key_to_path(const vsbk_storage_t *s, const char *key, char *out, size_t out_sz) {
  if (strstr(key, "..") != NULL) return -1;
  return vsbk_path_join(out, out_sz, s->root, key);
}

int vsbk_storage_put_file(vsbk_storage_t *s, const char *key, FILE *in, char *sha_out) {
  char path[VSBK_MAX_PATH];
  if (key_to_path(s, key, path, sizeof(path)) != 0) return -1;
  char parent[VSBK_MAX_PATH];
  snprintf(parent, sizeof(parent), "%s", path);
  for (char *p = parent + strlen(parent); p > parent; p--) {
    if (*p == '/' || *p == '\\') { *p = '\0'; break; }
  }
  vsbk_mkdir_p(parent);
  FILE *out = fopen(path, "wb");
  if (!out) return -1;
  uint8_t buf[1024 * 64];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (fwrite(buf, 1, n, out) != n) { fclose(out); return -1; }
  }
  fclose(out);
  if (sha_out) {
    if (vsbk_sha256_file(path, sha_out) != 0) sha_out[0] = '\0';
  }
  return 0;
}

int vsbk_storage_put_mem(vsbk_storage_t *s, const char *key, const void *data, size_t len) {
  char path[VSBK_MAX_PATH];
  if (key_to_path(s, key, path, sizeof(path)) != 0) return -1;
  char parent[VSBK_MAX_PATH];
  snprintf(parent, sizeof(parent), "%s", path);
  for (char *p = parent + strlen(parent); p > parent; p--) {
    if (*p == '/' || *p == '\\') { *p = '\0'; break; }
  }
  vsbk_mkdir_p(parent);
  FILE *out = fopen(path, "wb");
  if (!out) return -1;
  if (fwrite(data, 1, len, out) != len) { fclose(out); return -1; }
  fclose(out);
  return 0;
}

int vsbk_storage_exists(vsbk_storage_t *s, const char *key) {
  char path[VSBK_MAX_PATH];
  if (key_to_path(s, key, path, sizeof(path)) != 0) return 0;
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int vsbk_storage_delete(vsbk_storage_t *s, const char *key) {
  char path[VSBK_MAX_PATH];
  if (key_to_path(s, key, path, sizeof(path)) != 0) return -1;
  return remove(path);
}
