#include "vsbk/pipeline.h"
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

static int manifest_add(vsbk_manifest_t *m, const vsbk_file_entry_t *e) {
  if (m->file_count >= m->file_cap) {
    size_t nc = m->file_cap ? m->file_cap * 2 : 64;
    vsbk_file_entry_t *nf = realloc(m->files, nc * sizeof(*nf));
    if (!nf) return -1;
    m->files = nf;
    m->file_cap = nc;
  }
  m->files[m->file_count++] = *e;
  return 0;
}

static int walk_dir(const char *root, const char *rel, int respect_q,
                    vsbk_file_entry_t **out, size_t *count, size_t *cap) {
  char full[VSBK_MAX_PATH];
  if (rel[0]) vsbk_path_join(full, sizeof(full), root, rel);
  else snprintf(full, sizeof(full), "%s", root);
  DIR *d = opendir(full);
  if (!d) return -1;
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
    char child_rel[VSBK_MAX_PATH];
    if (rel[0]) snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, de->d_name);
    else snprintf(child_rel, sizeof(child_rel), "%s", de->d_name);
    for (char *p = child_rel; *p; p++) if (*p == '\\') *p = '/';
    if (respect_q && vsbk_is_quarantine_path(child_rel)) continue;
    char child_full[VSBK_MAX_PATH];
    vsbk_path_join(child_full, sizeof(child_full), root, child_rel);
    struct stat st;
    if (stat(child_full, &st) != 0) continue;
    if (S_ISDIR(st.st_mode)) {
      walk_dir(root, child_rel, respect_q, out, count, cap);
    } else if (S_ISREG(st.st_mode)) {
      if (*count >= *cap) {
        size_t nc = *cap ? *cap * 2 : 64;
        vsbk_file_entry_t *nf = realloc(*out, nc * sizeof(**out));
        if (!nf) { closedir(d); return -1; }
        *out = nf; *cap = nc;
      }
      vsbk_file_entry_t *e = &(*out)[(*count)++];
      memset(e, 0, sizeof(*e));
      snprintf(e->path, sizeof(e->path), "%s", child_rel);
      e->size = (uint64_t)st.st_size;
      e->mtime = (double)st.st_mtime;
    }
  }
  closedir(d);
  return 0;
}

int vsbk_backup_path(const char *source_dir, vsbk_storage_t *store,
                     const char *job_id, int respect_quarantine,
                     vsbk_manifest_t *out) {
  memset(out, 0, sizeof(*out));
  snprintf(out->job_id, sizeof(out->job_id), "%s", job_id);
  snprintf(out->source, sizeof(out->source), "%s", source_dir);
  vsbk_file_entry_t *entries = NULL;
  size_t count = 0, cap = 0;
  if (walk_dir(source_dir, "", respect_quarantine, &entries, &count, &cap) != 0) {
    free(entries);
    return -1;
  }
  for (size_t i = 0; i < count; i++) {
    vsbk_file_entry_t *e = &entries[i];
    e->change = VSBK_CHG_NEW;
    char full[VSBK_MAX_PATH];
    vsbk_path_join(full, sizeof(full), source_dir, e->path);
    vsbk_sha256_file(full, e->sha256);
    char key[VSBK_MAX_PATH];
    snprintf(key, sizeof(key), "%s/%s", job_id, e->path);
    FILE *in = fopen(full, "rb");
    if (!in) continue;
    if (vsbk_storage_put_file(store, key, in, NULL) == 0) {
      out->bytes_total += e->size;
      manifest_add(out, e);
      vsbk_log(1, "stored %s (NEW)", key);
    }
    fclose(in);
  }
  free(entries);
  char man_key[VSBK_MAX_PATH];
  snprintf(man_key, sizeof(man_key), "%s/_manifest.txt", job_id);
  char body[4096];
  int n = snprintf(body, sizeof(body),
                   "job_id=%s\nsource=%s\nfiles=%zu\nbytes=%llu\n",
                   out->job_id, out->source, out->file_count,
                   (unsigned long long)out->bytes_total);
  if (n > 0)
    vsbk_storage_put_mem(store, man_key, body, (size_t)n);
  return 0;
}

void vsbk_manifest_free(vsbk_manifest_t *m) {
  free(m->files);
  m->files = NULL;
  m->file_count = m->file_cap = 0;
}
