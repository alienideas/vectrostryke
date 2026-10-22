#ifndef VSBK_PIPELINE_H
#define VSBK_PIPELINE_H

#include "vsbk/common.h"
#include "vsbk/sal.h"

#define VSBK_MAX_FILES 100000

typedef enum {
  VSBK_CHG_NEW = 1,
  VSBK_CHG_MODIFIED = 2,
  VSBK_CHG_DELETED = 3,
  VSBK_CHG_UNCHANGED = 4
} vsbk_change_t;

typedef struct {
  char path[VSBK_MAX_PATH];
  uint64_t size;
  double mtime;
  char sha256[VSBK_SHA256_HEX];
  vsbk_change_t change;
} vsbk_file_entry_t;

typedef struct {
  char job_id[VSBK_JOB_ID_LEN];
  char source[VSBK_MAX_PATH];
  vsbk_file_entry_t *files;
  size_t file_count;
  size_t file_cap;
  uint64_t bytes_total;
} vsbk_manifest_t;

int vsbk_backup_path(const char *source_dir,
                     vsbk_storage_t *store,
                     const char *job_id,
                     int respect_quarantine,
                     vsbk_manifest_t *out_manifest);

void vsbk_manifest_free(vsbk_manifest_t *m);
int vsbk_sha256_file(const char *path, char *hex_out);

#endif /* VSBK_PIPELINE_H */
