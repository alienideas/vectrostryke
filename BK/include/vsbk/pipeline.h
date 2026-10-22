#ifndef VSBK_PIPELINE_H
#define VSBK_PIPELINE_H

#include "vsbk/common.h"
#include "vsbk/sal.h"

typedef struct {
  char job_id[VSBK_JOB_ID_LEN];
  size_t file_count;
  uint64_t bytes_total;
  char **paths;
  size_t paths_cap;
} vsbk_manifest_t;

int vsbk_backup_path(const char *source,
                     vsbk_storage_t *store,
                     const char *job_id,
                     int respect_quarantine,
                     vsbk_manifest_t *out_manifest);

void vsbk_manifest_free(vsbk_manifest_t *m);
int vsbk_sha256_file(const char *path, char *hex_out);

#endif /* VSBK_PIPELINE_H */
