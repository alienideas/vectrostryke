#include "vsbk/pipeline.h"
#include "vsbk/sal.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  const char *src = "./data/test_src";
  const char *store_path = "./data/test_store";
  vsbk_mkdir_p(src);
  vsbk_mkdir_p(store_path);
  char fpath[VSBK_MAX_PATH];
  vsbk_path_join(fpath, sizeof(fpath), src, "doc.txt");
  FILE *f = fopen(fpath, "wb");
  assert(f);
  fputs("payload", f);
  fclose(f);
  vsbk_storage_t *s = vsbk_storage_open_local(store_path);
  assert(s);
  vsbk_manifest_t man;
  int rc = vsbk_backup_path(src, s, "job-test-1", 1, &man);
  assert(rc == 0);
  assert(man.file_count >= 1);
  assert(man.bytes_total >= 7);
  assert(vsbk_storage_exists(s, "job-test-1/_manifest.txt"));
  vsbk_manifest_free(&man);
  vsbk_storage_close(s);
  printf("test_pipeline OK\n");
  return 0;
}
