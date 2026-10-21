#include "vsbk/common.h"
#include "vsbk/pipeline.h"
#include "vsbk/sal.h"
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
  #include <process.h>
  #define getpid _getpid
#else
  #include <unistd.h>
#endif

static void make_job_id(char *out, size_t n) {
  snprintf(out, n, "job-%ld-%d", (long)time(NULL), (int)getpid());
}

int main(int argc, char **argv) {
  const char *source = (argc > 1) ? argv[1] : ".";
  vsbk_config_t cfg;
  vsbk_config_from_env(&cfg);

  vsbk_log(1, "vsbk-agent starting source=%s storage=%s quarantine=%d",
           source, cfg.storage_path, cfg.respect_quarantine);

  if (vsbk_mkdir_p(cfg.storage_path) != 0) {
    vsbk_log(0, "cannot create storage path");
    return 1;
  }

  vsbk_storage_t *store = vsbk_storage_open_local(cfg.storage_path);
  if (!store) {
    vsbk_log(0, "storage open failed");
    return 1;
  }

  char job_id[VSBK_JOB_ID_LEN];
  make_job_id(job_id, sizeof(job_id));

  vsbk_manifest_t man;
  int rc = vsbk_backup_path(source, store, job_id, cfg.respect_quarantine, &man);
  if (rc != 0) {
    vsbk_log(0, "backup failed");
    vsbk_storage_close(store);
    return 2;
  }

  vsbk_log(1, "backup done job_id=%s files=%zu bytes=%llu",
           man.job_id, man.file_count, (unsigned long long)man.bytes_total);

  if (cfg.hook_url[0])
    vsbk_log(1, "VECTORSTRYKE_HOOK_URL set — POST not implemented in Sprint-0 C core");

  vsbk_manifest_free(&man);
  vsbk_storage_close(store);
  return 0;
}
