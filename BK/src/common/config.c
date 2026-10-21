#include "vsbk/common.h"

static void copy_env(char *dst, size_t n, const char *key, const char *defv) {
  const char *v = getenv(key);
  if (!v || !*v) v = defv;
  snprintf(dst, n, "%s", v);
}

void vsbk_config_from_env(vsbk_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  copy_env(cfg->mode, sizeof(cfg->mode), "VSBK_MODE", "embedded");
  copy_env(cfg->agent_id, sizeof(cfg->agent_id), "VSBK_AGENT_ID", "dev-agent-001");
  copy_env(cfg->storage_path, sizeof(cfg->storage_path), "VSBK_STORAGE_PATH", "./data/backups");
  copy_env(cfg->data_dir, sizeof(cfg->data_dir), "VSBK_DATA_DIR", "./data");
  copy_env(cfg->hook_url, sizeof(cfg->hook_url), "VECTORSTRYKE_HOOK_URL", "");
  const char *rq = getenv("VSBK_RESPECT_QUARANTINE");
  cfg->respect_quarantine = (!rq || *rq == '\0' || *rq == '1' || *rq == 't' || *rq == 'T') ? 1 : 0;
  cfg->log_level = 1;
}
