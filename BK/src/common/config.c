#include "vsbk/common.h"
#include <stdlib.h>

void vsbk_config_from_env(vsbk_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  const char *m = getenv("VSBK_MODE");
  snprintf(cfg->mode, sizeof(cfg->mode), "%s", m && *m ? m : "embedded");
  const char *id = getenv("VSBK_AGENT_ID");
  snprintf(cfg->agent_id, sizeof(cfg->agent_id), "%s", id && *id ? id : "agent-local");
  const char *sp = getenv("VSBK_STORAGE");
  snprintf(cfg->storage_path, sizeof(cfg->storage_path), "%s",
           sp && *sp ? sp : "./data/vsbk_store");
  const char *dd = getenv("VSBK_DATA_DIR");
  snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", dd && *dd ? dd : "./data");
  const char *rq = getenv("VSBK_RESPECT_QUARANTINE");
  cfg->respect_quarantine = (rq && (rq[0]=='0')) ? 0 : 1;
  const char *hook = getenv("VECTORSTRYKE_HOOK_URL");
  if (hook) snprintf(cfg->hook_url, sizeof(cfg->hook_url), "%s", hook);
  const char *ll = getenv("VSBK_LOG_LEVEL");
  cfg->log_level = ll ? atoi(ll) : 1;
}
