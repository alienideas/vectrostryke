#pragma once
#ifdef __cplusplus
extern "C" {
#endif

typedef enum { VS_OK=0, VS_ERR_IO=1, VS_ERR_INVALID_ARG=2, VS_ERR_NOT_FOUND=3 } vs_status_t;
typedef enum { VS_MODE_AUTOMATIC=0, VS_MODE_MANUAL=1 } vs_response_mode_t;
typedef enum { VS_TIER_CLEAN=0, VS_TIER_SUSPICIOUS=1, VS_TIER_MALICIOUS=2 } vs_threat_tier_t;
typedef enum { VS_KIND_HEURISTIC=1, VS_KIND_SIGNATURE=2 } vs_finding_kind_t;

typedef struct {
  vs_finding_kind_t kind;
  vs_threat_tier_t tier;
  int score;
  char path[512];
  char rule_id[64];
  char message[256];
} vs_finding_t;

typedef struct {
  vs_response_mode_t mode;
  int running;
  size_t last_scan_files;
} vs_engine_status_t;

typedef struct {
  size_t files_scanned;
  size_t findings_count;
  size_t quarantined;
} vs_scan_result_t;

typedef struct vs_engine vs_engine_t;

vs_engine_t* vs_engine_create(const char* config_path);
void vs_engine_destroy(vs_engine_t* e);
vs_status_t vs_engine_set_mode(vs_engine_t* e, vs_response_mode_t mode);
vs_status_t vs_engine_get_mode(vs_engine_t* e, vs_response_mode_t* out);
vs_status_t vs_engine_start(vs_engine_t* e);
vs_status_t vs_engine_stop(vs_engine_t* e);
vs_status_t vs_engine_get_status(vs_engine_t* e, vs_engine_status_t* out);
vs_status_t vs_engine_load_signatures(vs_engine_t* e, const char* path);
vs_status_t vs_engine_match_signatures(vs_engine_t* e, const char* path, vs_finding_t* out);
vs_status_t vs_engine_scan_path(vs_engine_t* e, const char* path, vs_scan_result_t* out);
const char* vs_engine_version(void);

#ifdef __cplusplus
}
#endif
