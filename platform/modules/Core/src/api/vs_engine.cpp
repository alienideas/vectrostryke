#include "vs_engine/vs_engine.h"
#include "vs_engine/engine.hpp"

struct vs_engine {
  vs::Engine* impl;
};

vs_engine_t* vs_engine_create(const char* config_path) {
  auto* e = new vs_engine();
  e->impl = new vs::Engine(config_path ? config_path : "./vs_engine.conf");
  return e;
}

void vs_engine_destroy(vs_engine_t* e) {
  if (!e) return;
  delete e->impl;
  delete e;
}

vs_status_t vs_engine_set_mode(vs_engine_t* e, vs_response_mode_t mode) {
  if (!e || !e->impl) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->set_mode(mode));
}

vs_status_t vs_engine_get_mode(vs_engine_t* e, vs_response_mode_t* out) {
  if (!e || !e->impl || !out) return VS_ERR_INVALID_ARG;
  *out = e->impl->mode();
  return VS_OK;
}

vs_status_t vs_engine_start(vs_engine_t* e) {
  if (!e || !e->impl) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->start());
}

vs_status_t vs_engine_stop(vs_engine_t* e) {
  if (!e || !e->impl) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->stop());
}

vs_status_t vs_engine_get_status(vs_engine_t* e, vs_engine_status_t* out) {
  if (!e || !e->impl || !out) return VS_ERR_INVALID_ARG;
  e->impl->fill_status(out);
  return VS_OK;
}

vs_status_t vs_engine_load_signatures(vs_engine_t* e, const char* path) {
  if (!e || !e->impl || !path) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->load_signatures(path));
}

vs_status_t vs_engine_match_signatures(vs_engine_t* e, const char* path, vs_finding_t* out) {
  if (!e || !e->impl || !path) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->match_signatures(path, out));
}

vs_status_t vs_engine_scan_path(vs_engine_t* e, const char* path, vs_scan_result_t* out) {
  if (!e || !e->impl || !path) return VS_ERR_INVALID_ARG;
  return static_cast<vs_status_t>(e->impl->scan_path(path, out));
}

const char* vs_engine_version(void) { return "0.2.0-e4"; }
