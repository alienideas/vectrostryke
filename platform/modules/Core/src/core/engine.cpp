#include "vs_engine/engine.hpp"
#include "vs_engine/detect.hpp"
#include "vs_engine/scan.hpp"
#include <cstring>

namespace vs {

Engine::Engine(std::string config_path) {
  cfg_ = Config::defaults(std::move(config_path));
  cfg_.load(cfg_.config_path);
  running_ = cfg_.running_flag;
  sigs_.load_file(cfg_.signature_db);
}

int Engine::load_config() {
  std::lock_guard<std::mutex> lock(mu_);
  if (!cfg_.load(cfg_.config_path)) return VS_ERR_IO;
  running_ = cfg_.running_flag;
  return VS_OK;
}

int Engine::save_config() {
  std::lock_guard<std::mutex> lock(mu_);
  return cfg_.save(cfg_.config_path) ? VS_OK : VS_ERR_IO;
}

int Engine::set_mode(vs_response_mode_t mode) {
  if (mode != VS_MODE_AUTOMATIC && mode != VS_MODE_MANUAL) return VS_ERR_INVALID_ARG;
  std::lock_guard<std::mutex> lock(mu_);
  cfg_.mode = mode;
  return cfg_.save(cfg_.config_path) ? VS_OK : VS_ERR_IO;
}

vs_response_mode_t Engine::mode() const {
  std::lock_guard<std::mutex> lock(mu_);
  return cfg_.mode;
}

int Engine::start() {
  std::lock_guard<std::mutex> lock(mu_);
  running_ = true; cfg_.running_flag = true; cfg_.save(cfg_.config_path);
  return VS_OK;
}

int Engine::stop() {
  std::lock_guard<std::mutex> lock(mu_);
  running_ = false; cfg_.running_flag = false; cfg_.save(cfg_.config_path);
  return VS_OK;
}

bool Engine::running() const {
  std::lock_guard<std::mutex> lock(mu_);
  return running_;
}

void Engine::fill_status(vs_engine_status_t* out) const {
  std::lock_guard<std::mutex> lock(mu_);
  if (!out) return;
  std::memset(out, 0, sizeof(*out));
  out->mode = cfg_.mode;
  out->running = running_ ? 1 : 0;
  out->last_scan_files = last_scan_files_;
}

int Engine::load_signatures(const std::string& path) {
  std::lock_guard<std::mutex> lock(mu_);
  return sigs_.load_file(path) ? VS_OK : VS_ERR_IO;
}

int Engine::match_signatures(const std::string& path, vs_finding_t* out) {
  std::lock_guard<std::mutex> lock(mu_);
  return sigs_.match_file(path, out) ? VS_OK : VS_ERR_NOT_FOUND;
}

int Engine::scan_path(const std::string& root, vs_scan_result_t* out) {
  Config cfg_copy;
  {
    std::lock_guard<std::mutex> lock(mu_);
    cfg_copy = cfg_;
  }
  auto st = vs::scan_path(cfg_copy, root, nullptr);
  last_scan_files_ = st.files_scanned;
  if (out) {
    out->files_scanned = st.files_scanned;
    out->findings_count = st.findings_count;
    out->quarantined = st.quarantined;
  }
  return VS_OK;
}

}  // namespace vs
