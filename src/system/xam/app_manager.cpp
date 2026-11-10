/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cstdlib>

#include <rex/logging.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xam/app_manager.h>

namespace rex {
namespace system {
namespace xam {

namespace {
// TB2_XMSG_LOG=1 logs every XAM app call (app id + message id + result) so a
// title's kernel API usage can be mapped without a debugger.
bool XMsgLogEnabled() {
  static int enabled = -1;
  if (enabled < 0) enabled = std::getenv("TB2_XMSG_LOG") ? 1 : 0;
  return enabled == 1;
}
}  // namespace

App::App(KernelState* kernel_state, uint32_t app_id)
    : kernel_state_(kernel_state), memory_(kernel_state->memory()), app_id_(app_id) {}

void AppManager::RegisterApp(std::unique_ptr<App> app) {
  assert_zero(app_lookup_.count(app->app_id()));
  app_lookup_.insert({app->app_id(), app.get()});
  apps_.push_back(std::move(app));
}

X_HRESULT AppManager::DispatchMessageSync(uint32_t app_id, uint32_t message, uint32_t buffer_ptr,
                                          uint32_t buffer_length) {
  App* app;
  {
    auto it = app_lookup_.find(app_id);
    if (it == app_lookup_.end()) {
      return X_E_NOTFOUND;
    }
    app = it->second;
  }
  X_HRESULT result = app->DispatchMessageSync(message, buffer_ptr, buffer_length);
  if (XMsgLogEnabled()) {
    REXKRNL_INFO("[xmsg] sync app={:02X} msg={:08X} buf={:08X} len={} -> {:08X}", app_id, message,
                 buffer_ptr, buffer_length, static_cast<uint32_t>(result));
  }
  return result;
}

X_HRESULT AppManager::DispatchMessageAsync(uint32_t app_id, uint32_t message, uint32_t buffer_ptr,
                                           uint32_t buffer_length) {
  App* app;
  {
    auto it = app_lookup_.find(app_id);
    if (it == app_lookup_.end()) {
      return X_E_NOTFOUND;
    }
    app = it->second;
  }
  X_HRESULT result = app->DispatchMessageSync(message, buffer_ptr, buffer_length);
  if (XMsgLogEnabled()) {
    REXKRNL_INFO("[xmsg] async app={:02X} msg={:08X} buf={:08X} len={} -> {:08X}", app_id, message,
                 buffer_ptr, buffer_length, static_cast<uint32_t>(result));
  }
  return result;
}

}  // namespace xam
}  // namespace system
}  // namespace rex
