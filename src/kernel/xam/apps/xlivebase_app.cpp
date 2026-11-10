/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2021 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cstring>

#include <rex/kernel/xam/apps/xlivebase_app.h>
#include <rex/logging.h>
#include <rex/system/xenumerator.h>
#include <rex/thread.h>

namespace rex {
namespace kernel {
namespace xam {
using namespace rex::system;
using namespace rex::system::xam;
namespace apps {
using namespace rex::system;

namespace {

// Live async calls pass an XLIVE_ASYNC_TASK whose marshalled request is a
// compact array of X_ARGUMENT_ENTRY { u32 native_size; u64 value_ptr; } (stride
// 0x10). Dereference entry N to the u32 value it points at.
uint32_t ReadLiveArgument(memory::Memory* memory, uint32_t args_list, uint32_t index) {
  if (!args_list) return 0;
  auto* entry = memory->TranslateVirtual<const uint8_t*>(args_list + index * 0x10);
  if (!entry) return 0;
  uint32_t value_ptr = memory::load_and_swap<uint32_t>(entry + 8);
  if (!value_ptr) return 0;
  auto* value = memory->TranslateVirtual<const uint8_t*>(value_ptr);
  return value ? memory::load_and_swap<uint32_t>(value) : 0;
}

uint32_t ReadLiveMarshalledRequest(memory::Memory* memory, uint32_t task) {
  if (!task) return 0;
  auto* p = memory->TranslateVirtual<const uint8_t*>(task + 0x18);  // marshalled_request_ptr
  return p ? memory::load_and_swap<uint32_t>(p) : 0;
}

}  // namespace

XLiveBaseApp::XLiveBaseApp(KernelState* kernel_state) : App(kernel_state, 0xFC) {}

// http://mb.mirage.org/bugzilla/xliveless/main.c

X_HRESULT XLiveBaseApp::DispatchMessageSync(uint32_t message, uint32_t buffer_ptr,
                                            uint32_t buffer_length) {
  // NOTE: buffer_length may be zero or valid.
  auto buffer = memory_->TranslateVirtual(buffer_ptr);
  switch (message) {
    case 0x00058004: {
      // Called on startup, seems to just return a bool in the buffer.
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XLiveBaseGetLogonId({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, 1);  // ?
      return X_E_SUCCESS;
    }
    case 0x00058006: {
      assert_true(!buffer_length || buffer_length == 4);
      REXKRNL_DEBUG("XLiveBaseGetNatType({:08X})", buffer_ptr);
      memory::store_and_swap<uint32_t>(buffer + 0, 1);  // XONLINE_NAT_OPEN
      return X_E_SUCCESS;
    }
    case 0x00058007: {
      // XOnlineGetServiceInfo(service_id, service_info_ptr). Old sync form:
      // buffer_ptr is the service id, buffer_length is the output pointer
      // (X_ONLINE_SERVICE_INFO, 0xC bytes). Returning an error here made the
      // title treat Xbox Live services as unavailable.
      auto* info = buffer_length ? memory_->TranslateVirtual<uint8_t*>(buffer_length) : nullptr;
      if (info) {
        std::memset(info, 0, 0xC);
        memory::store_and_swap<uint32_t>(info + 0, buffer_ptr);  // id
      }
      REXKRNL_INFO("XOnlineGetServiceInfo(id={}, info=0x{:08X}) -> success", buffer_ptr,
                   buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058020: {
      // XFriendsCreateEnumerator(task, args). Create an XamEnumerate-able,
      // empty friends list so the title's friend/roster code gets a valid
      // handle instead of E_FAIL.
      const uint32_t request = ReadLiveMarshalledRequest(memory_, buffer_ptr);
      const uint32_t user_index = ReadLiveArgument(memory_, request, 0);
      const uint32_t start_index = ReadLiveArgument(memory_, request, 1);
      const uint32_t amount = ReadLiveArgument(memory_, request, 2);
      const uint32_t buffer_size_ptr = ReadLiveArgument(memory_, request, 3);
      const uint32_t handle_ptr = ReadLiveArgument(memory_, request, 4);
      REXKRNL_INFO(
          "XFriendsCreateEnumerator(user={}, start={}, amount={}, size_ptr=0x{:08X}, "
          "handle_ptr=0x{:08X})",
          user_index, start_index, amount, buffer_size_ptr, handle_ptr);
      auto* handle_out =
          handle_ptr ? memory_->TranslateVirtual<uint8_t*>(handle_ptr) : nullptr;
      auto* size_out =
          buffer_size_ptr ? memory_->TranslateVirtual<uint8_t*>(buffer_size_ptr) : nullptr;
      if (!handle_out) {
        return X_E_INVALIDARG;
      }
      memory::store_and_swap<uint32_t>(handle_out, 0);
      if (size_out) {
        memory::store_and_swap<uint32_t>(size_out, 0);
      }
      if (!amount) {
        return X_E_INVALIDARG;
      }
      // X_ONLINE_FRIEND is 0xC4 bytes; the list stays empty (no friends).
      auto e = object_ref<XStaticUntypedEnumerator>(
          new XStaticUntypedEnumerator(kernel_state_, amount, 0xC4));
      auto result = e->Initialize(user_index, app_id(), 0x58021, 0x58022, 0);
      if (XFAILED(result)) {
        return result;
      }
      memory::store_and_swap<uint32_t>(handle_out, e->handle());
      return X_E_SUCCESS;
    }
    case 0x00058023: {
      REXKRNL_DEBUG(
          "CXLiveMessaging::XMessageGameInviteGetAcceptedInfo({:08X}, {:08X}) "
          "unimplemented",
          buffer_ptr, buffer_length);
      return X_E_FAIL;
    }
    case 0x00058046: {
      // Required to be successful for 4D530910 to detect signed-in profile
      // Doesn't seem to set anything in the given buffer, probably only takes
      // input
      REXKRNL_DEBUG("XLiveBaseUnk58046({:08X}, {:08X}) unimplemented", buffer_ptr, buffer_length);
      return X_E_SUCCESS;
    }
    case 0x00058037: {
      REXKRNL_DEBUG("XPresenceInitialize({:08X}, {:08X})", buffer_ptr, buffer_length);
      return X_E_SUCCESS;
    }
  }
  REXKRNL_ERROR(
      "Unimplemented XLIVEBASE message app={:08X}, msg={:08X}, arg1={:08X}, "
      "arg2={:08X}",
      app_id(), message, buffer_ptr, buffer_length);
  return X_E_FAIL;
}

}  // namespace apps
}  // namespace xam
}  // namespace kernel
}  // namespace rex
