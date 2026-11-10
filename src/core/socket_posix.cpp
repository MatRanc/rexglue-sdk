#include <rex/net/socket.h>
#include <rex/platform.h>

static_assert(REX_PLATFORM_LINUX || REX_PLATFORM_MAC, "This file is POSIX-only");

#include <sys/ioctl.h>
#include <unistd.h>

namespace rex::net {

int socket_close(SocketHandle handle) {
  return close(static_cast<int>(handle));
}

int socket_ioctl(SocketHandle handle, uint32_t cmd, uint8_t* arg) {
  // Xbox 360 socket ioctl commands use the WinSock 32-bit values, which do not
  // match Linux's ioctl numbers. Translate the ones titles actually use;
  // passing 0x8004667E straight to ioctl() fails with ENOTTY and games treat
  // that as "no network".
  uint64_t native_cmd;
  switch (cmd) {
    case 0x8004667E:  // X_FIONBIO
      native_cmd = FIONBIO;
      break;
    case 0x4004667F:  // X_FIONREAD
      native_cmd = FIONREAD;
      break;
    case 0x40047307:  // X_SIOCATMARK
      native_cmd = SIOCATMARK;
      break;
    default:
      native_cmd = cmd;
      break;
  }
  return ioctl(static_cast<int>(handle), native_cmd, arg);
}

}  // namespace rex::net
