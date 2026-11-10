/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#include <cstring>
#if !REX_PLATFORM_WIN32
#include <fcntl.h>
#endif

#include <rex/kernel/xam/module.h>
#include <rex/platform.h>
#include <rex/system/kernel_state.h>
#include <rex/system/xsocket.h>
// #include <rex/system/xnet.h>

#include <rex/net/socket.h>

// Standard socket types used by Xbox API emulation
#if REX_PLATFORM_WIN32
#include <WinSock2.h>

#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#endif

namespace rex::system {

XSocket::XSocket(KernelState* kernel_state) : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() {
  Close();
}

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::X_IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::X_IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
  if (native_handle_ == uint64_t(-1)) {
    return X_STATUS_SUCCESS;
  }

  int ret = rex::net::socket_close(native_handle_);
  native_handle_ = -1;
  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr, uint32_t optlen) {
  constexpr uint32_t kXSolSocket = 0xFFFF;
  constexpr uint32_t kXSoReuseAddr = 0x0004;

  if (level == kXSolSocket && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  // Xbox sockets use WinSock's level/option numbering. SOL_SOCKET is 0xFFFF
  // there and 1 on Linux, and the option names differ too, so passing them
  // straight through makes setsockopt fail with ENOPROTOOPT. In particular
  // titles never actually get SO_REUSEADDR, which they rely on to bind
  // several P2P sockets to one local port.
  int native_level = static_cast<int>(level);
  int native_optname = static_cast<int>(optname);
  if (level == kXSolSocket) {
    native_level = SOL_SOCKET;
    switch (optname) {
      case 0x0004:
        native_optname = SO_REUSEADDR;
        break;
      case 0x0020:
        native_optname = SO_BROADCAST;
        break;
      case 0x0080:
        native_optname = SO_LINGER;
        break;
      case 0x1001:
        native_optname = SO_SNDBUF;
        break;
      case 0x1002:
        native_optname = SO_RCVBUF;
        break;
      case 0x1005:
        native_optname = SO_SNDTIMEO;
        break;
      case 0x1006:
        native_optname = SO_RCVTIMEO;
        break;
      default:
        break;
    }
  }

  // Guest option values are big-endian, and titles often pass a 1-byte
  // boolean (e.g. SO_REUSEADDR with optlen 1). Linux only accepts a 4-byte
  // int for these options, so normalize: pad short values to an int and
  // byte-swap full words.
  int native_value = 0;
  const void* native_ptr = optval_ptr;
  uint32_t native_len = optlen;
  bool value_is_true = false;
  if (optval_ptr && optlen == 1) {
    native_value = *static_cast<uint8_t*>(optval_ptr);
    value_is_true = native_value != 0;
    native_ptr = &native_value;
    native_len = sizeof(native_value);
  } else if (optval_ptr && optlen == 4) {
    uint32_t raw;
    std::memcpy(&raw, optval_ptr, 4);
    // Boolean options are sometimes already host order (a byte written into a
    // 4-byte slot); accept 0/1 as-is, otherwise treat as big-endian.
    const bool is_bool_opt = native_optname == SO_REUSEADDR || native_optname == SO_BROADCAST;
    native_value = static_cast<int>(is_bool_opt && raw <= 1 ? raw : __builtin_bswap32(raw));
    value_is_true = native_value != 0;
    native_ptr = &native_value;
    native_len = sizeof(native_value);
  }

  int ret = setsockopt(native_handle_, native_level, native_optname, (char*)native_ptr, native_len);
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

#if REX_PLATFORM_LINUX && defined(SO_REUSEPORT)
  // Windows' SO_REUSEADDR allows several sockets to bind the same local
  // address/port (P2P titles open one per peer). Linux only allows that with
  // SO_REUSEPORT, so mirror the request. It must be set on every socket that
  // asks for SO_REUSEADDR, before bind.
  if (level == kXSolSocket && optname == kXSoReuseAddr && value_is_true) {
    int one = 1;
    setsockopt(native_handle_, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
  }
#endif

  // SO_BROADCAST
  if (level == kXSolSocket && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
  int ret = rex::net::socket_ioctl(native_handle_, cmd, arg_ptr);
  if (ret < 0) {
    // TODO: Get last error
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Connect(N_XSOCKADDR* name, int name_len) {
  int ret = connect(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(N_XSOCKADDR_IN* name, int name_len) {
  int ret = bind(native_handle_, (sockaddr*)name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_ = true;
  bound_port_ = name->sin_port;

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(N_XSOCKADDR* name, int* name_len) {
  sockaddr n_sockaddr;
  socklen_t n_name_len = sizeof(sockaddr);
  uintptr_t ret = accept(native_handle_, &n_sockaddr, &n_name_len);
  if (ret == -1) {
    std::memset(name, 0, *name_len);
    *name_len = 0;
    return nullptr;
  }

  std::memcpy(name, &n_sockaddr, n_name_len);
  *name_len = n_name_len;

#if !REX_PLATFORM_WIN32
  // WinSock: a socket returned by accept() inherits the listener's non-blocking
  // mode. POSIX does not, so the accepted socket would block the game thread in
  // recv() whenever the peer has nothing to send. Mirror the Windows behaviour.
  {
    const int listener_flags = fcntl(static_cast<int>(native_handle_), F_GETFL, 0);
    if (listener_flags >= 0 && (listener_flags & O_NONBLOCK)) {
      const int accepted_flags = fcntl(static_cast<int>(ret), F_GETFL, 0);
      if (accepted_flags >= 0) {
        fcntl(static_cast<int>(ret), F_SETFL, accepted_flags | O_NONBLOCK);
      }
    }
  }
#endif

  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) {
  return shutdown(native_handle_, how);
}

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* from,
                      uint32_t* from_len) {
  // Pop from secure packets first
  // TODO(DrChat): Enable when I commit XNet
  /*
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    if (incoming_packets_.size()) {
      packet* pkt = (packet*)incoming_packets_.front();
      int data_len = pkt->data_len;
      std::memcpy(buf, pkt->data, std::min((uint32_t)pkt->data_len, buf_len));

      from->sin_family = 2;
      from->sin_addr = pkt->src_ip;
      from->sin_port = pkt->src_port;

      incoming_packets_.pop();
      uint8_t* pkt_ui8 = (uint8_t*)pkt;
      delete[] pkt_ui8;

      return data_len;
    }
  }
  */

  sockaddr_in nfrom;
  socklen_t nfromlen = sizeof(sockaddr_in);
  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                     (sockaddr*)&nfrom, &nfromlen);
  if (from) {
    from->sin_family = nfrom.sin_family;
    from->sin_addr = ntohl(nfrom.sin_addr.s_addr);  // BE <- BE
    from->sin_port = nfrom.sin_port;
    std::memset(from->x_sin_zero, 0, sizeof(from->x_sin_zero));
  }

  if (from_len) {
    *from_len = nfromlen;
  }

  return ret;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len, flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags, N_XSOCKADDR_IN* to,
                    uint32_t to_len) {
  // Send 2 copies of the packet: One to XNet (for network security) and an
  // unencrypted copy for other Xenia hosts.
  // TODO(DrChat): Enable when I commit XNet.
  /*
  auto xam = kernel_state()->GetKernelModule<xam::XamModule>("xam.xex");
  auto xnet = xam->xnet();
  if (xnet) {
    xnet->SendPacket(this, to, buf, buf_len);
  }
  */

  sockaddr_in nto;
  if (to) {
    nto.sin_addr.s_addr = to->sin_addr;
    nto.sin_family = to->sin_family;
    nto.sin_port = to->sin_port;
  }

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? (sockaddr*)&nto : nullptr, to_len);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port, const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

}  // namespace rex::system
