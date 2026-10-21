/* Minimal health HTTP server — POSIX sockets; Winsock on Windows */
#include "vsbk/common.h"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET vsbk_sock_t;
  #define CLOSESOCK closesocket
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  typedef int vsbk_sock_t;
  #define CLOSESOCK close
  #define INVALID_SOCKET (-1)
#endif

static const char *RESP =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: application/json\r\n"
  "Content-Length: 48\r\n"
  "Connection: close\r\n"
  "\r\n"
  "{\"status\":\"ok\",\"service\":\"control-plane\",\"v\":\"0.3\"}";

int main(int argc, char **argv) {
  int port = 8080;
  if (argc > 1) port = atoi(argv[1]);
  if (port <= 0) port = 8080;

#ifdef _WIN32
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    vsbk_log(0, "WSAStartup failed");
    return 1;
  }
#endif

  vsbk_sock_t srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv == INVALID_SOCKET) {
    vsbk_log(0, "socket failed");
    return 1;
  }
  int yes = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    vsbk_log(0, "bind failed on %d", port);
    CLOSESOCK(srv);
    return 1;
  }
  if (listen(srv, 8) < 0) {
    vsbk_log(0, "listen failed");
    CLOSESOCK(srv);
    return 1;
  }
  vsbk_log(1, "control-plane listening on %d", port);

  for (;;) {
    vsbk_sock_t c = accept(srv, NULL, NULL);
    if (c == INVALID_SOCKET) continue;
    char buf[1024];
    recv(c, buf, sizeof(buf) - 1, 0);
    send(c, RESP, (int)strlen(RESP), 0);
    CLOSESOCK(c);
  }
  return 0;
}
