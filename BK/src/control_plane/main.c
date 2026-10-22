/* Minimal health HTTP server */
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
  typedef int vsbk_sock_t;
  #define CLOSESOCK close
  #define INVALID_SOCKET (-1)
#endif

static const char *RESP =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: application/json\r\n"
  "Content-Length: 27\r\n"
  "Connection: close\r\n\r\n"
  "{\"status\":\"ok\",\"svc\":\"bk\"}";

int main(int argc, char **argv) {
  int port = 8080;
  if (argc > 1) port = atoi(argv[1]);
#ifdef _WIN32
  WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
  vsbk_sock_t s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) return 1;
  int yes = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) return 2;
  listen(s, 8);
  vsbk_log(1, "vsbk-control-plane listening on %d", port);
  for (;;) {
    vsbk_sock_t c = accept(s, NULL, NULL);
    if (c == INVALID_SOCKET) continue;
    char buf[1024];
    recv(c, buf, sizeof(buf), 0);
    send(c, RESP, (int)strlen(RESP), 0);
    CLOSESOCK(c);
  }
}
