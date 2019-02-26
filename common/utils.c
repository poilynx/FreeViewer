#include <fcntl.h>
#include <assert.h>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
/* SO_REUSEPORT is not impl under windows */
#define SO_REUSEPORT 0
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

/** Returns 0 on success, or 1 if there was an error */
int utils_socket_set_blocking(int fd, int blocking) {
	assert(fd >= 0);
#ifdef _WIN32
	unsigned long mode = blocking ? 0 : 1;
	return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? 0: -1;
#else
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) return -1;
	flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	return (fcntl(fd, F_SETFL, flags) == 0) ? 0: -1;
#endif
}

/* Return 0 if succeed */
/*
int utils_socket_set_reuseaddr(int fd) {
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
		error("setsockopt(SO_REUSEADDR) failed");
		return -1;
	} else return 0;
}
*/
