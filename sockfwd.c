/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define LOGF_LOG_MIN_PRIO 2

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "sockfwd.h"

static int fd_client_src = 0;
static int fd_client_target = 0;

/*
 * enable or disbale simple socket protocol
 * where each meassage is prefixed with a 32bit
 * msg size value
 */
static bool protocol = true;

static void
(*sockfwd_recv_cb)(char *msg, size_t msg_len) = NULL;

#define BUF_SIZE 4096


/**
 * Event callback to receive messages from client socket and forward to other client socket
 *
 * @fd contains client fd which has pending data
 * @data contains the pointer to target client fd
 */
static void
sockfwd_client_cb_recv(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	int *target = data;

	if (events & EVENT_IO_EXCEPT) {
		event_remove_io(io);
		close(fd);
		close(*target);
		FATAL("IO error on fd %d", fd);
	}

	if (events & EVENT_IO_READ) {
		TRACE("Socket data available on source fd %d", fd);
		char* buf = mem_alloc(BUF_SIZE);

		ssize_t bytes_read = 0;
		ssize_t msg_len = BUF_SIZE;
		int flags = 0;

		if (protocol) {
			flags = MSG_WAITALL;
			if (recv(fd, &msg_len, sizeof(uint32_t), flags) != sizeof(uint32_t)) {
				mem_free(buf);
				FATAL_ERRNO("Failed to receive msg len!");
			}
			msg_len = ntohl(msg_len);
			TRACE("fd=%d, msg_len=%u", fd, msg_len);
		}
			
		// retry till full message is received
		do {
			bytes_read = recv(fd, buf, msg_len, flags);
		} while (bytes_read < 0 && ((errno == EINTR) || (errno == EAGAIN)));

		if (0 == bytes_read) {
			mem_free(buf);
			FATAL("EOF: Remote side closed connection.");
		}
		if (-1 == bytes_read) {
			mem_free(buf);
			FATAL_ERRNO("Failed to receive data!");
		}
		if (protocol && (bytes_read != msg_len)) {
			WARN_ERRNO("Failed to receive complete msg!");
		}

		// call data callback if there is one
		if (sockfwd_recv_cb) {
			sockfwd_recv_cb(buf, bytes_read);
		}

		if (protocol) {
			msg_len = htonl(msg_len);
			if (send(*target, &msg_len, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
				mem_free(buf);
				FATAL_ERRNO("Failed to send msg len!");
			}
		}

		if (-1 == send(*target, buf, bytes_read, 0)) {
			mem_free(buf);
			FATAL_ERRNO("Failed to forward data to target fd %d...", *target);
		}
		mem_free(buf);
	}
}

static void
sockfwd_listen_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	char *path = data;

	if (events & EVENT_IO_EXCEPT) {
		WARN("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept connection on path: %s", path);
		return;
	}
	INFO("Accepted connection %d on path: %s", cfd, path);

	fd_make_non_blocking(cfd);
	fd_client_target = cfd;

	// connection to target client and forward to src 
	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, sockfwd_client_cb_recv, &fd_client_src);
	event_add_io(event);

	// connection to src client and forward to target
	event_io_t *event_src_recv = event_io_new(fd_client_src, EVENT_IO_READ, sockfwd_client_cb_recv, &fd_client_target);
	event_add_io(event_src_recv);

}

int
sockfwd_run(const char* path_client_src, const char* path_listen, void (*data_recv_cb)(char*, size_t))
{
	sockfwd_recv_cb = data_recv_cb;

	// listen for clients we are forwarding to
	mode_t mask = umask(002);
	int fd_listen = sock_unix_create_and_bind(SOCK_STREAM | SOCK_NONBLOCK, path_listen);
	if (fd_listen < 0)
		FATAL("Could not create and bind UNIX domain socket: %s", path_listen);
	umask(mask);

	if (sock_unix_listen(fd_listen) < 0)
                FATAL_ERRNO("Could not listen on new socket: %s", path_listen);
	INFO("Listening for client connections on path=%s fd=%d", path_listen, fd_listen);

	// listen for connection to target client
	event_io_t *event_target_accept = event_io_new(fd_listen, EVENT_IO_READ, sockfwd_listen_cb_accept, (void*) path_listen);
	event_add_io(event_target_accept);

	// connect to server socket as client
	fd_client_src = sock_unix_create_and_connect(SOCK_STREAM, path_client_src);
	if (fd_client_src < 0)
		FATAL_ERRNO("Could not create and connect to UNIX domain socket: %s", path_client_src);
	INFO("Connected as client fd=%d to %s", fd_client_src, path_client_src);

	INFO("Starting event loop ...");
	event_loop();

	return 0;
}

