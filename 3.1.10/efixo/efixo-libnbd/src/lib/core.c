/*
 * core.c
 *
 * Copyright 2007 Miguel GAIO <miguel.gaio@efixo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * $Id: core.c 20868 2011-06-06 13:49:09Z mgo $
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>

#include <search.h>
#include <pthread.h>
#include <linux/unistd.h>

#include "core.h"

#define ACK 0x06

struct nbd_link {
	pthread_mutex_t mutex;
	int fd;
};

static struct nbd_link nbd_link = { PTHREAD_MUTEX_INITIALIZER, -1 };

static void __attribute__ ((constructor)) nbd_mutex_init(void)
{
#ifdef NB5
	static int registered;
#endif /* NB5 */

	int ret = pthread_mutex_init(&nbd_link.mutex, NULL);
	if (ret) {
		syslog(LOG_PERROR, "pthread_mutex_init: %m");
		exit(EXIT_FAILURE);
	}
#ifdef NB5
	if (!registered) {
		registered = 1;
		ret = pthread_atfork(NULL, NULL, nbd_mutex_init);
		if (ret) {
			syslog(LOG_PERROR, "pthread_atfork: %m");
			exit(EXIT_FAILURE);
		}
	}
#endif /* NB5 */
}

static ssize_t safe_write(int fd, const void *buf, size_t count)
{
	ssize_t n;

	do {
		n = write(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

static ssize_t safe_read(int fd, void *buf, size_t count)
{
	ssize_t n;

	do {
		n = read(fd, buf, count);
	} while (n < 0 && errno == EINTR);

	return n;
}

static ssize_t full_read(int fd, void *buf, size_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;
	while (len > 0) {
		cc = safe_read(fd, buf, len);
		if (cc < 0)
			return cc;	/* read() returns -1 on failure. */
		if (cc == 0)
			break;
		buf = ((char *)buf) + cc;
		total += cc;
		len -= cc;
	}

	return total;
}

static int safe_connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen)
{
	int r;

	do {
		r = connect(sockfd, addr, addrlen);
	} while (r < 0 && errno == EINTR);

	return r;
}

static void __nbd_close(void)
{
	if (nbd_link.fd > 0) {
		close(nbd_link.fd);
		nbd_link.fd = -1;
	}
}

static int __nbd_open(void)
{
	struct sockaddr_un srv_addr;
	char const *file;
	uint8_t answer = '\0';
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		syslog(LOG_PERROR, "socket() %m\n");
		return -1;
	}

	file = getenv("NBD_SOCKET");
	if (!file)
		file = "/var/run/nbd.socket";

	/* close on exec */
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	memset(&srv_addr, 0x00, sizeof(srv_addr));
	srv_addr.sun_family = PF_UNIX;
	snprintf(srv_addr.sun_path, sizeof(srv_addr.sun_path), "%s", file);

	if (safe_connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) <
	    0) {
		syslog(LOG_PERROR, "%s(%s) %m\n", "connect", file);
		close(fd);
		return -1;
	}

	if (safe_read(fd, &answer, sizeof(answer)) <= 0) {
		syslog(LOG_PERROR, "%s() %m\n", "read");
		close(fd);
		return -1;
	}

	if (answer != ACK) {
		syslog(LOG_PERROR, "%s() %s\n", __func__, "receive NAK");
		close(fd);
		return -1;
	}

	return fd;
}

int nbd_open(void)
{
	if (nbd_link.fd > 0)
		return nbd_link.fd;

	pthread_mutex_lock(&nbd_link.mutex);
	nbd_link.fd = __nbd_open();
	pthread_mutex_unlock(&nbd_link.mutex);

	return nbd_link.fd;
}

void nbd_close(void)
{
	pthread_mutex_lock(&nbd_link.mutex);
	__nbd_close();
	pthread_mutex_unlock(&nbd_link.mutex);
}

static ssize_t nbd_query_receive(int sfd, void *buf, size_t len, int *ret)
{
	char query_buffer[512];
	size_t count;

	if (full_read(sfd, ret, sizeof(*ret)) < 0) {
		syslog(LOG_PERROR, "%s: read answer error code %m", "libnbd");
		*ret = -1;
		return -1;
	}

	if (full_read(sfd, &count, sizeof(count)) < 0) {
		syslog(LOG_PERROR, "%s: read answer length %m", "libnbd");
		*ret = -1;
		return -1;
	}

	if (count > len) {
		/* limit max count to prevent bogus count read */
		if (count < sizeof(query_buffer)) {
			char *drop = query_buffer;

			full_read(sfd, drop, count);
		}
#ifdef DEBUG
		syslog(LOG_PERROR, "** ERROR **"
		       "%s: answer length (%zu) > buffer length (%zu)",
		       "libnbd", count, len);
#endif /* DEBUG */
		*ret = -1;
		return -1;
	}

	if (count == 0) {
		if (buf)
			(*(char *)buf) = '\0';
		return count;
	}

	memset(buf, 0x00, len);
	if (full_read(sfd, buf, count) < 0) {
		syslog(LOG_PERROR, "%s: read answer data %m", "libnbd");
		return -1;
	}

	return count;
}

static int nbd_query_receive_new(int sfd, char **buf, size_t * size, int *ret)
{
	if (!(buf && size)) {
		syslog(LOG_PERROR, "%s: invalid parameter %m", "libnbd");
		return -1;
	}

	if (safe_read(sfd, ret, sizeof(*ret)) < 0) {
		syslog(LOG_PERROR, "%s: read answer error code %m", "libnbd");
		return -1;
	}

	if (safe_read(sfd, size, sizeof(*size)) < 0) {
		syslog(LOG_PERROR, "%s: read answer length %m", "libnbd");
		return -1;
	}

	*buf = malloc(*size);
	if (!(*buf)) {
		syslog(LOG_PERROR, "%s: malloc failed %m", "libnbd");
		return -1;
	}

	if (full_read(sfd, *buf, *size) < 0) {
		syslog(LOG_PERROR, "%s: read answer data %m", "libnbd");
		return -1;
	}

	return 0;
}

static int nbd_query_send(int sfd, char const *plugin, va_list ap)
{
	struct query {
		int argc;
		char const *argv[12];
		char buffer[0];
	} *query;

	char buf[512];
	char *end;
	size_t len = sizeof(buf) - sizeof(*query) - 1;

	/* Build Query Command */
	query = (struct query *)buf;
	memset(query, 0x00, sizeof(*query));
	end = query->buffer;
	*end = '\0';
	for (char const *argv = plugin; argv; argv = va_arg(ap, char const *)) {
		off_t offset = snprintf(end, len, "%s", argv) + 1;

		query->argv[query->argc] = (char const *)(end - query->buffer);
		++query->argc;

		end += offset;
		len -= offset;
	}
	++end;
	*end = '\0';
	len = end - buf;

	if (safe_write(sfd, &len, sizeof(size_t)) < 0) {
		if (errno == EPIPE) {
			syslog(LOG_PERROR, "%s: disconnected, try reopen...",
			       "libnbd");
			__nbd_close();
			/* timeout 60 secs... */
			for (int i = 0; i < 60; i++) {
				sfd = nbd_link.fd = __nbd_open();
				if (sfd > 0)
					break;
				sleep(1);
			}

			if (sfd < 0) {
				syslog(LOG_PERROR, "%s: open failed %m",
				       "libnbd");
				return -1;
			}
			if (safe_write(sfd, &len, sizeof(size_t)) < 0) {
				syslog(LOG_PERROR, "%s: %s(%d, %p, %zu) %m",
				       "libnbd", "safe_write", sfd, &len,
				       sizeof(size_t));
				return -1;
			}
		} else {
			syslog(LOG_PERROR, "%s: %s(%d, %p, %zu) %m",
			       "libnbd", "safe_write", sfd, &len,
			       sizeof(size_t));
			return -1;
		}
	}

	return safe_write(sfd, buf, len);
}

int nbd_query(void *out, size_t outlen, char const *plugin, ...)
{
	int ret;
	va_list ap;

	/* Send Query */
	va_start(ap, plugin);

	pthread_mutex_lock(&nbd_link.mutex);

	ret = nbd_query_send(nbd_link.fd, plugin, ap);
	if (ret < 0) {
		syslog(LOG_PERROR, "%s(%d, %s, ...) %m", "nbd_query_send",
		       nbd_link.fd, plugin);
		__nbd_close();
		goto clean_exit;
	}

	/* Receive Query Answer */
	nbd_query_receive(nbd_link.fd, out, outlen, &ret);

clean_exit:
	pthread_mutex_unlock(&nbd_link.mutex);
	va_end(ap);

	return ret;
}

int nbd_query_new(char **out, size_t * outlen, char const *plugin, ...)
{
	int ret;
	va_list ap;
	size_t size;

	if (!out) {
		syslog(LOG_PERROR, "nbd: invalid parameter");
		return -1;
	}

	if (!outlen)
		outlen = &size;

	/* Send Query */
	va_start(ap, plugin);

	pthread_mutex_lock(&nbd_link.mutex);

	ret = nbd_query_send(nbd_link.fd, plugin, ap);
	if (ret < 0) {
		__nbd_close();
		syslog(LOG_PERROR, "%s(%d, %s, ...) %m", "nbd_query_send",
		       nbd_link.fd, plugin);
		goto clean_exit;
	}

	/* Receive Query Answer */
	if (nbd_query_receive_new(nbd_link.fd, out, outlen, &ret) < 0) {
		syslog(LOG_PERROR, "%s(%d; %p, %zu, %d) %m",
		       "nbd_query_receive_new", nbd_link.fd, out, *outlen, ret);
	}

clean_exit:
	pthread_mutex_unlock(&nbd_link.mutex);
	va_end(ap);

	return ret;
}
