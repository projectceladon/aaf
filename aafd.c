/*
 * Copyright (c) 2019, Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <cutils/list.h>
#include <cutils/uevent.h>
#include <libkmod/libkmod.h>
#include "libkmod-ext.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif
#define LOG_DEFAULT LOG_ERR
#define LOGBUFSIZE 512
#define UEVENT_MSG_LEN  1024

struct aaf_uevent {
	char *action;
	char *modalias;
	char *driver;
	char *devpath;
};

/* White list of modalias namespaces */
struct aaf_modalias_ns {
	const char *prefix;
	size_t prefix_len;
};

static struct aaf_modalias_ns nswl[] = {
	{ "acpi", 4 },
	{ "platform", 8 },
	{ "pci", 3 },
	{ "usb", 3 },
	{ "hid", 3 },
	{ "i2c", 3 },
	{ "sdio", 4 },
	{ "scsi", 4 },
	{ "dmi", 3 },
	{ "input", 5 },
	{ "serio", 5 },
	{ "wmi", 3 },
	{ "of", 2 },
	{ "idi", 3 },
};

static const char *default_config_paths[] = {
	"/vendor/etc/modprobe.d",
	"/system/etc/modprobe.d",
	"/run/modprobe.d",
	"/lib/modprobe.d",
	NULL
};

static struct kmod_ctx *g_kctx;
/* aaf signal mask */
static sigset_t aaf_mask;
static int log_priority;

static void kmod_log(void *data, int priority, const char *file, int line,
		const char *fn, const char *format, va_list args)
{
	char buf[LOGBUFSIZE];

	if (priority > log_priority)
		return;

	vsnprintf(buf, LOGBUFSIZE, format, args);
	buf[LOGBUFSIZE - 1] = 0;

	if (priority == LOG_DEFAULT)
		fprintf(stderr, "%s", buf);
	else
		printf("%s: %s", fn, buf);
}

static struct kmod_ctx *kmod_init(void)
{
	struct kmod_ctx *ctx;
	struct utsname u;
	char *p;

	if (uname(&u) < 0)
		return NULL;

	if (asprintf(&p, "%s/%s", "vendor/lib/modules", u.release) < 0)
		return NULL;

	ctx = kmod_new(p, default_config_paths);
	if (p)
		free(p);
	if (!ctx)
		return NULL;

	kmod_set_log_fn(ctx, kmod_log, NULL);
	kmod_set_log_priority(ctx, log_priority);

	return ctx;
}

static void trigger_device_uevent(DIR *dir)
{
	struct dirent *de;
	int dfd, fd, rc;

	dfd = dirfd(dir);

	fd = openat(dfd, "uevent", O_WRONLY);
	if (fd > 0) {
		rc = write(fd, "add\n", 4);
		if (rc < 0)
			printf("Failed to write uevent\n");
		close(fd);
	}

	while ((de = readdir(dir))) {
		DIR *dir2;

		if (de->d_type != DT_DIR || de->d_name[0] == '.')
			continue;

		fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
		if (fd < 0)
			continue;

		dir2 = fdopendir(fd);
		if (dir2) {
			trigger_device_uevent(dir2);
			closedir(dir2);
		} else {
			close(fd);
		}
	}
}

static int uevent_filter_out(struct aaf_uevent *uevent)
{
	uint i;

	if (!uevent->action)
		return 1;

	if (!uevent->modalias)
		return 1;

	for (i = 0; i < ARRAY_SIZE(nswl); i++) {
		if (!strncmp(uevent->modalias,
					nswl[i].prefix, nswl[i].prefix_len))
			return 0;
	}

	return 1;
}

static int uevent_fd_init(void)
{
	int fd;

	fd = uevent_open_socket(8 * 1024 * 1024, true);
	if (fd < 0)
		return fd;

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
}

static void free_aaf_uevent(struct aaf_uevent *uevent)
{
	if (uevent->action)
		free(uevent->action);

	if (uevent->modalias)
		free(uevent->modalias);

	if (uevent->driver)
		free(uevent->driver);

	if (uevent->devpath)
		free(uevent->devpath);

	free(uevent);
}

static int process_aaf_uevent(struct aaf_uevent *uevent)
{
	int ret;

	if (!strcmp(uevent->action, "add")) {
		ret = kmod_ext_probe(g_kctx, uevent->modalias, 0, NULL);
		printf("ADD: modalias->%s driver->%s devpath->%s ret: %d\n", \
				uevent->modalias, uevent->driver, uevent->devpath, ret);
	} else if (!strcmp(uevent->action, "remove")) {
		ret = kmod_ext_remove(g_kctx, uevent->modalias);
		printf("REMOVE: modalias->%s driver->%s devpath->%s ret: %d\n", \
				uevent->modalias, uevent->driver, uevent->devpath, ret);
	} else {
		printf("unmanaged uevent action %s\n", uevent->action);
		ret = -EINVAL;
	}

	free_aaf_uevent(uevent);

	return ret;
}

static void parse_uevent(const char *msg, struct aaf_uevent *uevent)
{
	while (*msg) {
		if (!uevent->action && !strncmp(msg, "ACTION=", 7)) {
			msg += 7;
			uevent->action = strdup(msg);
		} else if (!uevent->driver && !strncmp(msg, "DRIVER=", 7)) {
			msg += 7;
			uevent->driver = strdup(msg);
		} else if (!uevent->devpath && !strncmp(msg, "DEVPATH=", 8)) {
			msg += 8;
			uevent->devpath = strdup(msg);
		} else if (!uevent->modalias && !strncmp(msg, "MODALIAS=", 9)) {
			msg += 9;
			uevent->modalias = strdup(msg);
		}

		/* advance to after the next \0 */
		while (*msg++)
			;
	}
}

static void process_uevent(int uevent_fd)
{
	struct aaf_uevent *uevent;
	char msg[UEVENT_MSG_LEN+2];
	ssize_t msg_len;

	while ((msg_len = uevent_kernel_multicast_recv(uevent_fd, msg,
					UEVENT_MSG_LEN)) > 0) {
		if (msg_len >= UEVENT_MSG_LEN)
			continue;

		msg[msg_len] = '\0';
		msg[msg_len + 1] = '\0';

		uevent = calloc(1, sizeof(struct aaf_uevent));
		if (!uevent)
			continue;

		parse_uevent(msg, uevent);

		if (uevent_filter_out(uevent)) {
			free_aaf_uevent(uevent);
			continue;
		}
		process_aaf_uevent(uevent);
	}

	return;
}

static int setup_signalfd(void)
{
	sigset_t mask;
	int fd;

	sigemptyset(&mask);

	/* Wait for children termination */
	sigaddset(&mask, SIGCHLD);

	/* Termination signals */
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, &aaf_mask) < 0) {
		printf("Failed to set signal mask\n");
		return -errno;
	}

	fd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (fd < 0) {
		printf("Failed to create signal descriptor\n");
		return -errno;
	}

	return fd;
}

static int process_signal(int signal_fd)
{
	struct signalfd_siginfo si;
	int status, pid;
	ssize_t ret;

	ret = read(signal_fd, &si, sizeof(si));
	if (ret != sizeof(si))
		return 0;

	switch (si.ssi_signo) {
		case SIGCHLD:
			/*
			 * As we may receive only one SIGCHLD signal with potentially
			 * more than one child terminated we must loop and wait for all
			 * of them.
			 */
			for (;;) {
				/* Wait for any child to terminate */
				pid = waitpid(-1, &status, WNOHANG);
				if (pid <= 0)
					break;

				printf("%d terminated, Exited: %d, Status: %d\n", pid,
						WIFEXITED(status), WEXITSTATUS(status));
			}
			break;

		case SIGINT:
		case SIGTERM:
			/* hald will terminate */
			break;

		default:
			printf("Unhandled signal %d\n", si.ssi_signo);
			break;
	}

	return si.ssi_signo;
}

int main(int argc, char **argv)
{
	struct epoll_event ev, events[32];
	DIR *sysfs_dir;
	int  nfds, i, epoll_fd;
	int uevent_fd, signal_fd;
	pid_t uevent_pid;

	g_kctx = kmod_init();
	if (!g_kctx)
		return -ENOMEM;

	uevent_fd = uevent_fd_init();
	if (uevent_fd < 0) {
		printf("Could not create uevent listener\n");
		goto error_kmod_init;
	}

	uevent_pid = fork();

	/* Trigger device uevents in the child */
	if (!uevent_pid) {
		sysfs_dir = opendir("/sys/devices");
		if (!sysfs_dir) {
			printf("Could not open sysfs devices directory %s\n",
					strerror(errno));
			exit(-errno);
		}

		trigger_device_uevent(sysfs_dir);
		closedir(sysfs_dir);

		exit(0);
	}

	signal_fd = setup_signalfd();
	if (signal_fd < 0) {
		printf("Could not create signal fd\n");
		goto error_uevent_fd;
	}

	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		printf("epoll create error %s\n", strerror(errno));
		goto error_signal_fd;
	}

	/* Add the uevent fd to the epoll instance */
	ev.events = EPOLLIN;
	ev.data.fd = uevent_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, uevent_fd, &ev) < 0) {
		printf("Could not add uevent fd %s\n", strerror(errno));
		goto error_epoll_fd;
	}

	/* Add the signal fd to the epoll instance */
	ev.events = EPOLLIN;
	ev.data.fd = signal_fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &ev) < 0) {
		printf("Could not add signal fd %s\n", strerror(errno));
		goto error_epoll_fd;
	}

	while (1) {

		nfds = epoll_wait(epoll_fd, events, 32, -1);

		/* Timeout */
		if (!nfds)
			continue;

		if (nfds < 0) {
			printf("epoll error %s\n", strerror(errno));
			continue;
		}

		for (i = 0; i < nfds; i++) {

			if (events[i].data.fd == uevent_fd) {
				process_uevent(uevent_fd);
				continue;
			}

			if (events[i].data.fd == signal_fd) {
				uint32_t signo;
				signo = process_signal(signal_fd);
				if (signo == SIGTERM || signo == SIGINT)
					goto error_epoll_fd;
				continue;
			}
		}
	}


error_epoll_fd:
	close(epoll_fd);

error_signal_fd:
	close(signal_fd);

error_uevent_fd:
	close(uevent_fd);

error_kmod_init:
	kmod_unref(g_kctx);

	return -errno;
}
