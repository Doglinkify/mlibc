#include <abi-bits/vm-flags.h>
#include <bits/ensure.h>
#include <stdint.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wunused-parameter"

namespace mlibc {

void sys_libc_log(const char *message) {
	ssize_t result = 0;
	sys_write(0, message, strlen(message), &result);
}

void sys_libc_panic() {
	ssize_t bytes_written = 0;
	sys_write(0, "\e[31mmlibc: panic!\e[0m\n", 23, &bytes_written);
	sys_exit(0);
}

[[noreturn]] void sys_exit(int _status) {
	asm volatile (
		"int $0x80"
		:
		: "a" (4)
	);
	__builtin_unreachable();
}

#ifndef MLIBC_BUILDING_RTLD

[[noreturn]] void sys_thread_exit() { sys_exit(0); }

int sys_kill(pid_t pid, int signal)
{
	return 0;
}

int sys_tcgetattr(int fd, struct termios *attr) { return 0; }

int sys_tcsetattr(int fd, int optional_action, const struct termios *attr) { return 0; }

#endif

#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

int sys_tcb_set(void *pointer) {
	asm volatile (
		"int $0x80"
		:
		: "a" (6), "D" (pointer)
	);
	//ssize_t bytes_written;
	//sys_write(0, "alive!\n", 7, &bytes_written);
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

// int sys_ppoll(
//     struct pollfd *fds,
//     int nfds,
//     const struct timespec *timeout,
//     const sigset_t *sigmask,
//     int *num_events
// ) {}

// int sys_poll(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {}

// int sys_pselect(
//     int nfds,
//     fd_set *read_set,
//     fd_set *write_set,
//     fd_set *except_set,
//     const struct timespec *timeout,
//     const sigset_t *sigmask,
//     int *num_events
// ) {}

#endif

int sys_futex_wait(int *pointer, int expected, const struct timespec *time) { return 0; }

int sys_futex_wake(int *pointer) { return 0; }

#ifndef MLIBC_BUILDING_RTLD

int sys_ioctl(int fd, unsigned long request, void *arg, int *result) {
	return 0;
}

int sys_isatty(int fd) { return 0; }

int sys_getcwd(char *buffer, size_t size) {
	buffer[0] = '/';
	buffer[1] = '\0';
	return 0;
}

#endif

// int sys_openat(int dirfd, const char *path, int flags, mode_t mode, int *fd) {}

int sys_open(const char *path, int flags, mode_t mode, int *fd) {
	*fd = 1;
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

int sys_open_dir(const char *path, int *fd) {
	return 0;
}

int sys_read_entries(int fd, void *buffer, size_t max_size, size_t *bytes_read) {
	return 0;
}

#endif

int sys_close(int fd) {
	return 0;
}

int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
	return 0;
}

int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	unsigned long long tmp = 0xff;
	while (tmp == 0xff) {
		asm volatile (
			"int $0x80"
			: "=c" (tmp)
			: "a" (5)
		);
	}
	*(char *)buf = (char)tmp;
	*bytes_read = 1;
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
	asm volatile (
		"int $0x80"
		:
		: "a" (1), "D" (fd), "S" (buf), "c" (count)
	);
	*bytes_written = count;
	return 0;
}

// int sys_readlink(const char *path, void *data, size_t max_size, ssize_t *length) {}

// int sys_link(const char *old_path, const char *new_path) {}

// int sys_linkat(int olddirfd, const char *old_path, int newdirfd, const char *new_path, int flags)
// {}

// int sys_unlinkat(int fd, const char *path, int flags) {}

// int sys_fchmod(int fd, mode_t mode) {}

// int sys_rmdir(const char *path) {}

#endif

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	return 0;
}

int sys_vm_unmap(void *pointer, size_t size) { return 0; }

#ifndef MLIBC_BUILDING_RTLD

// int sys_vm_protect(void *pointer, size_t size, int prot) {}

#endif

uint64_t aether_brk_start = 0;

int sys_anon_allocate(size_t size, void **pointer) {
    if (!aether_brk_start) {
        asm volatile (
            "int $0x80"
            : "=S" (aether_brk_start)
            : "a" (7), "D" (0)
        );
	}

	*pointer = (void *)aether_brk_start;
	uint64_t trash;
	asm volatile (
	    "int $0x80"
		: "=S" (trash)
		: "a" (7), "D" (aether_brk_start + size)
	);
	return 0;
}

int sys_anon_free(void *pointer, size_t size) { return 0; }

#ifndef MLIBC_BUILDING_RTLD

pid_t sys_getpid() { return 114514; }

pid_t sys_getppid() { return 143; }

// uid_t sys_getuid() {}

// uid_t sys_geteuid() {}

// gid_t sys_getgid() {}

// int sys_setgid(gid_t gid) {}

// pid_t sys_getpgid(pid_t pid, pid_t *pgid) {}

// gid_t sys_getegid() {}

// int sys_setpgid(pid_t pid, pid_t pgid) {}

// int sys_ttyname(int fd, char *buf, size_t size) {}

int sys_clock_get(int clock, time_t *secs, long *nanos) { return 0; }

// int sys_stat(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {}

// int sys_faccessat(int dirfd, const char *pathname, int mode, int flags) {}

// int sys_access(const char *path, int mode) {}

// int sys_pipe(int *fds, int flags) {}

int sys_chdir(const char *path) {
	return 0;
}

// int sys_mkdir(const char *path, mode_t mode) {}

// int sys_mkdirat(int dirfd, const char *path, mode_t mode) {}

// int sys_socket(int domain, int type_and_flags, int proto, int *fd) {}

// int sys_socketpair(int domain, int type_and_flags, int proto, int *fds) {}

// int sys_bind(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {}

// int sys_connect(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {}

// int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags)
// {}

// int
// sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict
// size) {
// }

// int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size) {}

// int sys_msg_recv(int sockfd, struct msghdr *hdr, int flags, ssize_t *length) {}

// int sys_peername(
//     int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length, socklen_t *actual_length
// ) {}

// int sys_listen(int fd, int backlog) {}

// int sys_inotify_create(int flags, int *fd) {}

int sys_fork(pid_t *child) {
	asm volatile (
		"int $0x80"
		: "=c" (*child)
		: "a" (2)
	);
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]) {
	int len = strlen(path);
	asm volatile (
		"int $0x80"
		:
		: "a" (3), "D" (path), "c" (len)
	);
	return 0;
}

// int sys_fcntl(int fd, int request, va_list args, int *result) {}

// int sys_dup(int fd, int flags, int *newfd) {}

// int sys_dup2(int fd, int flags, int newfd) {}

// int sys_sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {}

// int sys_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact) {}

// int sys_signalfd_create(sigset_t mask, int flags, int *fd) {}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	return 0;
}

// int sys_getgroups(size_t size, const gid_t *list, int *_ret) {}

// int sys_mount(
//     const char *source,
//     const char *target,
//     const char *fstype,
//     unsigned long flags,
//     const void *data
// ) {}

// int sys_umount2(const char *target, int flags) {}

// int sys_gethostname(char *buffer, size_t bufsize) {}

// int sys_sethostname(const char *buffer, size_t bufsize) {}

// int sys_sleep(time_t *secs, long *nanos) {}

// int sys_getitimer(int, struct itimerval *) {}

// int sys_setitimer(int, const struct itimerval *, struct itimerval *) {}

#endif

} // namespace mlibc
