#include "flexsc_syscalls.h"
#define STACK_SIZE (1024 * 1024)
#define SIGCHLD     17

struct flexsc_sysentry *flexsc_getppid()
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	entry->sysnum = __NR_getppid;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	return entry;
}

struct flexsc_sysentry *flexsc_lseek(int fd, off_t offset, int whence) 
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_lseek(entry, fd, offset, whence);
	return entry;
}

struct flexsc_sysentry *flexsc_ioctl(int fd, unsigned int cmd, unsigned long arg)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_ioctl(entry, fd, cmd, arg);
	return entry;
}

struct flexsc_sysentry *flexsc_fadvise(int fd, off_t offset, off_t len, int advise)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_fadvise(entry, fd, offset, len, advise);
	return entry;
}

struct flexsc_sysentry *flexsc_fsync(int fd)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_fsync(entry, fd);
	return entry;
}

struct flexsc_sysentry *flexsc_fdatasync(int fd)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_fdatasync(entry, fd);
	return entry;
}

struct flexsc_sysentry *flexsc_getpid()
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_getpid(entry);
	return entry;
}

struct flexsc_sysentry *flexsc_read(unsigned int fd, char *buf, size_t count)
{
	struct flexsc_sysentry *entry;
	struct flexsc_strentry *str_entry;
	entry = free_syscall_entry();
	str_entry = free_str_entry(entry);
	request_syscall_read(entry, str_entry, fd, buf, count);
	return entry;
}

struct flexsc_sysentry *flexsc_write(unsigned int fd, char *buf, size_t count)
{
	struct flexsc_sysentry *entry;
	struct flexsc_strentry *str_entry;
	entry = free_syscall_entry();
	str_entry = free_str_entry(entry);
	request_syscall_write(entry, str_entry, fd, buf, count);
	return entry;
}
struct flexsc_sysentry *flexsc_open(const char *name, int flag) {
	struct flexsc_sysentry *entry;
	struct flexsc_strentry *str_entry;
	entry = free_syscall_entry();
	str_entry = free_str_entry(entry);

	request_syscall_open(entry, str_entry, name, flag, 0666);
	return entry;
}

struct flexsc_sysentry *flexsc_close(unsigned int fd)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_close(entry, fd);
	return entry;
}

struct flexsc_sysentry *flexsc_stat(const char *pathname, struct stat *statbuf)
{
	struct flexsc_sysentry *entry;
	struct flexsc_strentry *str_entry;
	entry = free_syscall_entry();
	str_entry = free_str_entry(entry);
	request_syscall_stat(entry, str_entry, pathname, statbuf);
	return entry;
}

struct flexsc_sysentry *flexsc_pthread_create(pthread_t *newthread,
					      const pthread_attr_t *attr,
					      void *(*start_routine)(void *),
					      void *arg)
{
	struct flexsc_sysentry *entry;
	entry = free_syscall_entry();
	request_syscall_pthread_create(entry, newthread, attr, start_routine, arg);
	return entry;
}

void request_syscall_stat(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, const char *pathname,
			  struct stat *statbuf)
{
	entry->sysnum = __NR_stat;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	strncpy(str_entry, pathname, 64);
	entry->args[0] = (long)str_entry;
	entry->args[1] = (long)statbuf;
}

void request_syscall_read(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, unsigned int fd,
			  char *buf, size_t count)
{
	entry->sysnum = __NR_read;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = (long)fd;
	entry->args[1] = (long)buf;
	entry->args[2] = (long)count;
}

void request_syscall_write(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, unsigned int fd,
			   char *buf, size_t count)
{
	entry->sysnum = __NR_write;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	strncpy(str_entry, buf, 64);
	entry->args[0] = (long)fd;
	entry->args[1] = (long)str_entry;
	entry->args[2] = (long)count;
}

void request_syscall_open(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, const char *filename,
			  int flags, mode_t mode)
{
	entry->sysnum = __NR_open;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	strncpy(str_entry, filename, 64);
	entry->args[0] = (long)str_entry;
	entry->args[1] = (long)flags;
	entry->args[2] = (long)mode;
}

void request_syscall_close(struct flexsc_sysentry *entry, unsigned int fd)
{
	entry->sysnum = __NR_close;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = (long)fd;
}

void request_syscall_getpid(struct flexsc_sysentry *entry)
{
	entry->sysnum = __NR_getpid;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
}

void request_syscall_pthread_create(struct flexsc_sysentry *entry, pthread_t *newthread,
                   const pthread_attr_t *attr,
                   void *(*start_routine)(void *),
                   void *arg)
{
	entry->sysnum = __NR_clone;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	char* stackTop = malloc(STACK_SIZE);
	entry->args[0] = (long)start_routine;
	entry->args[1] = (long)stackTop;
	entry->args[2] = (long)CLONE_NEWUTS | SIGCHLD;
	entry->args[3] = (long)arg;
	entry->args[4] = NULL;
}

void request_syscall_lseek(struct flexsc_sysentry *entry, int fd, off_t offset, int whence)
{
	entry->sysnum = __NR_lseek;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = fd;
	entry->args[1] = offset;
	entry->args[2] = whence;
}

void request_syscall_fsync(struct flexsc_sysentry *entry, int fd)
{
	entry->sysnum = __NR_fsync;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = fd;
}

void request_syscall_fdatasync(struct flexsc_sysentry *entry, int fd)
{
	entry->sysnum = __NR_fdatasync;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = fd;
}
void request_syscall_ioctl(struct flexsc_sysentry *entry, int fd, unsigned int cmd, unsigned long arg)
{
	entry->sysnum = __NR_ioctl;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = (long)fd;
	entry->args[1] = (long)cmd;
	entry->args[2] = (long)arg;
}

void request_syscall_fadvise(struct flexsc_sysentry *entry, int fd, off_t offset, off_t len, int advise)
{
	entry->sysnum = __NR_fadvise;
	entry->rstatus = FLEXSC_STATUS_SUBMITTED;
	entry->args[0] = (long)fd;
	entry->args[1] = (long)offset;
	entry->args[2] = (long)len;
	entry->args[3] = (long)advise;
}
