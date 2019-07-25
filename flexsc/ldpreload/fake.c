#include <stddef.h>
#include <dlfcn.h>
#include <signal.h>
#include "../libflexsc/flexsc_syscalls.h"

static int (*main_orig)(int, char **, char **);

ssize_t open64(char *pathname, int flags) {
	struct flexsc_sysentry *entry;
	entry = flexsc_open(pathname, flags);
	while (entry->rstatus != FLEXSC_STATUS_FREE);
	return entry->sysret;
}

int posix_fadvise64(int fd, off_t offset, off_t len, int fadvise) {
	struct flexsc_sysentry *entry;
	entry = flexsc_fadvise(fd, offset, len, fadvise);
	while (entry->rstatus != FLEXSC_STATUS_FREE);
	return entry->sysret;
}

void exit(int status) {
	printf("In exit");
	typeof(&exit) orig = dlsym(RTLD_NEXT, "exit");
	syscall(433);
	orig(status);
}

int fsync(int fd) {
	struct flexsc_sysentry *entry;
	entry = flexsc_fsync(fd);
	while (entry->rstatus != FLEXSC_STATUS_FREE);
	return entry->sysret;
}

int ioctl(int fd, unsigned int cmd, unsigned long args) {
	struct flexsc_sysentry *entry;
	entry = flexsc_ioctl(fd, cmd, args);
	while (entry->rstatus != FLEXSC_STATUS_FREE);
	return entry->sysret;
}

int fdatasync(int fd) {
	struct flexsc_sysentry *entry;
	entry = flexsc_fdatasync(fd);
	while (entry->rstatus != FLEXSC_STATUS_FREE);
	return entry->sysret;
}

/*
ssize_t pread64(int fd, void *buf, size_t nbytes, off_t offset) {
	struct flexsc_sysentry *entry[64];
	struct flexsc_sysentry *tmp_entry;
	entry[0] = flexsc_lseek(fd, 0, SEEK_CUR);
	while (entry[0]->rstatus != FLEXSC_STATUS_FREE);

	if (entry[0]->sysret == (off_t) -1) return -1;
	entry[0] = flexsc_lseek(fd, offset, SEEK_SET);
	while (entry[0]->rstatus != FLEXSC_STATUS_FREE);
	if (entry[0]->sysret == (off_t) -1) return -1;

	int max_ind = (nbytes/64)>64?64:(nbytes/64);
	for (int i=0; i<nbytes/64; ++i) {
		//printf("%d/%d\n", i, nbytes/64);
		tmp_entry = flexsc_read(fd, buf, 64);
		entry[tmp_entry->idx] = tmp_entry;
	}

	int ind = 0;
	while (ind != max_ind) {
		//printf("waiting: %d/%d\n", ind, max_ind);
		ind = 0;
		for (int i = 0; i < max_ind; ++i)
			if (entry[i]->rstatus == FLEXSC_STATUS_FREE)
				++ind;
	}
	return nbytes;
}
*/

ssize_t pwrite64(int fd, void *buf, size_t nbytes, off_t offset) {
	struct flexsc_sysentry *entry[64];
	struct flexsc_sysentry *tmp_entry;
	entry[0] = flexsc_lseek(fd, 0, SEEK_CUR);
	while (entry[0]->rstatus != FLEXSC_STATUS_FREE);

	if (entry[0]->sysret == (off_t) -1) return -1;
	entry[0] = flexsc_lseek(fd, offset, SEEK_SET);
	while (entry[0]->rstatus != FLEXSC_STATUS_FREE);
	if (entry[0]->sysret == (off_t) -1) return -1;

	flexsc_write(fd, buf, nbytes);

	return nbytes;
}

void cleanup_handler(int sig) {
	printf("cleanup\n");
	if (sig == SIGSEGV) printf("segmentation fault\n");
	syscall(433);
	exit(0);
}

int main_hook(int argc, char **argv, char **envp) {
	printf("START\n");
	signal(SIGSEGV, cleanup_handler);
	signal(SIGINT, cleanup_handler);

	struct flexsc_init_info info;
	flexsc_register(&info);

	int ret = main_orig(argc, argv, envp);
	syscall(433);
	printf("END\n");

	return ret;
}

int __libc_start_main(
		int (*main)(int, char **, char **),
		int argc,
		char **argv,
		int (*init)(int, char **, char **),
		void (*fini)(void), void (*rtld_fini)(void),
		void *stack_end)
{
	main_orig = main;
	typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");

	return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}

