#include <stddef.h>
#include <unistd.h>
#define BATCH_SIZE 64

static int (*main_orig)(int, char **, char **);

ssize_t pwrite64(int fd, void *buf, size_t nbytes, off_t offset) {
	ssize_t result;
	size_t nbytes_div = nbytes/BATCH_SIZE;
	off_t old_offset = lseek(fd, 0, SEEK_CUR);
	//printf("nbytes: %ld = %ld*%d\n", nbytes, nbytes_div, BATCH_SIZE);
	if (old_offset == (off_t) -1) return -1;
	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) return -1;

	int max_ind = (nbytes/64)>64?64:(nbytes/64);

	int total = 0;
	for (int i=0; i<max_ind; ++i)
		total += write(fd, buf, 64);

	return total;
}
