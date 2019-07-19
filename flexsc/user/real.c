#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static const char file[] = "test.txt";
static char buf[32];
int main() {
	int fd = open(file, O_RDONLY);
	read(fd, buf, 32);
	printf("%s\n", buf);
	return 0;
}
