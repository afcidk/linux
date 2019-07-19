/*
 *  * sch-test
 *   * test program fro syscallh
 *    * Feb 23, 2019
 *     * root@davejingtian.org
 *      * https://davejingtian.org
 *       */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include "../libflexsc/flexsc_syscalls.h"

static const char *readme = "test.txt";
static const char buf[64];

int main(void)
{
	struct flexsc_sysentry *entry;
	struct flexsc_sysentry *receiver[65];
	struct flexsc_init_info info;

	entry = flexsc_register(&info);
	printf("After registering flexsc\n");

	receiver[0] = flexsc_open(readme, O_RDONLY);
	syscall(432, getpid());
	while (receiver[0]->rstatus != FLEXSC_STATUS_DONE);

	for (int i=1; i<65; ++i) {
		receiver[i] = flexsc_read(receiver[0]->sysret, buf, sizeof(buf)/2);
	}
	while (receiver[1]->rstatus != FLEXSC_STATUS_DONE);

	printf("fd: %d\n", receiver[0]->sysret);
	printf("Bytes: %d\n->%s<-\n", receiver[1]->sysret, buf);
	return 0;
}
