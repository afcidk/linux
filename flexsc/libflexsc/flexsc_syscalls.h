#include "flexsc.h"

struct call_info {
    struct flexsc_sysentry *entry;
    struct flexsc_cb *cb;
};

/* long flexsc_getpid(struct call_info *info);
long flexsc_read(struct call_info *info);
long flexsc_write(struct call_info *info);
long flexsc_mmap(struct call_info *info);
long flexsc_stat(struct call_info *info);
 */

struct flexsc_sysentry *flexsc_getpid(void);
struct flexsc_sysentry *flexsc_getppid(void);
struct flexsc_sysentry *flexsc_read(unsigned int fd, char *buf, size_t count);
struct flexsc_sysentry *flexsc_write(unsigned int fd, char *buf, size_t count);
struct flexsc_sysentry *flexsc_lseek(int fd, off_t offset, int whence);
struct flexsc_sysentry *flexsc_ioctl(int fd, unsigned int cmd, unsigned long args);
struct flexsc_sysentry *flexsc_fsync(int fd);
struct flexsc_sysentry *flexsc_fdatasync(int fd);
struct flexsc_sysentry *flexsc_fadvise(int fd, off_t, off_t, int);
struct flexsc_sysentry *flexsc_open(const char *name, int flag);
struct flexsc_sysentry *flexsc_close(unsigned int fd);
struct flexsc_sysentry* flexsc_stat(const char *pathname, struct stat *statbuf);
struct flexsc_sysentry* flexsc_pthread_create(pthread_t *newthread,
                   const pthread_attr_t *attr,
                   void *(*start_routine)(void *),
                   void *arg);

void request_syscall_read(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, unsigned int fd, char  *buf, size_t count);
void request_syscall_write(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, unsigned int fd, char  *buf, size_t count);
void request_syscall_lseek(struct flexsc_sysentry *entry, int fd, off_t offset, int whence);
void request_syscall_fsync(struct flexsc_sysentry *entry, int fd);
void request_syscall_fdatasync(struct flexsc_sysentry *entry, int fd);
void request_syscall_ioctl(struct flexsc_sysentry *entry, int fd, unsigned int cmd, unsigned long args);
void request_syscall_open(struct flexsc_sysentry *, struct flexsc_strentry *, const char  *filename, int flags, mode_t mode);
void request_syscall_close(struct flexsc_sysentry *entry, unsigned int fd);
void request_syscall_getpid(struct flexsc_sysentry *entry);
void request_syscall_getppid(struct flexsc_sysentry *entry);
void request_syscall_stat(struct flexsc_sysentry *entry, struct flexsc_strentry *str_entry, const char *pathname, struct stat *statbuf);
void request_syscall_fadvise(struct flexsc_sysentry *entry, int fd, off_t offset, off_t len, int advise);
void request_syscall_pthread_create(struct flexsc_sysentry *entry, pthread_t *newthread,
                   const pthread_attr_t *attr,
                   void *(*start_routine)(void *),
                   void *arg);


/* long flexsc_getpid(struct flexsc_sysentry *entry);
long flexsc_read(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count);
long flexsc_write(struct flexsc_sysentry *entry, unsigned int fd, char *buf, size_t count); */
// long flexsc_mmap(struct flexsc_sysentry *entry, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);

