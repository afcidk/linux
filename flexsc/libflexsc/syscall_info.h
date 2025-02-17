#define __NR_write 1
#define __NR_read 0
#define __NR_open 2
#define __NR_close 3
#define __NR_mmap 9
#define __NR_getpid 39
#define __NR_stat 4
#define __NR_mkdir 83
#define __NR_getppid 110
#define __NR_clone 56

#define __ARGS_write 3
#define __ARGS_read 3
#define __ARGS_open 3
#define __ARGS_close 1
#define __ARGS_mmap 6
#define __ARGS_getpid 0
#define __ARGS_stat 2
#define __ARGS_mkdir 2
#define __ARGS_getppid 0
#define __ARGS_clone 5

/* #define __NR_read 0
#define __ARGS_read 3
#define __NR_write 1
#define __ARGS_write 3
#define __NR_open 2
#define __ARGS_open 3
#define __NR_close 3
#define __ARGS_close 1
#define __NR_stat 4
#define __ARGS_stat 2
#define __NR_fstat 5
#define __ARGS_fstat 2
#define __NR_lstat 6
#define __ARGS_lstat 2
#define __NR_poll 7
#define __ARGS_poll 3
#define __NR_lseek 8
#define __ARGS_lseek 3
#define __NR_mmap 9
#define __ARGS_mmap 6
#define __NR_mprotect 10
#define __ARGS_mprotect 3
#define __NR_munmap 11
#define __ARGS_munmap 2
#define __NR_brk 12
#define __ARGS_brk 1
#define __NR_rt_sigaction 13
#define __ARGS_rt_sigaction 4
#define __NR_rt_sigprocmask 14
#define __ARGS_rt_sigprocmask 4
#define __NR_rt_sigreturn 15
#define __ARGS_rt_sigreturn 1
#define __NR_ioctl 16
#define __ARGS_ioctl 3
#define __NR_pread64 17
#define __ARGS_pread64 4
#define __NR_pwrite64 18
#define __ARGS_pwrite64 4
#define __NR_readv 19
#define __ARGS_readv 3
#define __NR_writev 20
#define __ARGS_writev 3
#define __NR_access 21
#define __ARGS_access 2
#define __NR_pipe 22
#define __ARGS_pipe 1
#define __NR_select 23
#define __ARGS_select 5
#define __NR_sched_yield 24
#define __ARGS_sched_yield 0
#define __NR_mremap 25
#define __ARGS_mremap 5
#define __NR_msync 26
#define __ARGS_msync 3
#define __NR_mincore 27
#define __ARGS_mincore 3
#define __NR_madvise 28
#define __ARGS_madvise 3
#define __NR_shmget 29
#define __ARGS_shmget 3
#define __NR_shmat 30
#define __ARGS_shmat 3
#define __NR_shmctl 31
#define __ARGS_shmctl 3
#define __NR_dup 32
#define __ARGS_dup 1
#define __NR_dup2 33
#define __ARGS_dup2 2
#define __NR_pause 34
#define __ARGS_pause 0
#define __NR_nanosleep 35
#define __ARGS_nanosleep 2
#define __NR_getitimer 36
#define __ARGS_getitimer 2
#define __NR_alarm 37
#define __ARGS_alarm 1
#define __NR_setitimer 38
#define __ARGS_setitimer 3
#define __NR_getpid 39
#define __ARGS_getpid 0
#define __NR_sendfile 40
#define __ARGS_sendfile 4
#define __NR_socket 41
#define __ARGS_socket 3
#define __NR_connect 42
#define __ARGS_connect 3
#define __NR_accept 43
#define __ARGS_accept 3
#define __NR_sendto 44
#define __ARGS_sendto 6
#define __NR_recvfrom 45
#define __ARGS_recvfrom 6
#define __NR_sendmsg 46
#define __ARGS_sendmsg 3
#define __NR_recvmsg 47
#define __ARGS_recvmsg 3
#define __NR_shutdown 48
#define __ARGS_shutdown 2
#define __NR_bind 49
#define __ARGS_bind 3
#define __NR_listen 50
#define __ARGS_listen 2
#define __NR_getsockname 51
#define __ARGS_getsockname 3
#define __NR_getpeername 52
#define __ARGS_getpeername 3
#define __NR_socketpair 53
#define __ARGS_socketpair 4
#define __NR_setsockopt 54
#define __ARGS_setsockopt 5
#define __NR_getsockopt 55
#define __ARGS_getsockopt 5
#define __NR_clone 56
#define __ARGS_clone 5
#define __NR_fork 57
#define __ARGS_fork 1
#define __NR_vfork 58
#define __ARGS_vfork 1
#define __NR_execve 59
#define __ARGS_execve 3
#define __NR_exit 60
#define __ARGS_exit 1
#define __NR_wait4 61
#define __ARGS_wait4 4
#define __NR_kill 62
#define __ARGS_kill 2
#define __NR_uname 63
#define __ARGS_uname 1
#define __NR_semget 64
#define __ARGS_semget 3
#define __NR_semop 65
#define __ARGS_semop 3
#define __NR_semctl 66
#define __ARGS_semctl 4
#define __NR_shmdt 67
#define __ARGS_shmdt 1
#define __NR_msgget 68
#define __ARGS_msgget 2
#define __NR_msgsnd 69
#define __ARGS_msgsnd 4
#define __NR_msgrcv 70
#define __ARGS_msgrcv 5
#define __NR_msgctl 71
#define __ARGS_msgctl 3
#define __NR_fcntl 72
#define __ARGS_fcntl 3
#define __NR_flock 73
#define __ARGS_flock 2
#define __NR_fsync 74
#define __ARGS_fsync 1
#define __NR_fdatasync 75
#define __ARGS_fdatasync 1
#define __NR_truncate 76
#define __ARGS_truncate 2
#define __NR_ftruncate 77
#define __ARGS_ftruncate 2
#define __NR_getdents 78
#define __ARGS_getdents 2
#define __NR_getcwd 79
#define __ARGS_getcwd 2
#define __NR_chdir 80
#define __ARGS_chdir 1
#define __NR_fchdir 81
#define __ARGS_fchdir 1
#define __NR_rename 82
#define __ARGS_rename 2
#define __NR_mkdir 83
#define __ARGS_mkdir 2
#define __NR_rmdir 84
#define __ARGS_rmdir 1
#define __NR_creat 85
#define __ARGS_creat 2
#define __NR_link 86
#define __ARGS_link 2
#define __NR_unlink 87
#define __ARGS_unlink 1
#define __NR_symlink 88
#define __ARGS_symlink 2
#define __NR_readlink 89
#define __ARGS_readlink 3
#define __NR_chmod 90
#define __ARGS_chmod 2
#define __NR_fchmod 91
#define __ARGS_fchmod 2
#define __NR_chown 92
#define __ARGS_chown 3
#define __NR_fchown 93
#define __ARGS_fchown 3
#define __NR_lchown 94
#define __ARGS_lchown 3
#define __NR_umask 95
#define __ARGS_umask 1
#define __NR_gettimeofday 96
#define __ARGS_gettimeofday 2
#define __NR_getrlimit 97
#define __ARGS_getrlimit 2
#define __NR_getrusage 98
#define __ARGS_getrusage 2
#define __NR_sysinfo 99
#define __ARGS_sysinfo 1
#define __NR_times 100
#define __ARGS_times 2
#define __NR_ptrace 101
#define __ARGS_ptrace 4
#define __NR_getuid 102
#define __ARGS_getuid 0
#define __NR_syslog 103
#define __ARGS_syslog 3
#define __NR_getgid 104
#define __ARGS_getgid 0
#define __NR_setuid 105
#define __ARGS_setuid 1
#define __NR_setgid 106
#define __ARGS_setgid 1
#define __NR_geteuid 107
#define __ARGS_geteuid 0
#define __NR_getegid 108
#define __ARGS_getegid 0
#define __NR_setpgid 109
#define __ARGS_setpgid 2
#define __NR_getpgrp 111
#define __ARGS_getpgrp 0
#define __NR_setsid 112
#define __ARGS_setsid 0
#define __NR_setreuid 113
#define __ARGS_setreuid 2
#define __NR_setregid 114
#define __ARGS_setregid 2
#define __NR_getgroups 115
#define __ARGS_getgroups 2
#define __NR_setgroups 116
#define __ARGS_setgroups 2
#define __NR_setresuid 117
#define __ARGS_setresuid 3
#define __NR_getresuid 118
#define __ARGS_getresuid 3

#define __NR_setresgid 119
#define __ARGS_setresgid 3

#define __NR_getresgid 120
#define __ARGS_getresgid 3

#define __NR_getpgid 121
#define __ARGS_getpgid 1
#define __NR_setfsuid 122
#define __ARGS_setfsuid 1
#define __NR_setfsgid 123
#define __ARGS_setfsgid 1
#define __NR_getsid 124
#define __ARGS_getsid 1
#define __NR_capget 125
#define __ARGS_capget 2
#define __NR_capset 126
#define __ARGS_capset 2
#define __NR_rt_sigpending 127
#define __ARGS_rt_sigpending 2
#define __NR_rt_sigtimedwait 128
#define __ARGS_rt_sigtimedwait 4
#define __NR_rt_sigqueueinfo 129
#define __ARGS_rt_sigqueueinfo 3
#define __NR_rt_sigsuspend 130
#define __ARGS_rt_sigsuspend 2
#define __NR_sigaltstack 131
#define __ARGS_sigaltstack 2
#define __NR_utime 132
#define __ARGS_utime 2
#define __NR_mknod 133
#define __ARGS_mknod 3
#define __NR_uselib 134
#define __ARGS_uselib 1
#define __NR_personality 135
#define __ARGS_personality 1
#define __NR_ustat 136
#define __ARGS_ustat 2
#define __NR_statfs 137
#define __ARGS_statfs 2
#define __NR_fstatfs 138
#define __ARGS_fstatfs 2
#define __NR_sysfs 139
#define __ARGS_sysfs 3
#define __NR_getpriority 140
#define __ARGS_getpriority 2
#define __NR_setpriority 141
#define __ARGS_setpriority 3
#define __NR_sched_setparam 142
#define __ARGS_sched_setparam 2
#define __NR_sched_getparam 143
#define __ARGS_sched_getparam 2
#define __NR_sched_setscheduler 144
#define __ARGS_sched_setscheduler 2
#define __NR_sched_getscheduler 145
#define __ARGS_sched_getscheduler 1
#define __NR_sched_get_priority_max 146
#define __ARGS_sched_get_priority_max 1
#define __NR_sched_get_priority_min 147
#define __ARGS_sched_get_priority_min 1
#define __NR_sched_rr_get_interval 148
#define __ARGS_sched_rr_get_interval 2
#define __NR_mlock 149
#define __ARGS_mlock 2
#define __NR_munlock 150
#define __ARGS_munlock 2
#define __NR_mlockall 151
#define __ARGS_mlockall 1
#define __NR_munlockall 152
#define __ARGS_munlockall 0
#define __NR_vhangup 153
#define __ARGS_vhangup 0
#define __NR_modify_ldt 154
#define __NR_pivot_root 155
#define __ARGS_pivot_root 2
#define __NR_sysctl 156
#define __ARGS_sysctl 1
#define __NR_prctl 157
#define __ARGS_prctl 5
#define __NR_arch_prctl 158
#define __NR_adjtimex 159
#define __ARGS_adjtimex 1
#define __NR_setrlimit 160
#define __ARGS_setrlimit 2
#define __NR_chroot 161
#define __ARGS_chroot 1
#define __NR_sync 162
#define __ARGS_sync 0
#define __NR_acct 163
#define __ARGS_acct 1
#define __NR_settimeofday 164
#define __ARGS_settimeofday 2
#define __NR_mount 165
#define __ARGS_mount 5
#define __NR_umount2 166
#define __ARGS_umount2 2
#define __NR_swapon 167
#define __ARGS_swapon 2
#define __NR_swapoff 168
#define __ARGS_swapoff 1
#define __NR_reboot 169
#define __ARGS_reboot 4
#define __NR_sethostname 170
#define __ARGS_sethostname 2
#define __NR_setdomainname 171
#define __ARGS_setdomainname 2
#define __NR_iopl 172
#define __NR_ioperm 173
#define __ARGS_ioperm 3
#define __NR_create_module 174
#define __NR_init_module 175
#define __ARGS_init_module 3
#define __NR_delete_module 176
#define __ARGS_delete_module 2
#define __NR_get_kernel_syms 177
#define __NR_query_module 178
#define __NR_quotactl 179
#define __ARGS_quotactl 4
#define __NR_nfsservctl 180
#define __NR_getpmsg 181
#define __NR_putpmsg 182
#define __NR_afs_syscall 183
#define __NR_tuxcall 184
#define __NR_security 185
#define __NR_gettid 186
#define __ARGS_gettid 0
#define __NR_readahead 187
#define __ARGS_readahead 3
#define __NR_setxattr 188
#define __ARGS_setxattr 5
#define __NR_lsetxattr 189
#define __ARGS_lsetxattr 5
#define __NR_fsetxattr 190
#define __ARGS_fsetxattr 5
#define __NR_getxattr 191
#define __ARGS_getxattr 4
#define __NR_lgetxattr 192
#define __ARGS_lgetxattr 4
#define __NR_fgetxattr 193
#define __ARGS_fgetxattr 4
#define __NR_listxattr 194
#define __ARGS_listxattr 3
#define __NR_llistxattr 195
#define __ARGS_fllistxattr 3
#define __NR_flistxattr 196
#define __ARGS_flistxattr 3
#define __NR_removexattr 197
#define __ARGS_removexattr 2
#define __NR_lremovexattr 198
#define __ARGS_lremovexattr 2
#define __NR_fremovexattr 199
#define __ARGS_fremovexattr 2
#define __NR_tkill 200
#define __ARGS_tkill 2
#define __NR_time 201
#define __ARGS_time 1
#define __NR_futex 202
#define __ARGS_futex 6
#define __NR_sched_setaffinity 203
#define __ARGS_sched_setaffinity 3
#define __NR_sched_getaffinity 204
#define __ARGS_sched_getaffinity 3
#define __NR_set_thread_area 205
#define __NR_io_setup 206
#define __ARGS_io_setup 2
#define __NR_io_destroy 207
#define __ARGS_io_destroy 1
#define __NR_io_getevents 208
#define __ARGS_io_getevents 5
#define __NR_io_submit 209
#define __ARGS_io_submit 3
#define __NR_io_cancel 210
#define __ARGS_io_cancel 3
#define __NR_get_thread_area 211
#define __NR_lookup_dcookie 212
#define __ARGS_lookup_dcookie 3
#define __NR_epoll_create 213
#define __ARGS_epoll_create 1
#define __NR_epoll_ctl_old 214
#define __NR_epoll_wait_old 215
#define __NR_remap_file_pages 216
#define __ARGS_remap_file_pages 5
#define __NR_getdents64 217
#define __ARGS_getdents64 3
#define __NR_set_tid_address 218
#define __ARGS_set_tid_address 1
#define __NR_restart_syscall 219
#define __ARGS_restart_syscall 0
#define __NR_semtimedop 220
#define __ARGS_semtimedop 4
#define __NR_fadvise64 221
#define __ARGS_fadvise64 4
#define __NR_timer_create 222
#define __ARGS_timer_create 3
#define __NR_timer_settime 223
#define __ARGS_timer_settime 4
#define __NR_timer_gettime 224
#define __ARGS_timer_gettime 2
#define __NR_timer_getoverrun 225
#define __ARGS_timer_getoverrun 1
#define __NR_timer_delete 226
#define __ARGS_timer_delete 1
#define __NR_clock_settime 227
#define __ARGS_clock_settime 2
#define __NR_clock_gettime 228
#define __ARGS_clock_gettime 2
#define __NR_clock_getres 229
#define __ARGS_clock_getres 2
#define __NR_clock_nanosleep 230
#define __ARGS_clock_nanosleep 4
#define __NR_exit_group 231
#define __ARGS_exit_group 1
#define __NR_epoll_wait 232
#define __ARGS_epoll_wait 4
#define __NR_epoll_ctl 233
#define __ARGS_epoll_ctl 4
#define __NR_tgkill 234
#define __ARGS_tgkill 3
#define __NR_utimes 235
#define __ARGS_utimes 2
#define __NR_vserver 236
#define __NR_mbind 237
#define __ARGS_mbind 6
#define __NR_set_mempolicy 238
#define __ARGS_set_mempolicy 3
#define __NR_get_mempolicy 239
#define __ARGS_get_mempolicy 5
#define __NR_mq_open 240
#define __ARGS_mq_open 4
#define __NR_mq_unlink 241
#define __ARGS_mq_unlink 1
#define __NR_mq_timedsend 242
#define __ARGS_mq_timedsend 5
#define __NR_mq_timedreceive 243
#define __ARGS_mq_timedreceive 5
#define __NR_mq_notify 244
#define __ARGS_mq_notify 2
#define __NR_mq_getsetattr 245
#define __ARGS_mq_getsetattr 3
#define __NR_kexec_load 246
#define __ARGS_kexec_load 4
#define __NR_waitid 247
#define __ARGS_waitid 5
#define __NR_add_key 248
#define __ARGS_add_key 5
#define __NR_request_key 249
#define __ARGS_request_key 4
#define __NR_keyctl 250
#define __ARGS_keyctl 5
#define __NR_ioprio_set 251
#define __ARGS_ioprio_set 3
#define __NR_ioprio_get 252
#define __ARGS_ioprio_get 2
#define __NR_inotify_init 253
#define __ARGS_inotify_init 0
#define __NR_inotify_add_watch 254
#define __ARGS_inotify_add_watch 3
#define __NR_inotify_rm_watch 255
#define __ARGS_inotify_rm_watch 2
#define __NR_migrate_pages 256
#define __ARGS_migrate_pages 4
#define __NR_openat 257
#define __ARGS_openat 4
#define __NR_mkdirat 258
#define __ARGS_mkdirat 3
#define __NR_mknodat 259
#define __ARGS_mknodat 4
#define __NR_fchownat 260
#define __ARGS_fchownat 5
#define __NR_futimesat 261
#define __ARGS_futimesat 3
#define __NR_newfstatat 262
#define __ARGS_newfstatat 4
#define __NR_unlinkat 263
#define __ARGS_unlinkat 3
#define __NR_renameat 264
#define __ARGS_fchownat 5
#define __NR_linkat 265
#define __ARGS_linkat 5
#define __NR_symlinkat 266
#define __ARGS_symlinkat 3
#define __NR_readlinkat 267
#define __ARGS_readlinkat 4
#define __NR_fchmodat 268
#define __ARGS_fchmodat 3
#define __NR_faccessat 269
#define __ARGS_faccessat 3
#define __NR_pselect6 270
#define __ARGS_pselect6 6
#define __NR_ppoll 271
#define __ARGS_pselect6 5
#define __NR_unshare 272
#define __ARGS_unshare 1
#define __NR_set_robust_list 273
#define __ARGS_set_robust_list 2
#define __NR_get_robust_list 274
#define __ARGS_get_robust_list 6
#define __NR_splice 275
#define __ARGS_splice 6
#define __NR_tee 276
#define __ARGS_tee 4
#define __NR_sync_file_range 277
#define __ARGS_sync_file_range 4
#define __NR_vmsplice 278
#define __ARGS_vmsplice 4
#define __NR_move_pages 279
#define __ARGS_move_pages 7
#define __NR_utimensat 280
#define __ARGS_utimensat 4
#define __NR_epoll_pwait 281
#define __ARGS_utimensat 6
#define __NR_signalfd 282
#define __ARGS_signalfd 3
#define __NR_timerfd_create 283
#define __ARGS_timerfd_create 2
#define __NR_eventfd 284
#define __ARGS_eventfd 1
#define __NR_fallocate 285
#define __ARGS_fallocate 4
#define __NR_timerfd_settime 286
#define __ARGS_timerfd_settime 4
#define __NR_timerfd_gettime 287
#define __ARGS_timerfd_gettime 2
#define __NR_accept4 288
#define __ARGS_accept4 4
#define __NR_accept 289
#define __ARGS_accept 3
#define __NR_utimensat 290
#define __ARGS_utimensat 4
#define __NR_epoll_create1 291
#define __ARGS_epoll_create1 1
#define __NR_dup3 292
#define __ARGS_dup3 3
#define __NR_pipe2 293
#define __ARGS_pipe2 2
#define __NR_inotify_init1 294
#define __ARGS_inotify_init1 1
#define __NR_preadv 295
#define __ARGS_preadv 5
#define __NR_pwritev 296
#define __ARGS_pwritev 5
#define __NR_rt_tgsigqueueinfo 297
#define __ARGS_rt_tgsigqueueinfo 4
#define __NR_perf_event_open 298
#define __ARGS_perf_event_open 5
#define __NR_recvmmsg 299
#define __ARGS_recvmmsg 5
#define __NR_fanotify_init 300
#define __ARGS_fanotify_init 2
#define __NR_fanotify_mark 301
#define __ARGS_fanotify_mark 5
#define __NR_prlimit64 302
#define __ARGS_prlimit64 4
#define __NR_name_to_handle_at 303
#define __ARGS_name_to_handle_at 5
#define __NR_open_by_handle_at 304
#define __ARGS_open_by_handle_at 3
#define __NR_clock_adjtime 305
#define __ARGS_clock_adjtime 2
#define __NR_syncfs 306
#define __ARGS_syncfs 1
#define __NR_sendmmsg 307
#define __ARGS_sendmmsg 4
#define __NR_setns 308
#define __ARGS_setns 2
#define __NR_getcpu 309
#define __ARGS_getcpu 3
#define __NR_process_vm_readv 310
#define __ARGS_process_vm_readv 6
#define __NR_process_vm_writev 311
#define __ARGS_process_vm_writev 6
#define __NR_kcmp 312
#define __ARGS_kcmp 5
#define __NR_finit_module 313
#define __ARGS_finit_module 3
#define __NR_sched_setattr 314
#define __ARGS_sched_setattr 3
#define __NR_sched_getattr 315
#define __ARGS_sched_getattr 4
#define __NR_renameat2 316
#define __ARGS_renameat2 5
#define __NR_seccomp 317
#define __ARGS_seccomp 3
#define __NR_getrandom 318
#define __ARGS_getrandom 3
#define __NR_memfd_create 319
#define __ARGS_memfd_create 2
#define __NR_kexec_file_load 320
#define __ARGS_kexec_file_load 5
#define __NR_bpf 321
#define __ARGS_bpf 3
#define __NR_execveat 322
#define __ARGS_execveat 5
#define __NR_userfaultfd 323
#define __ARGS_userfaultfd 1
#define __NR_membarrier 324
#define __ARGS_membarrier 2
#define __NR_mlock2 325
#define __ARGS_mlock2 3 */
