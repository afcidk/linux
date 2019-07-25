/* Copyright (C) 
 * 2017 - Yongrae Jo
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 * 
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <sched.h>
#include <stdio.h>
#include <sys/stat.h>
#include "flexsc_cpu.h"
#include "flexsc_types.h"
#include "syscall_info.h"

struct flexsc_sysentry *flexsc_register(struct flexsc_init_info *info);
void flexsc_wait(void);
int init_info(struct flexsc_init_info *);
static unsigned current_pid;

/* Globally used sysentry; it's used for free_syscall_entry() */
static struct flexsc_sysentry *gentry; 
static struct flexsc_strentry *g_strentry;

/* Find free sysentry and returns it */
struct flexsc_sysentry *free_syscall_entry(void);
struct flexsc_strentry *free_str_entry(struct flexsc_sysentry*);
char *flexsc_getbuf(int idx);

void flexsc_hook(void);

pid_t gettid(void);

void flexsc_exit();

static void __flexsc_register(struct flexsc_init_info *info) 
{
	current_pid = getpid();
    printf("%s sycall %d\n", __func__, SYSCALL_FLEXSC_REGISTER);
    syscall(SYSCALL_FLEXSC_REGISTER, info); 
}

void print_sysentry(struct flexsc_sysentry *entry);

long flexsc_syscall(unsigned sysnum, unsigned n, unsigned long args[6], struct flexsc_cb *cb);
void init_cpuinfo_default(struct flexsc_cpuinfo *cpuinfo);
