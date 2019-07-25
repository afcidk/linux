#include "flexsc.h"
#include <asm/syscall.h>
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <asm/syscalls.h>
#include <linux/delay.h>
#define EXP

pid_t hooked_task[FLEXSC_MAX_HOOKED];
const sys_call_ptr_t *sys_ptr;

static struct task_struct *systhread;
/* Declaration of workqueue */
static struct workqueue_struct *flexsc_workqueue;
static struct work_struct *flexsc_works = NULL;

static void flexsc_work_handler(struct work_struct *work);

static struct page *kernel_page;
static struct page *kernel_str_page[64];
size_t nentry; /* Reserved for devel mode */

int systhread_main(void *arg)
{
    struct flexsc_init_info *info = (struct flexsc_init_info*)arg;
    
    while (!kthread_should_stop()) {
        int idx;
        for (idx = 0; idx<nentry; ++idx) {
            if (info->sysentry[idx].rstatus == FLEXSC_STATUS_SUBMITTED) {
#ifdef DEBUG
                printk("work %ld\n", flexsc_works[idx].work_entry->sysnum);
#endif
                info->sysentry[idx].rstatus = FLEXSC_STATUS_BUSY;

				struct flexsc_sysentry *entry = flexsc_works[idx].work_entry;
				entry->idx = idx;

                // open a thread to handle syscall
                queue_work_on(6, flexsc_workqueue, &flexsc_works[idx]);
            }
        }
    }

#ifdef DEBUG
    printk(KERN_INFO "Thread Stopping\n");
#endif
    return 0;
}

void flexsc_create_workqueue(char *name) 
{
#ifdef DEBUG
    printk("Creating flexsc workqueue...\n");
#endif
    /* Create workqueue so that systhread can put a work */
    flexsc_workqueue = alloc_workqueue(name, WQ_CPU_INTENSIVE, 0);
#ifdef DEBUG
    printk("Address of flexsc_workqueue: %p\n", flexsc_workqueue);
#endif
}

static __always_inline long
do_syscall(unsigned int sysname, struct pt_regs *regs) {
    extern const sys_call_ptr_t sys_call_table[];
#ifdef DEBUG
    printk("Do syscall %d\n", sysname);
#endif

    if (likely(sysname < 500)) {
		return sys_call_table[sysname](regs);
    }
    return -ENOSYS;
}

struct flexsc_sysentry *do_flexsc_register(struct flexsc_init_info *user_info)
{
    struct flexsc_init_info *info = kmalloc(sizeof(struct flexsc_init_info), GFP_KERNEL);
    copy_from_user(info, user_info, sizeof(struct flexsc_init_info));
    nentry = info->nentry;

    down_read(&current->mm->mmap_sem);

    get_user_pages(info->sysentry, 1, 1, &kernel_page, NULL);
    k_sysentry = (struct flexsc_sysentry *)kmap(kernel_page);
    info->sysentry = k_sysentry;

    get_user_pages(info->strentry, 1, 1, &kernel_str_page, NULL);
    k_strentry = (struct flexsc_strentry *)kmap(kernel_str_page);
    info->strentry = k_strentry;

    up_read(&current->mm->mmap_sem);

    flexsc_create_workqueue("flexsc_workqueue");
    alloc_workstruct(info);
	systhread = kthread_create(systhread_main, info, "systhread_main");
	kthread_bind(systhread, 7);
	wake_up_process(systhread);

    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_register);

void alloc_workstruct(struct flexsc_init_info *info)
{
    int nentry = info->nentry; /* Number of sysentry */
    int i;
    flexsc_works = (struct work_struct *)kmalloc(sizeof(struct work_struct) * nentry, GFP_KERNEL);
	struct pt_regs *regs = (struct pt_regs*)kmalloc(sizeof(struct pt_regs) * nentry, GFP_KERNEL);

#ifdef DEBUG
    printk("Initializing: Binding work_struct and work_handler\n");
#endif
    for (i = 0; i < nentry; i++) {
        memset(&(info->sysentry[i]), 0, sizeof(struct flexsc_sysentry));
        FLEXSC_INIT_WORK(&flexsc_works[i], flexsc_work_handler, &(info->sysentry[i]), &(info->strentry[i]), &regs[i]);
    }
}


long do_flexsc_exit(void)
{
    printk("%s\n", __func__);
	if (systhread) kthread_stop(systhread);
	if (flexsc_workqueue) destroy_workqueue(flexsc_workqueue);
	if (flexsc_works) kfree(flexsc_works);
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_exit);


static __always_inline void flexsc_work_handler(struct work_struct *work)
{
	#ifdef DEBUG
	printk("In flexsc_work_handler, sysentry: %p\n", work->work_entry);
	#endif
    /* Here is the place where system calls are actually executed */
    struct flexsc_sysentry *entry = work->work_entry;
    const unsigned int sysnum = entry->sysnum;
	struct pt_regs *regs = work->syscall_regs;

	if (sysnum == 2) {
	#ifdef DEBUG
		printk("entry->idx: %d\n", entry->idx);
	#endif
		regs->di = &k_strentry[entry->idx];
	#ifdef DEBUG
		printk("filename: %s %p\n", regs->di, regs->di);
	#endif
	}
	else regs->di  = entry->args[0];

	if (sysnum == 0 || sysnum == 1) {
	#ifdef DEBUG
		printk("entry->idx: %d\n", entry->idx);
	#endif
		regs->si = &k_strentry[entry->idx];
	#ifdef DEBUG
		printk("string: %s %p\n", regs->si, regs->si);
	#endif
	}
	else regs->si  = entry->args[1];
	regs->dx  = entry->args[2];
	regs->r10 = entry->args[3];
	regs->r9  = entry->args[4];
	regs->r8  = entry->args[5];

	#ifdef DEBUG
	printk("%ld %ld %ld %ld %ld %ld\n", entry->args[0], entry->args[1], entry->args[2], entry->args[3], entry->args[4], entry->args[5]);
	#endif
	entry->sysret = do_syscall(sysnum, regs);

	// Note: immediately set to free for experimental purpose
#ifdef EXP
	entry->rstatus = FLEXSC_STATUS_FREE;
#else
	entry->rstatus = FLEXSC_STATUS_DONE;
#endif
	return ;
}

/* Make calling thread(mostly user thread) sleep */
long do_flexsc_wait(void) 
{
    /* static struct task_struct *systhread_pool[SYSENTRY_NUM_DEFAULT]; */
    /* int i; */
    /* printk("Waking up sleeping systhread..."); */
#ifdef DEBUG
    printk("%d is going to sleep\n", current->pid);
#endif

    /* user thread goes to sleep */

    set_current_state(TASK_INTERRUPTIBLE);
    schedule();

    /* for (i = 0; i < SYSENTRY_NUM_DEFAULT; i++) {
        wake_up_process(systhread_pool[i]);
    } */
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_wait);

SYSCALL_DEFINE0(flexsc_wait)
{
	do_flexsc_wait();
	return 0;
}

SYSCALL_DEFINE1(flexsc_register, struct flexsc_init_info *, info)
{
	do_flexsc_register(info);
	return 0;
}

SYSCALL_DEFINE0(flexsc_exit)
{
	do_flexsc_exit();
	return 0;
}
