#include "flexsc.h"
#include <asm/syscall.h>
#include <linux/highmem.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/sched/task.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <asm/syscalls.h>

const sys_call_ptr_t *sys_ptr;

static struct task_struct *systhread;
/* Declaration of workqueue */
static struct workqueue_struct *flexsc_workqueue;
static struct work_struct *flexsc_works = NULL;

static void flexsc_work_handler(struct work_struct *work);

static struct page *kernel_page;
int systhread_on_cpu[2] = {5, 6};
struct task_struct *user_task;
size_t nentry; /* Reserved for devel mode */

int systhread_main(void *arg)
{
    struct flexsc_init_info *info = (struct flexsc_init_info*)arg;
    /* int idx = *((int *)arg); */
    /* printk("Got an index(%d)\n", idx); */
    
    // This entry pointer exactly points to an entry with having right offset
    
    while (!kthread_should_stop()) {
        int idx;
        ssleep(1);
        for (idx = 0; idx<nentry; ++idx) {
            if (info->sysentry[idx].rstatus == FLEXSC_STATUS_SUBMITTED) {
                //printk("work %ld\n", flexsc_works[idx].work_entry->sysnum);
                info->sysentry[idx].rstatus = FLEXSC_STATUS_BUSY;

                // open a thread to handle syscall
                queue_work_on(DEFAULT_CPU, flexsc_workqueue, &flexsc_works[idx]);
            }
        }
    }

    //printk(KERN_INFO "Thread Stopping\n");
    do_exit(0);
    return 0;
}

void flexsc_create_workqueue(char *name) 
{
    //printk("Creating flexsc workqueue...\n");
    /* Create workqueue so that systhread can put a work */
    flexsc_workqueue = create_workqueue(name);
    //printk("Address of flexsc_workqueue: %p\n", flexsc_workqueue);
}

static __always_inline long
do_syscall(unsigned int sysname, struct pt_regs *regs) {
    extern const sys_call_ptr_t sys_call_table[];
    //printk("Do syscall %d\n", sysname);

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
    //printk("nentry: %lu\n", info->nentry);

    down_read(&current->mm->mmap_sem);

    get_user_pages(info->sysentry, 1, 1, &kernel_page, NULL);
    k_sysentry = (struct flexsc_sysentry *)kmap(kernel_page);
    info->sysentry = k_sysentry;

    up_read(&current->mm->mmap_sem);

    syscall_regs = kmalloc(sizeof(struct pt_regs), GFP_KERNEL);
    //flexsc_create_workqueue("flexsc_workqueue");
    alloc_workstruct(info);
	/*
    systhread = kthread_run(systhread_main, info, "systhread_main");
	*/

    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_register);

void alloc_workstruct(struct flexsc_init_info *info)
{
    int nentry = info->nentry; /* Number of sysentry */
    int i;
    //printk("INFO Allocating work_struct(#%d)\n", nentry);
    flexsc_works = (struct work_struct *)kmalloc(sizeof(struct work_struct) * nentry, GFP_KERNEL);

    //printk("Initializing: Binding work_struct and work_handler\n");
    for (i = 0; i < nentry; i++) {
        memset(&(info->sysentry[i]), 0, sizeof(struct flexsc_sysentry));
        FLEXSC_INIT_WORK(&flexsc_works[i], flexsc_work_handler, &(info->sysentry[i]));
    }
}


long do_flexsc_exit(void)
{
    //printk("%s\n", __func__);
    flexsc_destroy_workqueue(flexsc_workqueue);
    flexsc_free_works(flexsc_works);
    kthread_stop(systhread);
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_exit);


void flexsc_destroy_workqueue(struct workqueue_struct *flexsc_workqueue)
{
    if (flexsc_workqueue == NULL) {
        //printk("flexsc workqueue is empty!\n");
        return;
    }

    //printk("Destroying flexsc workqueue...\n");
    destroy_workqueue(flexsc_workqueue);
}

void flexsc_free_works(struct work_struct *flexsc_works)
{
    int i;
    if (flexsc_works == NULL) {
        //printk("flexsc works is empty!\n");
        return;
    }

    //printk("Deallocating flexsc work structs...\n");
    for (i=0; i < nentry; ++i)
        kfree(&flexsc_works[i]);
}

static __always_inline void flexsc_work_handler(struct work_struct *work)
{
    /* Here is the place where system calls are actually executed */
    struct flexsc_sysentry *entry = work->work_entry;
    const unsigned int sysnum = entry->sysnum;
    //printk("In flexsc_work_handler\n");

	syscall_regs->di  = entry->args[0];
	syscall_regs->si = entry->args[1];
    syscall_regs->dx  = entry->args[2];
    syscall_regs->r10 = entry->args[3];
    syscall_regs->r9  = entry->args[4];
    syscall_regs->r8  = entry->args[5];

    entry->sysret = do_syscall(sysnum, syscall_regs);
    entry->rstatus = FLEXSC_STATUS_DONE;
    return ;
}

/* Make calling thread(mostly user thread) sleep */
long do_flexsc_wait(void) 
{
    /* static struct task_struct *systhread_pool[SYSENTRY_NUM_DEFAULT]; */
    /* int i; */
    /* //printk("Waking up sleeping systhread..."); */
    //printk("%d is going to sleep\n", current->pid);

    /* user thread goes to sleep */

    set_current_state(TASK_INTERRUPTIBLE);
    schedule();

    /* for (i = 0; i < SYSENTRY_NUM_DEFAULT; i++) {
        wake_up_process(systhread_pool[i]);
    } */
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_wait);

long do_flexsc_start_hook(pid_t hooked_pid) 
{
	//printk("Processing syscalls...\n");
	int idx;
	for (idx = 0; idx<nentry; ++idx) {
		if (k_sysentry[idx].rstatus == FLEXSC_STATUS_SUBMITTED){
			//printk("work %ld\n", flexsc_works[idx].work_entry->sysnum);
			k_sysentry[idx].rstatus = FLEXSC_STATUS_BUSY;

			// open a thread to handle syscall
			flexsc_work_handler(&flexsc_works[idx]);
		}
	}
    return 0;
}
EXPORT_SYMBOL_GPL(do_flexsc_start_hook);

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

SYSCALL_DEFINE1(flexsc_start_hook, pid_t, hooked_pid)
{
	do_flexsc_start_hook(hooked_pid);
	return 0;
}

SYSCALL_DEFINE0(flexsc_exit)
{
	do_flexsc_exit();
	return 0;
}
