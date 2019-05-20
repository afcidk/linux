/**
 * @file syscall_hooking.c
 * @brief variation of syscall hooking via dynamic loading kernel module. It locates sys_call_table and intercept system call invoked.
 * @author Yongrae Jo
 * @version 1.0
 * @date 2017
 */

#include "syshook.h"

/* syscall thread main function */
int scanner_thread(void *arg)
{
	struct flexsc_sysentry *entry = (struct flexsc_sysentry *)arg;
	int cnt = 0, i, cpu, ret;
	cpu = smp_processor_id();

	BUG_ON(DEFAULT_CPU != cpu);

	printk("kthread[%d %d %d %d], user[%d, %d] starts\n", current->pid,
	       current->parent->pid, DEFAULT_CPU, cpu, utask->pid,
	       utask->parent->pid);

	/* printk("*****************  entry[3] before main loop  *****************\n");
    print_sysentry(&entry[3]); */

	while (1) {
		set_current_state(TASK_UNINTERRUPTIBLE);

		if (kthread_should_stop()) {
			printk("kernel thread dying...\n");
			do_exit(0);
		}

		for (i = 0; i < NUM_SYSENTRY; i++) {
			if (entry[i].rstatus == FLEXSC_STATUS_SUBMITTED) {
				printk("entry[%d].rstatus == SUBMITTED\n", i);

				entry[i].rstatus = FLEXSC_STATUS_BUSY;
				ret = queue_work_on(DEFAULT_CPU, sys_workqueue,
						    &sys_works[i]);

				if (ret == NULL) {
					printk("sys_work already queued\n");
				}

				/* entry[i].sysret = utask->pid; */
				/* ssleep(3); */
			}
		}
		/* printk("*****************  entry[3]  *****************\n");
        print_sysentry(&entry[3]); */

		/* printk("hello! %d\n", cnt++); */
		schedule_timeout(HZ);
	}
	return 0;
}

#ifdef CONFIG_X86_64
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
#else
typedef asmlinkage long (*sys_call_ptr_t)(unsigned long, unsigned long,
					  unsigned long, unsigned long,
					  unsigned long, unsigned long);
#endif /* CONFIG_X86_64 */

static __always_inline long do_syscall(unsigned int sysnum,
				       struct pt_regs *regs)
{
	if (unlikely(sysnum >= __SYSNUM_flexsc_base)) {
		return -1;
	}

	if (likely(sysnum < 500)) {
		return ((sys_call_ptr_t *)sys_call_table)[sysnum](regs);
	}

	return -ENOSYS;
}

static void syscall_handler(struct work_struct *work)
{
	struct flexsc_sysentry *entry = work->work_entry;
	long sysret;

	print_sysentry(entry);

	sysret = do_syscall(entry->sysnum, entry->regs);

	if (sysret == -ENOSYS) {
		printk("%d %s: do_syscall failed!\n", __LINE__, __func__);
	}

	entry->sysret = sysret;
	entry->rstatus = FLEXSC_STATUS_DONE;
	return;
}

struct task_struct *kstruct;
asmlinkage long sys_hook_flexsc_register(struct flexsc_init_info __user *info)
{
	int i, err, npinned_pages;
	struct flexsc_sysentry *entry;

	/* Print first 8 sysentries */
	pretty_print_emph("User address space");
	print_multiple_sysentry(info->sysentry, 8);

	/* Get syspage from user space 
     * and map it to kernel virtual address space */
	npinned_pages = get_user_pages(
		(unsigned long)(&(info->sysentry[0])), /* Start address to map */
		NUM_PINNED_PAGES, /* Number of pinned pages */
		FOLL_WRITE | FOLL_FORCE, /* Writable flag, Force flag */
		pinned_pages, /* struct page ** pointer to pinned pages */
		NULL);

	if (npinned_pages < 0) {
		printk("Error on getting pinned pages\n");
	}

	sysentry_start_addr = kmap(pinned_pages[0]);

	entry = (struct flexsc_sysentry *)sysentry_start_addr;

	sys_workqueue = create_workqueue("flexsc_workqueue");
	workqueue_set_max_active(sys_workqueue, NUM_SYSENTRY);

	sys_works = (struct work_struct *)kmalloc(
		sizeof(struct work_struct) * NUM_SYSENTRY, GFP_KERNEL);
	if (sys_works == NULL) {
		printk("Error on allocating sys_works\n");
		return -1;
	}

	for (i = 0; i < NUM_SYSENTRY; i++) {
		FLEXSC_INIT_WORK(&sys_works[i], syscall_handler, &(entry[i]));
	}

	kstruct = kthread_create(scanner_thread, (void *)entry,
				 "flexsc scanner thread");
	kthread_bind(kstruct, DEFAULT_CPU);

	if (IS_ERR(kstruct)) {
		printk("queueing thread creation fails\n");
		err = PTR_ERR(kstruct);
		kstruct = NULL;
		return err;
	}

	wake_up_process(kstruct);

	return 0;
}

asmlinkage long sys_hook_flexsc_exit(void)
{
	int i, ret;
	printk("flexsc_exit hooked start\n");
	for (i = 0; i < NUM_PINNED_PAGES; i++) {
		kunmap(pinned_pages[i]);
	}

	if (kstruct) {
		ret = kthread_stop(kstruct);
		kstruct = NULL;
	}

	if (!ret) {
		printk("kthread stopped\n");
	}

	if (!sys_workqueue) {
		destroy_workqueue(sys_workqueue);
	}

	if (!sys_works) {
		kfree(sys_works);
	}

	printk("flexsc_exit hooked end\n");
	return 0;
}

/**
 * disable_write_protection - disable syscall table write protect
 *
 * disable_write_protection() use read_cr0 and write_cr0 to disable
 * syscall table write protect
 */
void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	write_cr0(cr0);
}

/**
 * enable_write_protection - enable syscall table protect
 *
 * enable_write_protection() use read_cr0 and write_cr0 to enable
 * syscall table protect
 */
void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	write_cr0(cr0);
}

int syscall_hooking_init(void)
{
	unsigned long cr0;

	printk("Start hooking\n");
	if ((sys_call_table = get_sys_call_table()) == NULL) {
		printk("Can't find sys_call_table\n");
		return -1;
	}
	printk("-----------------------syscall hooking module-----------------------\n");
	printk("[%p] sys_call_table\n", sys_call_table);

	disable_write_protection();

    /* add flexsc register and exit */
	flexsc_register_orig = (void *)sys_call_table[__NR_flexsc_register];
	flexsc_exit_orig = (void *)sys_call_table[__NR_flexsc_exit];
	sys_call_table[__NR_flexsc_register] = (void *)sys_hook_flexsc_register;
	sys_call_table[__NR_flexsc_exit] = (void *)sys_hook_flexsc_exit;

	enable_write_protection();
	printk("%d %s syscall hooking module init\n", __LINE__, __func__);
	return 0;
}

void syscall_hooking_cleanup(void)
{
	disable_write_protection();
	sys_call_table[__NR_flexsc_register] = (void *)flexsc_register_orig;
	sys_call_table[__NR_flexsc_exit] = (void *)flexsc_exit_orig;
	enable_write_protection();

	printk("Hooking moudle cleanup\n");
	return;
}

unsigned long **get_sys_call_table(void)
{
	unsigned long **entry = (unsigned long **)PAGE_OFFSET;

	for (; (unsigned long)entry < ULONG_MAX; entry += 1) {
		if (entry[__NR_close] == (unsigned long *)ksys_close) {
			return entry;
		}
	}
	return NULL;
}

void print_sysentry(struct flexsc_sysentry *entry)
{
	printk("[%p] %d-%d-%d-%d with %lu,%lu,%lu,%lu,%lu,%lu\n", entry,
	       entry->sysnum, entry->nargs, entry->rstatus, entry->sysret,
	       entry->regs->di, entry->regs->si, entry->regs->dx,
	       entry->regs->r10, entry->regs->r8, entry->regs->r9);
}

void print_multiple_sysentry(struct flexsc_sysentry *entry, size_t n)
{
	int i;
	for (i = 0; i < n; i++) {
		print_sysentry(&entry[i]);
	}
}

void address_stuff(void *addr)
{
	/* printk("flexsc_register() hooked by %d\n", current->pid);
    printk("%d\n", PAGE_SHIFT);
    printk("sizeof entry: %ld, %ld\n", sizeof(entry), sizeof(*entry)); */
	/* 
    physical_address = virt_to_phys(info->sysentry);

    printk("# of pinned pages:                   %d\n", npinned_pages);
    printk("pinned_pages[0]                      %p\n", pinned_pages[0]);
    printk("page_address(pinned_pages[0]):       %p\n", page_address(pinned_pages[0]));
    printk("sysentry_start_addr:                 %p\n", sysentry_start_addr);

    printk("physical address                     %p\n", (void *)physical_address);
    printk("info->sysentry                       %p\n", info->sysentry);
    printk("__pa(info->sysentry)                 %p\n", (void *)__pa(info->sysentry));
    printk("virt_to_page(info->sysentry)         %p\n", virt_to_page(info->sysentry));

    printk("virt_to_pfn(sysentry)                %ld\n", virt_to_pfn(info->sysentry));
    printk("virt_to_phys(sysentry)               %p\n", (void *)virt_to_phys(info->sysentry));

    printk("page->virt                           %p\n", page_address(virt_to_page(info->sysentry)));
    printk("%20s\n", "After kamp(pinned_pages)"); */
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_cleanup);
MODULE_LICENSE("GPL");
