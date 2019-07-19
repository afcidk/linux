#include "syshook.h"

asmlinkage long syshook_flexsc_register(struct flexsc_init_info __user *info)
{
	printk("**************syshook_flexsc_register success!!!!************\n");
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

static __init int syscall_hooking_init(void)
{	
	pr_info("Entering: %s\n", __func__);
	
	sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		pr_err("sch: Couldn't look up sys_call_table\n");
		return -1;
	}
	
	pr_info("-----------------------syscall hooking module-----------------------\n");
	pr_info("[%p] sys_call_table\n", sys_call_table);
	
	/* add flexsc register and exit */

	disable_write_protection();
	orig_flexsc_register = (void *)xchg(&sys_call_table[__NR_getpid], syshook_flexsc_register);
	enable_write_protection();
	pr_info("%d %s syscall hooking module init\n", __LINE__, __func__);
	return 0;
}

void syscall_hooking_cleanup(void)
{
	disable_write_protection();
	sys_call_table[__NR_getpid] = (void *)orig_flexsc_register;
	enable_write_protection();

	pr_info("Hooking moudle cleanup\n");
	return;
}

module_init(syscall_hooking_init);
module_exit(syscall_hooking_cleanup);
MODULE_LICENSE("GPL");
