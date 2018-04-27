#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/lsm_hooks.h>
#include <linux/slab.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");

#include "acslinux_hooks.c"

static __init int acslinux_init(void)
{
	printk(KERN_INFO "ACSLinux:  Initializing.\n");

	security_add_hooks(acslinux_hooks, ARRAY_SIZE(acslinux_hooks), "acslinux");

	return 0;
}

module_init(acslinux_init);
