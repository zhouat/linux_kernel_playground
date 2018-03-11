/**
 * Vulnerable kernel driver
 *
 * This module is vulnerable to OOB access and allows arbitrary code
 * execution.
 * An arbitrary offset can be passed from user space via the provided ioctl().
 * This offset is then used as an index for the 'ops' array to obtain the
 * function address to be executed.
 * 
 *
 * Full article: https://cyseclabs.com/page?n=17012016
 *
 * Author: Vitaly Nikolenko
 * Email: vnik@cyseclabs.com
 **/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "drv.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/tty.h>
#define DEVICE_NAME "vulndrv"
#define DEVICE_PATH "/dev/vulndrv"

static int device_open(struct inode *, struct file *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_release(struct inode *, struct file *f);

static struct class *class;
unsigned long* ops[3];
static int major_no;

#define IOCTL_TYPE 'G'
#define UAF_192 	_IOR(IOCTL_TYPE, 0, int)
#define UAF_1024	_IOR(IOCTL_TYPE, 2, int)
#define ROOT_SHELL	_IOR(IOCTL_TYPE, 3, int)
#define Ret2Usr 	_IOR(IOCTL_TYPE, 4, int)
#define CODE_EXE	_IOR(IOCTL_TYPE, 5, int)

#ifndef offsetof
	#define offsetof(TYPE, MEMBER) ((size_t) &(((TYPE*)0)->MEMBER))
#endif
static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};


static int device_release(struct inode *i, struct file *f) {
	printk(KERN_INFO "device released!\n");
	return 0;
}

static int device_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "device opened!\n");
	return 0;
}
long long* student;
void *fake_cred;
char *fake_tty_struct;
void *fake_stack;
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct drv_req *req;
	void (*fn)(void);
	req = (struct drv_req *)args;
	switch(cmd) {
	case Ret2Usr:{ // no smep & smap
		printk(KERN_INFO "enter Ret2Usr demo %lx %p\n",req->offset, req->fn);
		*((unsigned long *)req->offset) = (unsigned long)req->fn;
	};break;
	case ROOT_SHELL:{ //backdoor
		commit_creds(prepare_kernel_cred(NULL));
	};break;
	case UAF_1024: {//UAF kmalloc-1024
		printk(KERN_INFO "enter ROP demo");
		switch(req->offset){
			case 1:// free a struct tty_struct obj
				fake_tty_struct = kmalloc(sizeof(struct tty_struct), GFP_KERNEL);
				kfree(fake_tty_struct);
			break;
			case 2:				
				printk(KERN_INFO "magick %lx fake_tty_operations  %lx", *(unsigned long*)fake_tty_struct, req->fn);
				*(unsigned long long *)&fake_tty_struct[24] = (unsigned long long)req->fn;
					
			break;		
		}
	};
	break;
        case UAF_192:{//UAF kmalloc-192
                printk(KERN_INFO "enter UAF demo");
                switch(req->offset){
                        case 1:
                                printk(KERN_INFO "kmalloc %lx\n", sizeof(struct cred));
                                fake_cred = kmalloc(sizeof(struct cred), GFP_KERNEL);
                                kfree(fake_cred);
                        break;
                        case 2:
                                printk(KERN_INFO "cred offset 0 %lx",offsetof(struct cred , egid));
                                memset(fake_cred, 0, offsetof(struct cred , egid));
                        break;
			}
                }
                break;
	case CODE_EXE: { // ROP code exe , smep & smap turn on 
		printk(KERN_INFO "size = %lx fn=%p\n", req->offset, req->fn);
                printk(KERN_INFO "fn is at %p\n", &ops[req->offset]);
		fn = (void(*)(void))&ops[req->offset];
		fn();
		}
		break;
	default:
		printk(KERN_INFO "erro switch\n");
		break;
	}

	return 0;
}

static int m_init(void) {
	printk(KERN_INFO "addr(ops) = %p\n", &ops);
	printk(KERN_INFO "size struct cred =%lx\n", sizeof(struct cred));
	printk(KERN_INFO "size struct tty_struct: %lx\n", sizeof(struct tty_struct));	
	printk(KERN_INFO "size struct file_operations: %lx offset release:%lx\n", sizeof(struct file_operations), offsetof(struct file_operations,release));	
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(class, NULL, MKDEV(major_no, 0), NULL, DEVICE_NAME);

	return 0;
}

static void m_exit(void) {
	device_destroy(class, MKDEV(major_no, 0));
	class_unregister(class);
	class_destroy(class);
	unregister_chrdev(major_no, DEVICE_NAME);
	printk(KERN_INFO "Driver unloaded\n");
}

module_init(m_init);
module_exit(m_exit);


MODULE_LICENSE("GPL");
