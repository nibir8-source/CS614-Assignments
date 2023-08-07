#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include<linux/sysfs.h>
#include<linux/kobject.h>
#include <linux/err.h>


#define DEVNAME "cs614_device"

//values to read
#define PID             0
#define STATIC_PRIO     1
#define COMM            2
#define PPID            3
#define NVCSW           4
#define PID_MAX         4194304

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

static int map[PID_MAX + 1];

static int demo_open(struct inode *inode, struct file *file)
{
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        printk(KERN_INFO "Device opened successfully\n");
        return 0;
}

static int demo_release(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device closed successfully\n");
        return 0;
}

static ssize_t demo_read(struct file *filp,
                           char *ubuf,
                           size_t length,
                           loff_t * offset)
{
        
	int newval = map[current->pid];
	char *d_buf = NULL;	
	ssize_t ret;	
	d_buf = kzalloc(4096, GFP_KERNEL);	
	if(newval == PID){
		ret = sprintf(d_buf, "%lu", (unsigned long)current->pid); 
	}else if(newval == STATIC_PRIO){
		ret = sprintf(d_buf, "%d", current->static_prio);
	}else if(newval == COMM){
		ret = sprintf(d_buf, "%s", current->comm);
	}else if(newval == PPID){
		ret = sprintf(d_buf, "%d", current->parent->pid); 
	}else{
		ret = sprintf(d_buf, "%lu", current->nvcsw); 
	} 

	if(copy_to_user(ubuf, d_buf, length)){
               	kfree(d_buf);	 
		return -EINVAL;
       	} 
	kfree(d_buf);	
	printk(KERN_INFO "In read\n");
        return ret;
}


static struct file_operations fops = {
        .read = demo_read,
        .write = NULL,
        .open = demo_open,
        .release = demo_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}



/*
** Function Prototypes
*/
static int      __init cs614_driver_init(void);
static void     __exit cs614_driver_exit(void);



static ssize_t cs614_value_set(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        int newval;
        int err = kstrtoint(buf, 10, &newval);
        if (err || newval < 0 || newval > 6 )
                return -EINVAL;
	map[current->pid] = newval;
        return count;


}



static struct kobj_attribute cs614_value_attribute = __ATTR(cs614_value, 0660, NULL, cs614_value_set);
static struct attribute *cs614_value_attrs[] = {
        &cs614_value_attribute.attr,
        NULL,
};
static struct attribute_group cs614_value_attr_group = {
        .attrs = cs614_value_attrs,
        .name = "cs614_sysfs",
};

/*
** Module Init function
*/
static int __init cs614_driver_init(void)
{
        int ret = sysfs_create_group (kernel_kobj, &cs614_value_attr_group);
        int err;
        if(unlikely(ret))
                printk(KERN_INFO "demo: can't create sysfs\n");
        major = register_chrdev(0, DEVNAME, &fops);
        err = major;
        if (err < 0) {
             printk(KERN_ALERT "Registering char device failed with %d\n", major);
             goto error_regdev;
        }

        demo_class = class_create(THIS_MODULE, DEVNAME);
        err = PTR_ERR(demo_class);
        if (IS_ERR(demo_class))
                goto error_class;

        demo_class->devnode = demo_devnode;

        demo_device = device_create(demo_class, NULL,
                                        MKDEV(major, 0),
                                        NULL, DEVNAME);
        err = PTR_ERR(demo_device);
        if (IS_ERR(demo_device))
                goto error_device;

        printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);                         
        atomic_set(&device_opened, 0);
 pr_info("Device Driver Insert...Done!!!\n");
        return 0;
error_device:
         class_destroy(demo_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        return  err;

}

/*
** Module exit function
*/
static void __exit cs614_driver_exit(void)
{
        device_destroy(demo_class, MKDEV(major, 0));
        class_destroy(demo_class);
        unregister_chrdev(major, DEVNAME);
        sysfs_remove_group (kernel_kobj, &cs614_value_attr_group);

        pr_info("Device Driver Remove...Done!!!\n");
}

module_init(cs614_driver_init);
module_exit(cs614_driver_exit);

MODULE_LICENSE("GPL");



