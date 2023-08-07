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
#include <linux/fdtable.h>
#include<linux/ptrace.h>
#include<linux/module.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/file.h>
#include<linux/path.h>
#include<linux/dcache.h>
#include<linux/sched.h>
#include<linux/fs_struct.h>
#include <asm/tlbflush.h>
#include<linux/sched/task_stack.h>
#include <linux/mmap_lock.h>


#define DEVNAME "cs614_device"

//values to read
#define PID             0
#define STATIC_PRIO     1
#define COMM            2
#define PPID            3
#define NVCSW           4
#define NUM_THREADS     5
#define NUM_FILES_OPEN  6
#define STACK_SIZE      7




#define PID_MAX         4194304

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

static int map[PID_MAX + 1];
static struct mutex mutex_thread[PID_MAX + 1];


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

static unsigned long get_stack_end(struct mm_struct *mm, struct pt_regs *regs){
		struct vm_area_struct *vma;	
		unsigned long stack_end;	
		VMA_ITERATOR(vmi, mm, 0);
                mmap_read_lock(mm);
                for_each_vma(vmi, vma) {
                	if(regs->sp < vma->vm_end && regs->sp >= vma->vm_start){
				stack_end = vma->vm_end;
                                break;
                        }
                }
                mmap_read_unlock(mm);
		return stack_end;
}

static ssize_t demo_read(struct file *filp,
                           char *ubuf,
                           size_t length,
                           loff_t * offset)
{
        char *d_buf = NULL;
        ssize_t ret;
	int newval;	
	mutex_lock(&mutex_thread[current->tgid]);		
	newval = map[current->tgid];
	mutex_unlock(&mutex_thread[current->tgid]);	
	d_buf = kzalloc(4096, GFP_KERNEL);
	if(newval == PID){
		ret = sprintf(d_buf, "%lu", (unsigned long)current->pid); 
	}else if(newval == STATIC_PRIO){
		ret = sprintf(d_buf, "%d", current->static_prio);
	}else if(newval == COMM){
		ret = sprintf(d_buf, "%s", current->comm);
	}else if(newval == PPID){
		ret = sprintf(d_buf, "%d", current->parent->pid); 
	}else if(newval == NVCSW){
		ret = sprintf(d_buf, "%lu", current->nvcsw); 
	}else if(newval == NUM_THREADS){
		ret = sprintf(d_buf, "%d", current->signal->nr_threads);	
	}else if(newval == NUM_FILES_OPEN){
		struct fdtable *fdt = files_fdtable(current->files);
		int count = 0;	
		for(int i=0; i<fdt->max_fds; i++){	
			if(fd_is_open(i, fdt))
				count++;
		}
		ret = sprintf(d_buf, "%d", count);
	}else if(newval == STACK_SIZE){
		struct task_struct *group_leader = current->group_leader;	
		struct pt_regs *regs = task_pt_regs(group_leader);	
		struct mm_struct *mm = group_leader->mm;	
		unsigned long stack_start = group_leader->mm->start_stack;	
		unsigned long stack_end;	
		unsigned long max_stack = stack_start - regs->sp;
		pid_t max_stack_pid = group_leader->pid; 
		struct task_struct *t;	
		for_each_thread(group_leader, t){	
			regs = task_pt_regs(t);	
			stack_end = get_stack_end(mm, regs);	
			if(stack_end - regs->sp > max_stack){
				max_stack = stack_end - regs->sp;	
				max_stack_pid = t->pid;		
			}
		}
		ret = sprintf(d_buf, "%d", max_stack_pid);	
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
        if (err || newval < 0 || newval > 7 )
                return -EINVAL;
	mutex_lock(&mutex_thread[current->tgid]);	
	map[current->tgid] = newval;
	mutex_unlock(&mutex_thread[current->tgid]);	
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
 	
	for(int i = 0; i <= PID_MAX; i++){
		mutex_init(&mutex_thread[i]);		
	}	

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
	for(int i = 0; i <= PID_MAX; i++){
		mutex_destroy(&mutex_thread[i]);	
	}
        pr_info("Device Driver Remove...Done!!!\n");
}

module_init(cs614_driver_init);
module_exit(cs614_driver_exit);

MODULE_LICENSE("GPL");



