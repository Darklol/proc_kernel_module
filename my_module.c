#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/ctype.h>


#define PROCFS_ENTRY_NAME "my_module"
#define PROCFS_FULL_NAME "/proc/my_module"
#define BUF_SIZE 8192
#define MAX_PATH_LEN 1024
#define OUTPUT_SIZE 4096



static int pid = 0;
static int struct_id = 0;
static char path[MAX_PATH_LEN] = {0};
static struct proc_dir_entry *proc_dir_entry;



static ssize_t read_dentry(char __user *ubuf){
	
	printk(KERN_INFO "read_dentry....\n");
	
	char *vbuf = vmalloc(BUF_SIZE);
	ssize_t info = 0;
	
	struct path f_path;
    int file_not_found = kern_path(path, LOOKUP_FOLLOW, &f_path);
	
	if (!file_not_found){
		info += sprintf(vbuf, "Info on a dentry of file %s\n", path);
		info += sprintf(vbuf + info, "d_name = %s \n", f_path.dentry->d_name.name);
		info += sprintf(vbuf + info, "d_parent_name = %s \n", (const void*)f_path.dentry->d_parent->d_name.name);
		info += sprintf(vbuf + info, "d_inode_id = %u \n", f_path.dentry->d_inode->i_ino);
	} else {
		info += sprintf(vbuf, "File %s doesn't exist\n", path);
	}
	
	
	if (copy_to_user(ubuf, vbuf, info)){
		return -EFAULT;
	}
	
	memset(path, 0, sizeof(path));
	vfree(vbuf);
	return info;
}

static ssize_t read_vm_area_struct(char __user *ubuf){
	
	char *vbuf = vmalloc(BUF_SIZE);
	ssize_t info = 0;
	int exists = 1;
	
	struct pid *pid_struct;
	struct task_struct *task_struct;
	struct mm_struct *mm_struct;
	
	pid_struct = find_get_pid(pid);
	if (NULL == pid_struct)	{
		info += sprintf(vbuf, "Process with pid=%d doesn't exist\n", pid);
		exists = 0;
	} else {
			task_struct = pid_task(pid_struct, PIDTYPE_PID);
			if (NULL == task_struct) {
				info += sprintf(vbuf, "Failed to get task_struct with pid=%d\n", pid);
				exists = 0;
			}  else {
					mm_struct = task_struct->mm;
					if (NULL == mm_struct) {
						info += sprintf(vbuf, "mm_struct is NULL | pid=%d\n", pid);
						exists = 0;
					}
			}
	}
	
	if (exists){
	
	info += sprintf(vbuf, "Memory mappings of the process with pid = %d \n", pid);
	info += sprintf(vbuf + info, "Address\t\t Size\tFlags\n", pid);
	
	struct vm_area_struct *vm_area_struct = mm_struct->mmap;

	int null_flag = 0;
	while (!null_flag){
		
		char flags[4] = "---\0";
		
		switch (vm_area_struct->vm_flags & 0x0007){
			case 1:
				strcpy(flags, "r--");
				break;
			case 2:
				strcpy(flags, "-w-");
				break;
			case 3:
				strcpy(flags, "rw-");
				break;
			case 4:
				strcpy(flags, "--x");
				break;
			case 5:
				strcpy(flags, "r-x");
				break;
			case 6:
				strcpy(flags, "-wx");
				break;
			case 7:
				strcpy(flags, "rwx");
				break;
		}
		
		info += sprintf(vbuf + info, "%016lx %luK \t%3s\n", 
			vm_area_struct->vm_start, (vm_area_struct->vm_end - vm_area_struct->vm_start)/1024, flags);
			
		//info += sprintf(vbuf + info, "Mapping from %016lx to %016lx \n", 
		//	vm_area_struct->vm_start, vm_area_struct->vm_end);
		
		if (copy_to_user(ubuf, vbuf, info)){
			return -EFAULT;
		}
		
		if (!vm_area_struct->vm_next){
			null_flag = 1;
			continue;
		}
		vm_area_struct = vm_area_struct->vm_next;
		}
	}

	info += sprintf(vbuf + info, "\0");

	if (copy_to_user(ubuf, vbuf, info)){
		return -EFAULT;
	}
	
	vfree(vbuf);
	return info;
}

static ssize_t read_failed(char __user *ubuf){
	
	ssize_t info = 0;
	
	char *vbuf = vmalloc(BUF_SIZE);
	
	info += sprintf(vbuf, "Failed to read a structure, please try different arguments.\n");
	info += sprintf(vbuf + info, "Usage: {struct_id} {pid_or_path string} {string length}.\n");
	info += sprintf(vbuf + info, "Limitations: struct_id 0 or 1, strings length %d bytes, buffer size %d bytes\n", MAX_PATH_LEN - 1, BUF_SIZE);
	if (copy_to_user(ubuf, vbuf, info)){
		return -EFAULT;
	}
	
	vfree(vbuf);
	
	return info;
}


static ssize_t proc_read(struct file *file, char __user *ubuf, size_t ubuf_size, loff_t *ppos){
	
	
	ssize_t info = 0;	
	
	switch(struct_id){
		case -1:
			info = read_failed(ubuf);
			break;
		case 0:
			info = read_vm_area_struct(ubuf);
			break;
		case 1:
			info = read_dentry(ubuf);
			break;
	} 
	
	*ppos = info;
	
	return info;
}


static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
	
	char *vbuf = vmalloc(BUF_SIZE);
	int arg1, arg3, args_num;
	char arg2[MAX_PATH_LEN] = {0};
	long temp_pid = 0;
	
	printk(KERN_INFO "proc file wrote.....\n");
	
	if (*ppos > 0 || count > BUF_SIZE){
		return -EFAULT;
	}

	if( copy_from_user(vbuf, ubuf, count) ) {
		return -EFAULT;
	}
	
	//magic number in %s is MAX_PATH_LEN
	args_num = sscanf(vbuf, "%d %1024s %d", &arg1, &arg2, &arg3);
	
	
	if (args_num == 3 && arg3 <= MAX_PATH_LEN) {
		printk(KERN_INFO "Arguments have been read: arg1 = %d, arg2 = %1024s, arg3 = %d\n", arg1, arg2, arg3);
		struct_id = arg1;
		if (arg1 == 0) {
			kstrtol((char *) arg2, 10, &temp_pid);
			pid = temp_pid;
		}
		else if (arg1 == 1){
			memcpy(path, (char *) arg2, arg3);
		} else {
			struct_id = -1;
			printk(KERN_INFO "wrong_argument: illegal struct_id read, struct_id = %d", arg1);
		}
		
	}
	else {
		struct_id = -1;
		printk(KERN_INFO "sscanf failed: %d argument(s) have been read, arg3 = %d, MAX_PATH_LEN = %d", args_num, arg3, MAX_PATH_LEN);
		
	}
	
	*ppos = strlen(vbuf);
	vfree(vbuf);

	return strlen(vbuf);
}

static int proc_open(struct inode *inode, struct file *file)
{	
	mutex_lock(&file -> f_pos_lock);
	printk(KERN_INFO "proc file opened...\t");
	return 0;
}

static int proc_release(struct inode *inode, struct file *file)
{	
	mutex_unlock(&file -> f_pos_lock);
	printk(KERN_INFO "proc file released...\t");
	return 0;
}

static const struct file_operations proc_fops = {
	.read = proc_read,
	.write = proc_write,
	.open = proc_open,
	.release = proc_release
};

static int __init my_module_init(void)
{
        proc_dir_entry = proc_create(PROCFS_ENTRY_NAME, 0, NULL, &proc_fops);
        if (NULL == proc_dir_entry) {
                proc_remove(proc_dir_entry);
                printk(KERN_ALERT "Could not initialize /proc/%s", PROCFS_ENTRY_NAME);
                return ENOMEM;
        }
        printk(KERN_INFO "/proc/%s initialized", PROCFS_ENTRY_NAME);
        return 0;
}


static void __exit my_module_cleanup(void)
{
        proc_remove(proc_dir_entry);
        printk(KERN_INFO "/proc/%s removed", PROCFS_ENTRY_NAME);
}


module_init(my_module_init);
module_exit(my_module_cleanup);


MODULE_LICENSE("GPL");
