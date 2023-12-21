#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/mm.h>
#include <linux/timekeeping.h>

#include <asm/errno.h>

#define SUCCESS 0
#define DEVICE_NAME "kfetch"
#define BUF_LEN 1024

#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1);

static int kfetch_open(struct inode *, struct file *);
static int kfetch_release(struct inode *, struct file *);
static ssize_t kfetch_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t kfetch_write(struct file *, const char __user *, size_t, loff_t *);

static void kfetch_msg(char*);
static void next_victim(char*);
static void kernel_release(char*);
static void cpu_model(char*);
static void num_cpus(char*);
static void mem(char*);
static void num_procs(char*);
static void uptime(char*);

typedef struct {
    char str[200];
    bool present;
} info_struct;

static int major;
enum {
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);

static char kfetch_buf[BUF_LEN + 1];

static struct class *cls;

static info_struct info[6];

const static struct file_operations kfetch_ops = {
    .owner   = THIS_MODULE,
    .read    = kfetch_read,
    .write   = kfetch_write,
    .open    = kfetch_open,
    .release = kfetch_release,
};

static int __init kfetch_init(void)
{
    major = register_chrdev(0, DEVICE_NAME, &kfetch_ops);

    if (major < 0) { 
        pr_alert("Registering char device failed with %d\n", major); 
        return major; 
    } 
 
    pr_info("I was assigned major number %d.\n", major); 

    cls = class_create(THIS_MODULE, DEVICE_NAME);

    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME); 

    pr_info("Device created on /dev/%s\n", DEVICE_NAME);

    return SUCCESS;
}
 
static void __exit kfetch_exit(void)
{
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);

    unregister_chrdev(major, DEVICE_NAME);
}

static int kfetch_open(struct inode *inode, struct file *file) 
{
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) 
        return -EBUSY; 

    try_module_get(THIS_MODULE);

    return SUCCESS; 
} 

static int kfetch_release(struct inode *inode, struct file *file) 
{
    atomic_set(&already_open, CDEV_NOT_USED); 

    module_put(THIS_MODULE); 

    for (int i = 0; i < KFETCH_NUM_INFO; i++) {
        memset(info[i].str, 0, sizeof(info[i].str));
        info[i].present = false;
    }

    return SUCCESS; 
}

static int mask_info;

static ssize_t kfetch_read(struct file *filp,
                           char __user *buffer,
                           size_t length,
                           loff_t *offset)
{
    size_t bytes_read;

    memset(kfetch_buf, 0, BUF_LEN + 1);
    kfetch_msg(kfetch_buf);
    bytes_read = min(strlen(kfetch_buf) - (size_t)(*offset), sizeof(kfetch_buf));

    if (bytes_read == 0) {
        return 0;
    }

    if (copy_to_user(buffer, kfetch_buf + *offset, bytes_read)) {
        pr_alert("Failed to copy data to user");
        return -EFAULT;
    }

    *offset += bytes_read;
    return bytes_read;
}

static ssize_t kfetch_write(struct file *filp,
                            const char __user *buffer,
                            size_t length,
                            loff_t *offset)
{
    if (length != sizeof(mask_info)) {
        pr_alert("Invalid length of data");
        return -EINVAL; // Invalid argument error
    }

    if (copy_from_user(&mask_info, buffer, length)) {
        pr_alert("Failed to copy data from user");
        return -EFAULT;
    }

    // if the corresponding bit is set, then set the info
    if (mask_info & KFETCH_RELEASE) {
        kernel_release(info[0].str);
        info[0].present = true;
    }
    if (mask_info & KFETCH_NUM_CPUS) {
        num_cpus(info[1].str);
        info[1].present = true;
    }
    if (mask_info & KFETCH_CPU_MODEL) {
        cpu_model(info[2].str);
        info[2].present = true;
    }
    if (mask_info & KFETCH_MEM) {
        mem(info[3].str);
        info[3].present = true;
    }
    if (mask_info & KFETCH_UPTIME) {
        uptime(info[4].str);
        info[4].present = true;
    }
    if (mask_info & KFETCH_NUM_PROCS) {
        num_procs(info[5].str);
        info[5].present = true;
    }

    return SUCCESS;
}

static void kfetch_msg(char* buf)
{
/*
format: (ascii art should be included in the output) (the info below separator are optional)
                    <hostname>
        .-.         ---separator with same length as hostname---
       (-- |        Kernel:   <kernel release>
        U  |        CPU:      <cpu model>
      / --- \       CPUs:     <online CPUs>/<total CPUs>
     ( |   | |      Mem:      <used memory>/<total memory>
   |\\_)___/\)/\    Procs:    <total processes>
  <__)------(__/    Uptime:   <uptime> ms
*/
    char* hostname = "sh.haha.com";

    strcat(buf, "                    ");
    strcat(buf, hostname);
    strcat(buf, "\n");
    strcat(buf, "        .-.         ");
    for (int i = 0; i < strlen(hostname); i++) {
        strcat(buf, "-");
    }
    strcat(buf, "\n");
    strcat(buf, "       (-- |        ");
    next_victim(buf);
    strcat(buf, "\n");
    strcat(buf, "        U  |        ");
    next_victim(buf);
    strcat(buf, "\n");
    strcat(buf, "      / --- \\       ");
    next_victim(buf);
    strcat(buf, "\n");
    strcat(buf, "     ( |   | |      ");
    next_victim(buf);
    strcat(buf, "\n");
    strcat(buf, "   |\\_)___/\\)/\\     ");
    next_victim(buf);
    strcat(buf, "\n");
    strcat(buf, "  <__)------(__/    ");
    next_victim(buf);
    strcat(buf, "\n");
}

static void next_victim(char* buf)
{
    // go through the info array and find the first present info
    for (int i = 0; i < KFETCH_NUM_INFO; i++) {
        if (info[i].present) {
            strcat(buf, info[i].str);
            info[i].present = false;
            return;
        }
    }
}

static void kernel_release(char* buf)
{
    sprintf(buf, "Kernel:   %s", utsname()->release);
}

static void cpu_model(char* buf) {
    sprintf(buf, "CPU:      Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz");
}

static void num_cpus(char* buf) {
    sprintf(buf, "CPUs:     %u / %u", num_online_cpus(), num_possible_cpus());
}

static void mem(char* buf) {
    struct sysinfo i;
    si_meminfo(&i);
    sprintf(buf, "Mem:      %lu / %lu MB", i.freeram >> 10, i.totalram >> 10);
}

static void num_procs(char* buf)
{
    // sprintf(buf, "Procs:    %u", get_nr_threads());
    sprintf(buf, "Procs:    temp");
}

static void uptime(char* buf) {
    struct timespec64 uptime;
    long uptime_min;
    ktime_get_boottime_ts64(&uptime);
    uptime_min = div_u64(uptime.tv_sec, 60);
    sprintf(buf, "Uptime:   %ld mins", uptime_min);
}

module_init(kfetch_init);
module_exit(kfetch_exit);

MODULE_LICENSE("GPL");
