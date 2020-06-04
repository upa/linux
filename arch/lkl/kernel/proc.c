#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/page.h>

static unsigned long mem_start = 0;
static unsigned long mem_size = 0;

static int lkl_proc_mem_start_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lx", mem_start);
	return 0;
}


static int lkl_proc_mem_size_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lx", mem_size);
	return 0;
}

int proc_init(void)
{
	struct proc_dir_entry *proc_lkl;

	obtain_bootmem(&mem_start, &mem_size);

	proc_lkl = proc_mkdir("lkl", NULL);
	if (!proc_lkl) {
		pr_err("proc_mkdir lkl failed\n");
		return -1;
	}

	proc_create_single("mem_start", 0444, proc_lkl,
			   lkl_proc_mem_start_show);
	proc_create_single("mem_size", 0444, proc_lkl,
			   lkl_proc_mem_size_show);

	return 0;
}

void proc_cleanup(void)
{
	/* should proc_remove */
}
