   // SPDX-License-Identifier: GPL-2.0
   #include <linux/fs.h>
   #include <linux/init.h>
   #include <linux/kernel.h>
   #include <linux/proc_fs.h>
   #include <linux/seq_file.h>
   #include <linux/string.h>
   #include <linux/utsname.h>

   extern bool uname_should_spoof(void);

   static int version_proc_show(struct seq_file *m, void *v)
   {
   	char rel[sizeof(utsname()->release)];
   	const char *release = utsname()->release;

   	if (uname_should_spoof()) {
   		const char *suffix = strchr(release, '-');

   		scnprintf(rel, sizeof(rel), "5.4.191%s", suffix ? suffix : "");
   		release = rel;
   	}

   	seq_printf(m, linux_proc_banner,
   		utsname()->sysname,
   		release,
   		utsname()->version);
   	return 0;
   }

   static int __init proc_version_init(void)
   {
   	proc_create_single("version", 0, NULL, version_proc_show);
   	return 0;
   }
   fs_initcall(proc_version_init);
