/* Updated: Karl MacMillan <kmacmillan@tresys.com>
 *
 *  Added conditional policy language extensions
 *
 *  Updated: Hewlett-Packard <paul@paul-moore.com>
 *
 *  Added support for the policy capability bitmap
 *
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2003 - 2004 Tresys Technology, LLC
 * Copyright (C) 2004 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 2.
 */

#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/security.h>
#include <linux/major.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/audit.h>
#include <linux/uaccess.h>
#include <linux/kobject.h>
#include <linux/ctype.h>

/* selinuxfs pseudo filesystem for exporting the security policy API.
   Based on the proc code and the fs/nfsd/nfsctl.c code. */

#include "flask.h"
#include "avc.h"
#include "avc_ss.h"
#include "security.h"
#include "objsec.h"
#include "conditional.h"

int selinux_enforcing = 0;  // 设置默认宽容模式

enum sel_inos {
    SEL_ROOT_INO = 2,
    SEL_LOAD,    /* load policy */
    SEL_ENFORCE, /* get or set enforcing status */
    SEL_CONTEXT, /* validate context */
    SEL_ACCESS,  /* compute access decision */
    SEL_CREATE,  /* compute create labeling decision */
    SEL_RELABEL, /* compute relabeling decision */
    SEL_USER,    /* compute reachable user contexts */
    SEL_POLICYVERS, /* return policy version for this kernel */
    SEL_COMMIT_BOOLS, /* commit new boolean values */
    SEL_MLS,     /* return if MLS policy is enabled */
    SEL_DISABLE, /* disable SELinux until next reboot */
    SEL_MEMBER,  /* compute polyinstantiation membership decision */
    SEL_CHECKREQPROT, /* check requested protection, not kernel-applied one */
    SEL_COMPAT_NET,   /* whether to use old compat network packet controls */
    SEL_REJECT_UNKNOWN, /* export unknown reject handling to userspace */
    SEL_DENY_UNKNOWN, /* export unknown deny handling to userspace */
    SEL_STATUS,    /* export current status using mmap() */
    SEL_POLICY,    /* allow userspace to read the in kernel policy */
    SEL_VALIDATE_TRANS, /* compute validatetrans decision */
    SEL_INO_NEXT,  /* The next inode number to use */
};

struct selinux_fs_info {
    struct dentry *bool_dir;
    unsigned int bool_num;
    char **bool_pending_names;
    unsigned int *bool_pending_values;
    struct dentry *class_dir;
    unsigned long last_class_ino;
    bool policy_opened;
    struct dentry *policycap_dir;
    struct mutex mutex;
    unsigned long last_ino;
    struct selinux_state *state;
    struct super_block *sb;
};

static int selinux_fs_info_create(struct super_block *sb)
{
    struct selinux_fs_info *fsi;

    fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
    if (!fsi)
        return -ENOMEM;

    mutex_init(&fsi->mutex);
    fsi->last_ino = SEL_INO_NEXT - 1;
    fsi->state = &selinux_state;
    fsi->sb = sb;
    sb->s_fs_info = fsi;
    return 0;
}

static void selinux_fs_info_free(struct super_block *sb)
{
    struct selinux_fs_info *fsi = sb->s_fs_info;
    int i;

    if (fsi) {
        for (i = 0; i < fsi->bool_num; i++)
            kfree(fsi->bool_pending_names[i]);
        kfree(fsi->bool_pending_names);
        kfree(fsi->bool_pending_values);
    }
    kfree(sb->s_fs_info);
    sb->s_fs_info = NULL;
}

#define SEL_INITCON_INO_OFFSET        0x01000000
#define SEL_BOOL_INO_OFFSET        0x02000000
#define SEL_CLASS_INO_OFFSET        0x04000000
#define SEL_POLICYCAP_INO_OFFSET    0x08000000
#define SEL_INO_MASK            0x00ffffff

#define TMPBUFLEN    12
static ssize_t sel_read_enforce(struct file *filp, char __user *buf,
                                size_t count, loff_t *ppos)
{
    struct selinux_fs_info *fsi = file_inode(filp)->i_sb->s_fs_info;
    char tmpbuf[TMPBUFLEN];
    ssize_t length;

    length = scnprintf(tmpbuf, TMPBUFLEN, "%d",
                       enforcing_enabled(fsi->state));
    return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}
