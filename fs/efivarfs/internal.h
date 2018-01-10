/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef EFIVAR_FS_INTERNAL_H
#define EFIVAR_FS_INTERNAL_H

#include <linux/list.h>

extern const struct file_operations efivarfs_file_operations;
extern const struct inode_operations efivarfs_dir_inode_operations;
extern bool efivarfs_valid_name(const char *str, int len);
extern struct inode *efivarfs_get_inode(struct super_block *sb,
<<<<<<< HEAD
			const struct inode *dir, int mode, dev_t dev,
			bool is_removable);
=======
			const struct inode *dir, int mode, dev_t dev);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c

extern struct list_head efivarfs_list;

#endif /* EFIVAR_FS_INTERNAL_H */
