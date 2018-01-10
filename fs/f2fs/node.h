/*
 * fs/f2fs/node.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
/* start node id of a node block dedicated to the given node id */
#define	START_NID(nid) ((nid / NAT_ENTRY_PER_BLOCK) * NAT_ENTRY_PER_BLOCK)

/* node block offset on the NAT area dedicated to the given start node id */
#define	NAT_BLOCK_OFFSET(start_nid) (start_nid / NAT_ENTRY_PER_BLOCK)

/* # of pages to perform readahead before building free nids */
#define FREE_NID_PAGES 4

<<<<<<< HEAD
/* maximum readahead size for node during getting data blocks */
#define MAX_RA_NODE		128

/* control the memory footprint threshold (10MB per 1GB ram) */
#define DEF_RAM_THRESHOLD	10

/* vector size for gang look-up from nat cache that consists of radix tree */
#define NATVEC_SIZE	64
#define SETVEC_SIZE	32
=======
/* maximum # of free node ids to produce during build_free_nids */
#define MAX_FREE_NIDS (NAT_ENTRY_PER_BLOCK * FREE_NID_PAGES)

/* maximum readahead size for node during getting data blocks */
#define MAX_RA_NODE		128

/* maximum cached nat entries to manage memory footprint */
#define NM_WOUT_THRESHOLD	(64 * NAT_ENTRY_PER_BLOCK)

/* vector size for gang look-up from nat cache that consists of radix tree */
#define NATVEC_SIZE	64
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c

/* return value for read_node_page */
#define LOCKED_PAGE	1

<<<<<<< HEAD
/* For flag in struct node_info */
enum {
	IS_CHECKPOINTED,	/* is it checkpointed before? */
	HAS_FSYNCED_INODE,	/* is the inode fsynced before? */
	HAS_LAST_FSYNC,		/* has the latest node fsync mark? */
	IS_DIRTY,		/* this nat entry is dirty? */
};

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
/*
 * For node information
 */
struct node_info {
	nid_t nid;		/* node id */
	nid_t ino;		/* inode number of the node's owner */
	block_t	blk_addr;	/* block address of the node */
	unsigned char version;	/* version of the node */
<<<<<<< HEAD
	unsigned char flag;	/* for node information bits */
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
};

struct nat_entry {
	struct list_head list;	/* for clean or dirty nat list */
<<<<<<< HEAD
=======
	bool checkpointed;	/* whether it is checkpointed or not */
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	struct node_info ni;	/* in-memory node information */
};

#define nat_get_nid(nat)		(nat->ni.nid)
#define nat_set_nid(nat, n)		(nat->ni.nid = n)
#define nat_get_blkaddr(nat)		(nat->ni.blk_addr)
#define nat_set_blkaddr(nat, b)		(nat->ni.blk_addr = b)
#define nat_get_ino(nat)		(nat->ni.ino)
#define nat_set_ino(nat, i)		(nat->ni.ino = i)
#define nat_get_version(nat)		(nat->ni.version)
#define nat_set_version(nat, v)		(nat->ni.version = v)

<<<<<<< HEAD
#define inc_node_version(version)	(++version)

static inline void copy_node_info(struct node_info *dst,
						struct node_info *src)
{
	dst->nid = src->nid;
	dst->ino = src->ino;
	dst->blk_addr = src->blk_addr;
	dst->version = src->version;
	/* should not copy flag here */
}

static inline void set_nat_flag(struct nat_entry *ne,
				unsigned int type, bool set)
{
	unsigned char mask = 0x01 << type;
	if (set)
		ne->ni.flag |= mask;
	else
		ne->ni.flag &= ~mask;
}

static inline bool get_nat_flag(struct nat_entry *ne, unsigned int type)
{
	unsigned char mask = 0x01 << type;
	return ne->ni.flag & mask;
}

static inline void nat_reset_flag(struct nat_entry *ne)
{
	/* these states can be set only after checkpoint was done */
	set_nat_flag(ne, IS_CHECKPOINTED, true);
	set_nat_flag(ne, HAS_FSYNCED_INODE, false);
	set_nat_flag(ne, HAS_LAST_FSYNC, true);
}

=======
#define __set_nat_cache_dirty(nm_i, ne)					\
	list_move_tail(&ne->list, &nm_i->dirty_nat_entries);
#define __clear_nat_cache_dirty(nm_i, ne)				\
	list_move_tail(&ne->list, &nm_i->nat_entries);
#define inc_node_version(version)	(++version)

>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
static inline void node_info_from_raw_nat(struct node_info *ni,
						struct f2fs_nat_entry *raw_ne)
{
	ni->ino = le32_to_cpu(raw_ne->ino);
	ni->blk_addr = le32_to_cpu(raw_ne->block_addr);
	ni->version = raw_ne->version;
}

<<<<<<< HEAD
static inline void raw_nat_from_node_info(struct f2fs_nat_entry *raw_ne,
						struct node_info *ni)
{
	raw_ne->ino = cpu_to_le32(ni->ino);
	raw_ne->block_addr = cpu_to_le32(ni->blk_addr);
	raw_ne->version = ni->version;
}

enum mem_type {
	FREE_NIDS,	/* indicates the free nid list */
	NAT_ENTRIES,	/* indicates the cached nat entry */
	DIRTY_DENTS,	/* indicates dirty dentry pages */
	INO_ENTRIES,	/* indicates inode entries */
	EXTENT_CACHE,	/* indicates extent cache */
	BASE_CHECK,	/* check kernel status */
};

struct nat_entry_set {
	struct list_head set_list;	/* link with other nat sets */
	struct list_head entry_list;	/* link with dirty nat entries */
	nid_t set;			/* set number*/
	unsigned int entry_cnt;		/* the # of nat entries in set */
};

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
/*
 * For free nid mangement
 */
enum nid_state {
	NID_NEW,	/* newly added to free nid list */
	NID_ALLOC	/* it is allocated */
};

struct free_nid {
	struct list_head list;	/* for free node id list */
	nid_t nid;		/* node id */
	int state;		/* in use or not: NID_NEW or NID_ALLOC */
};

<<<<<<< HEAD
static inline void next_free_nid(struct f2fs_sb_info *sbi, nid_t *nid)
=======
static inline int next_free_nid(struct f2fs_sb_info *sbi, nid_t *nid)
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct free_nid *fnid;

<<<<<<< HEAD
	spin_lock(&nm_i->free_nid_list_lock);
	if (nm_i->fcnt <= 0) {
		spin_unlock(&nm_i->free_nid_list_lock);
		return;
	}
	fnid = list_entry(nm_i->free_nid_list.next, struct free_nid, list);
	*nid = fnid->nid;
	spin_unlock(&nm_i->free_nid_list_lock);
=======
	if (nm_i->fcnt <= 0)
		return -1;
	spin_lock(&nm_i->free_nid_list_lock);
	fnid = list_entry(nm_i->free_nid_list.next, struct free_nid, list);
	*nid = fnid->nid;
	spin_unlock(&nm_i->free_nid_list_lock);
	return 0;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
}

/*
 * inline functions
 */
static inline void get_nat_bitmap(struct f2fs_sb_info *sbi, void *addr)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	memcpy(addr, nm_i->nat_bitmap, nm_i->bitmap_size);
}

static inline pgoff_t current_nat_addr(struct f2fs_sb_info *sbi, nid_t start)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	pgoff_t block_off;
	pgoff_t block_addr;
	int seg_off;

	block_off = NAT_BLOCK_OFFSET(start);
	seg_off = block_off >> sbi->log_blocks_per_seg;

	block_addr = (pgoff_t)(nm_i->nat_blkaddr +
		(seg_off << sbi->log_blocks_per_seg << 1) +
		(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

	if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
		block_addr += sbi->blocks_per_seg;

	return block_addr;
}

static inline pgoff_t next_nat_addr(struct f2fs_sb_info *sbi,
						pgoff_t block_addr)
{
	struct f2fs_nm_info *nm_i = NM_I(sbi);

	block_addr -= nm_i->nat_blkaddr;
	if ((block_addr >> sbi->log_blocks_per_seg) % 2)
		block_addr -= sbi->blocks_per_seg;
	else
		block_addr += sbi->blocks_per_seg;

	return block_addr + nm_i->nat_blkaddr;
}

static inline void set_to_next_nat(struct f2fs_nm_info *nm_i, nid_t start_nid)
{
	unsigned int block_off = NAT_BLOCK_OFFSET(start_nid);

<<<<<<< HEAD
	f2fs_change_bit(block_off, nm_i->nat_bitmap);
=======
	if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
		f2fs_clear_bit(block_off, nm_i->nat_bitmap);
	else
		f2fs_set_bit(block_off, nm_i->nat_bitmap);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
}

static inline void fill_node_footer(struct page *page, nid_t nid,
				nid_t ino, unsigned int ofs, bool reset)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(page);
	unsigned int old_flag = 0;

	if (reset)
		memset(rn, 0, sizeof(*rn));
	else
		old_flag = le32_to_cpu(rn->footer.flag);

	rn->footer.nid = cpu_to_le32(nid);
	rn->footer.ino = cpu_to_le32(ino);

	/* should remain old flag bits such as COLD_BIT_SHIFT */
	rn->footer.flag = cpu_to_le32((ofs << OFFSET_BIT_SHIFT) |
					(old_flag & OFFSET_BIT_MASK));
=======
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	if (reset)
		memset(rn, 0, sizeof(*rn));
	rn->footer.nid = cpu_to_le32(nid);
	rn->footer.ino = cpu_to_le32(ino);
	rn->footer.flag = cpu_to_le32(ofs << OFFSET_BIT_SHIFT);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
}

static inline void copy_node_footer(struct page *dst, struct page *src)
{
<<<<<<< HEAD
	struct f2fs_node *src_rn = F2FS_NODE(src);
	struct f2fs_node *dst_rn = F2FS_NODE(dst);
=======
	void *src_addr = page_address(src);
	void *dst_addr = page_address(dst);
	struct f2fs_node *src_rn = (struct f2fs_node *)src_addr;
	struct f2fs_node *dst_rn = (struct f2fs_node *)dst_addr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	memcpy(&dst_rn->footer, &src_rn->footer, sizeof(struct node_footer));
}

static inline void fill_node_footer_blkaddr(struct page *page, block_t blkaddr)
{
<<<<<<< HEAD
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(F2FS_P_SB(page));
	struct f2fs_node *rn = F2FS_NODE(page);

=======
	struct f2fs_sb_info *sbi = F2FS_SB(page->mapping->host->i_sb);
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	rn->footer.cp_ver = ckpt->checkpoint_ver;
	rn->footer.next_blkaddr = cpu_to_le32(blkaddr);
}

static inline nid_t ino_of_node(struct page *node_page)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(node_page);
=======
	void *kaddr = page_address(node_page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	return le32_to_cpu(rn->footer.ino);
}

static inline nid_t nid_of_node(struct page *node_page)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(node_page);
=======
	void *kaddr = page_address(node_page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	return le32_to_cpu(rn->footer.nid);
}

static inline unsigned int ofs_of_node(struct page *node_page)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(node_page);
=======
	void *kaddr = page_address(node_page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	unsigned flag = le32_to_cpu(rn->footer.flag);
	return flag >> OFFSET_BIT_SHIFT;
}

static inline unsigned long long cpver_of_node(struct page *node_page)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(node_page);
=======
	void *kaddr = page_address(node_page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	return le64_to_cpu(rn->footer.cp_ver);
}

static inline block_t next_blkaddr_of_node(struct page *node_page)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(node_page);
=======
	void *kaddr = page_address(node_page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	return le32_to_cpu(rn->footer.next_blkaddr);
}

/*
 * f2fs assigns the following node offsets described as (num).
 * N = NIDS_PER_BLOCK
 *
 *  Inode block (0)
 *    |- direct node (1)
 *    |- direct node (2)
 *    |- indirect node (3)
 *    |            `- direct node (4 => 4 + N - 1)
 *    |- indirect node (4 + N)
 *    |            `- direct node (5 + N => 5 + 2N - 1)
 *    `- double indirect node (5 + 2N)
 *                 `- indirect node (6 + 2N)
<<<<<<< HEAD
 *                       `- direct node
 *                 ......
 *                 `- indirect node ((6 + 2N) + x(N + 1))
 *                       `- direct node
 *                 ......
 *                 `- indirect node ((6 + 2N) + (N - 1)(N + 1))
 *                       `- direct node
=======
 *                       `- direct node (x(N + 1))
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 */
static inline bool IS_DNODE(struct page *node_page)
{
	unsigned int ofs = ofs_of_node(node_page);
<<<<<<< HEAD

	if (f2fs_has_xattr_block(ofs))
		return false;

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (ofs == 3 || ofs == 4 + NIDS_PER_BLOCK ||
			ofs == 5 + 2 * NIDS_PER_BLOCK)
		return false;
	if (ofs >= 6 + 2 * NIDS_PER_BLOCK) {
		ofs -= 6 + 2 * NIDS_PER_BLOCK;
		if (!((long int)ofs % (NIDS_PER_BLOCK + 1)))
			return false;
	}
	return true;
}

static inline void set_nid(struct page *p, int off, nid_t nid, bool i)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(p);

	f2fs_wait_on_page_writeback(p, NODE);
=======
	struct f2fs_node *rn = (struct f2fs_node *)page_address(p);

	wait_on_page_writeback(p);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c

	if (i)
		rn->i.i_nid[off - NODE_DIR1_BLOCK] = cpu_to_le32(nid);
	else
		rn->in.nid[off] = cpu_to_le32(nid);
	set_page_dirty(p);
}

static inline nid_t get_nid(struct page *p, int off, bool i)
{
<<<<<<< HEAD
	struct f2fs_node *rn = F2FS_NODE(p);

=======
	struct f2fs_node *rn = (struct f2fs_node *)page_address(p);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (i)
		return le32_to_cpu(rn->i.i_nid[off - NODE_DIR1_BLOCK]);
	return le32_to_cpu(rn->in.nid[off]);
}

/*
 * Coldness identification:
 *  - Mark cold files in f2fs_inode_info
 *  - Mark cold node blocks in their node footer
 *  - Mark cold data pages in page cache
 */
<<<<<<< HEAD
=======
static inline int is_cold_file(struct inode *inode)
{
	return F2FS_I(inode)->i_advise & FADVISE_COLD_BIT;
}

static inline void set_cold_file(struct inode *inode)
{
	F2FS_I(inode)->i_advise |= FADVISE_COLD_BIT;
}

static inline int is_cp_file(struct inode *inode)
{
	return F2FS_I(inode)->i_advise & FADVISE_CP_BIT;
}

static inline void set_cp_file(struct inode *inode)
{
	F2FS_I(inode)->i_advise |= FADVISE_CP_BIT;
}

>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
static inline int is_cold_data(struct page *page)
{
	return PageChecked(page);
}

static inline void set_cold_data(struct page *page)
{
	SetPageChecked(page);
}

static inline void clear_cold_data(struct page *page)
{
	ClearPageChecked(page);
}

<<<<<<< HEAD
static inline int is_node(struct page *page, int type)
{
	struct f2fs_node *rn = F2FS_NODE(page);
	return le32_to_cpu(rn->footer.flag) & (1 << type);
}

#define is_cold_node(page)	is_node(page, COLD_BIT_SHIFT)
#define is_fsync_dnode(page)	is_node(page, FSYNC_BIT_SHIFT)
#define is_dent_dnode(page)	is_node(page, DENT_BIT_SHIFT)

static inline void set_cold_node(struct inode *inode, struct page *page)
{
	struct f2fs_node *rn = F2FS_NODE(page);
=======
static inline int is_cold_node(struct page *page)
{
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	return flag & (0x1 << COLD_BIT_SHIFT);
}

static inline unsigned char is_fsync_dnode(struct page *page)
{
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	return flag & (0x1 << FSYNC_BIT_SHIFT);
}

static inline unsigned char is_dent_dnode(struct page *page)
{
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	return flag & (0x1 << DENT_BIT_SHIFT);
}

static inline void set_cold_node(struct inode *inode, struct page *page)
{
	struct f2fs_node *rn = (struct f2fs_node *)page_address(page);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	unsigned int flag = le32_to_cpu(rn->footer.flag);

	if (S_ISDIR(inode->i_mode))
		flag &= ~(0x1 << COLD_BIT_SHIFT);
	else
		flag |= (0x1 << COLD_BIT_SHIFT);
	rn->footer.flag = cpu_to_le32(flag);
}

<<<<<<< HEAD
static inline void set_mark(struct page *page, int mark, int type)
{
	struct f2fs_node *rn = F2FS_NODE(page);
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	if (mark)
		flag |= (0x1 << type);
	else
		flag &= ~(0x1 << type);
	rn->footer.flag = cpu_to_le32(flag);
}
#define set_dentry_mark(page, mark)	set_mark(page, mark, DENT_BIT_SHIFT)
#define set_fsync_mark(page, mark)	set_mark(page, mark, FSYNC_BIT_SHIFT)
=======
static inline void set_fsync_mark(struct page *page, int mark)
{
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	if (mark)
		flag |= (0x1 << FSYNC_BIT_SHIFT);
	else
		flag &= ~(0x1 << FSYNC_BIT_SHIFT);
	rn->footer.flag = cpu_to_le32(flag);
}

static inline void set_dentry_mark(struct page *page, int mark)
{
	void *kaddr = page_address(page);
	struct f2fs_node *rn = (struct f2fs_node *)kaddr;
	unsigned int flag = le32_to_cpu(rn->footer.flag);
	if (mark)
		flag |= (0x1 << DENT_BIT_SHIFT);
	else
		flag &= ~(0x1 << DENT_BIT_SHIFT);
	rn->footer.flag = cpu_to_le32(flag);
}
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
