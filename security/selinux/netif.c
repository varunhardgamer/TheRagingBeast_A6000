/*
 * Network interface table.
 *
 * Network interfaces (devices) do not have a security field, so we
 * maintain a table associating each interface with a SID.
 *
 * Author: James Morris <jmorris@redhat.com>
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 * Copyright (C) 2007 Hewlett-Packard Development Company, L.P.
 *		      Paul Moore <paul@paul-moore.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>

#include "security.h"
#include "objsec.h"
#include "netif.h"
#include "avc.h"

#define SEL_NETIF_HASH_SIZE	64
#define SEL_NETIF_HASH_MAX	1024

struct sel_netif {
	struct list_head list;
	struct netif_security_struct nsec;
	struct rcu_head rcu_head;
};

static u32 sel_netif_total;
static LIST_HEAD(sel_netif_list);
static DEFINE_SPINLOCK(sel_netif_lock);
static struct list_head sel_netif_hash[SEL_NETIF_HASH_SIZE];

/**
 * sel_netif_hashfn - Hashing function for the interface table
<<<<<<< HEAD
 * @ns: the network namespace
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 * @ifindex: the network interface
 *
 * Description:
 * This is the hashing function for the network interface table, it returns the
 * bucket number for the given interface.
 *
 */
<<<<<<< HEAD
static inline u32 sel_netif_hashfn(const struct net *ns, int ifindex)
{
	return (((uintptr_t)ns + ifindex) & (SEL_NETIF_HASH_SIZE - 1));
=======
static inline u32 sel_netif_hashfn(int ifindex)
{
	return (ifindex & (SEL_NETIF_HASH_SIZE - 1));
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
}

/**
 * sel_netif_find - Search for an interface record
<<<<<<< HEAD
 * @ns: the network namespace
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 * @ifindex: the network interface
 *
 * Description:
 * Search the network interface table and return the record matching @ifindex.
 * If an entry can not be found in the table return NULL.
 *
 */
<<<<<<< HEAD
static inline struct sel_netif *sel_netif_find(const struct net *ns,
					       int ifindex)
{
	int idx = sel_netif_hashfn(ns, ifindex);
	struct sel_netif *netif;

	list_for_each_entry_rcu(netif, &sel_netif_hash[idx], list)
		if (net_eq(netif->nsec.ns, ns) &&
		    netif->nsec.ifindex == ifindex)
=======
static inline struct sel_netif *sel_netif_find(int ifindex)
{
	int idx = sel_netif_hashfn(ifindex);
	struct sel_netif *netif;

	list_for_each_entry_rcu(netif, &sel_netif_hash[idx], list)
		/* all of the devices should normally fit in the hash, so we
		 * optimize for that case */
		if (likely(netif->nsec.ifindex == ifindex))
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
			return netif;

	return NULL;
}

/**
 * sel_netif_insert - Insert a new interface into the table
 * @netif: the new interface record
 *
 * Description:
 * Add a new interface record to the network interface hash table.  Returns
 * zero on success, negative values on failure.
 *
 */
static int sel_netif_insert(struct sel_netif *netif)
{
	int idx;

	if (sel_netif_total >= SEL_NETIF_HASH_MAX)
		return -ENOSPC;

<<<<<<< HEAD
	idx = sel_netif_hashfn(netif->nsec.ns, netif->nsec.ifindex);
=======
	idx = sel_netif_hashfn(netif->nsec.ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	list_add_rcu(&netif->list, &sel_netif_hash[idx]);
	sel_netif_total++;

	return 0;
}

/**
 * sel_netif_destroy - Remove an interface record from the table
 * @netif: the existing interface record
 *
 * Description:
 * Remove an existing interface record from the network interface table.
 *
 */
static void sel_netif_destroy(struct sel_netif *netif)
{
	list_del_rcu(&netif->list);
	sel_netif_total--;
	kfree_rcu(netif, rcu_head);
}

/**
 * sel_netif_sid_slow - Lookup the SID of a network interface using the policy
<<<<<<< HEAD
 * @ns: the network namespace
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 * @ifindex: the network interface
 * @sid: interface SID
 *
 * Description:
 * This function determines the SID of a network interface by quering the
 * security policy.  The result is added to the network interface table to
 * speedup future queries.  Returns zero on success, negative values on
 * failure.
 *
 */
<<<<<<< HEAD
static int sel_netif_sid_slow(struct net *ns, int ifindex, u32 *sid)
=======
static int sel_netif_sid_slow(int ifindex, u32 *sid)
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
{
	int ret;
	struct sel_netif *netif;
	struct sel_netif *new = NULL;
	struct net_device *dev;

	/* NOTE: we always use init's network namespace since we don't
	 * currently support containers */

<<<<<<< HEAD
	dev = dev_get_by_index(ns, ifindex);
=======
	dev = dev_get_by_index(&init_net, ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (unlikely(dev == NULL)) {
		printk(KERN_WARNING
		       "SELinux: failure in sel_netif_sid_slow(),"
		       " invalid network interface (%d)\n", ifindex);
		return -ENOENT;
	}

	spin_lock_bh(&sel_netif_lock);
<<<<<<< HEAD
	netif = sel_netif_find(ns, ifindex);
=======
	netif = sel_netif_find(ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (netif != NULL) {
		*sid = netif->nsec.sid;
		ret = 0;
		goto out;
	}
	new = kzalloc(sizeof(*new), GFP_ATOMIC);
	if (new == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	ret = security_netif_sid(dev->name, &new->nsec.sid);
	if (ret != 0)
		goto out;
<<<<<<< HEAD
	new->nsec.ns = ns;
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	new->nsec.ifindex = ifindex;
	ret = sel_netif_insert(new);
	if (ret != 0)
		goto out;
	*sid = new->nsec.sid;

out:
	spin_unlock_bh(&sel_netif_lock);
	dev_put(dev);
	if (unlikely(ret)) {
		printk(KERN_WARNING
		       "SELinux: failure in sel_netif_sid_slow(),"
		       " unable to determine network interface label (%d)\n",
		       ifindex);
		kfree(new);
	}
	return ret;
}

/**
 * sel_netif_sid - Lookup the SID of a network interface
<<<<<<< HEAD
 * @ns: the network namespace
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 * @ifindex: the network interface
 * @sid: interface SID
 *
 * Description:
 * This function determines the SID of a network interface using the fastest
 * method possible.  First the interface table is queried, but if an entry
 * can't be found then the policy is queried and the result is added to the
 * table to speedup future queries.  Returns zero on success, negative values
 * on failure.
 *
 */
<<<<<<< HEAD
int sel_netif_sid(struct net *ns, int ifindex, u32 *sid)
=======
int sel_netif_sid(int ifindex, u32 *sid)
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
{
	struct sel_netif *netif;

	rcu_read_lock();
<<<<<<< HEAD
	netif = sel_netif_find(ns, ifindex);
=======
	netif = sel_netif_find(ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (likely(netif != NULL)) {
		*sid = netif->nsec.sid;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

<<<<<<< HEAD
	return sel_netif_sid_slow(ns, ifindex, sid);
=======
	return sel_netif_sid_slow(ifindex, sid);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
}

/**
 * sel_netif_kill - Remove an entry from the network interface table
<<<<<<< HEAD
 * @ns: the network namespace
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
 * @ifindex: the network interface
 *
 * Description:
 * This function removes the entry matching @ifindex from the network interface
 * table if it exists.
 *
 */
<<<<<<< HEAD
static void sel_netif_kill(const struct net *ns, int ifindex)
=======
static void sel_netif_kill(int ifindex)
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
{
	struct sel_netif *netif;

	rcu_read_lock();
	spin_lock_bh(&sel_netif_lock);
<<<<<<< HEAD
	netif = sel_netif_find(ns, ifindex);
=======
	netif = sel_netif_find(ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	if (netif)
		sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
	rcu_read_unlock();
}

/**
 * sel_netif_flush - Flush the entire network interface table
 *
 * Description:
 * Remove all entries from the network interface table.
 *
 */
void sel_netif_flush(void)
{
	int idx;
	struct sel_netif *netif;

	spin_lock_bh(&sel_netif_lock);
	for (idx = 0; idx < SEL_NETIF_HASH_SIZE; idx++)
		list_for_each_entry(netif, &sel_netif_hash[idx], list)
			sel_netif_destroy(netif);
	spin_unlock_bh(&sel_netif_lock);
}

static int sel_netif_netdev_notifier_handler(struct notifier_block *this,
					     unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;

<<<<<<< HEAD
	if (event == NETDEV_DOWN)
		sel_netif_kill(dev_net(dev), dev->ifindex);
=======
	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;

	if (event == NETDEV_DOWN)
		sel_netif_kill(dev->ifindex);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c

	return NOTIFY_DONE;
}

static struct notifier_block sel_netif_netdev_notifier = {
	.notifier_call = sel_netif_netdev_notifier_handler,
};

static __init int sel_netif_init(void)
{
	int i, err;

	if (!selinux_enabled)
		return 0;

	for (i = 0; i < SEL_NETIF_HASH_SIZE; i++)
		INIT_LIST_HEAD(&sel_netif_hash[i]);

	register_netdevice_notifier(&sel_netif_netdev_notifier);

	return err;
}

__initcall(sel_netif_init);

