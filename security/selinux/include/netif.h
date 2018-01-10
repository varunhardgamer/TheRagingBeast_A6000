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
 *                    Paul Moore <paul@paul-moore.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */
#ifndef _SELINUX_NETIF_H_
#define _SELINUX_NETIF_H_

<<<<<<< HEAD
#include <net/net_namespace.h>

void sel_netif_flush(void);

int sel_netif_sid(struct net *ns, int ifindex, u32 *sid);
=======
void sel_netif_flush(void);

int sel_netif_sid(int ifindex, u32 *sid);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c

#endif	/* _SELINUX_NETIF_H_ */

