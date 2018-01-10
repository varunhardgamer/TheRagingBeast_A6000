#ifndef _INET_DIAG_H_
#define _INET_DIAG_H_ 1

#include <uapi/linux/inet_diag.h>

<<<<<<< HEAD
struct net;
=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
struct sock;
struct inet_hashinfo;
struct nlattr;
struct nlmsghdr;
struct sk_buff;
struct netlink_callback;

struct inet_diag_handler {
	void			(*dump)(struct sk_buff *skb,
					struct netlink_callback *cb,
					struct inet_diag_req_v2 *r,
					struct nlattr *bc);

	int			(*dump_one)(struct sk_buff *in_skb,
					const struct nlmsghdr *nlh,
					struct inet_diag_req_v2 *req);

	void			(*idiag_get_info)(struct sock *sk,
						  struct inet_diag_msg *r,
						  void *info);
<<<<<<< HEAD

	int			(*destroy)(struct sk_buff *in_skb,
					   struct inet_diag_req_v2 *req);

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
	__u16                   idiag_type;
};

struct inet_connection_sock;
int inet_sk_diag_fill(struct sock *sk, struct inet_connection_sock *icsk,
			      struct sk_buff *skb, struct inet_diag_req_v2 *req,
			      struct user_namespace *user_ns,
			      u32 pid, u32 seq, u16 nlmsg_flags,
<<<<<<< HEAD
			      const struct nlmsghdr *unlh, bool net_admin);
=======
			      const struct nlmsghdr *unlh);
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
void inet_diag_dump_icsk(struct inet_hashinfo *h, struct sk_buff *skb,
		struct netlink_callback *cb, struct inet_diag_req_v2 *r,
		struct nlattr *bc);
int inet_diag_dump_one_icsk(struct inet_hashinfo *hashinfo,
		struct sk_buff *in_skb, const struct nlmsghdr *nlh,
		struct inet_diag_req_v2 *req);

<<<<<<< HEAD
struct sock *inet_diag_find_one_icsk(struct net *net,
				     struct inet_hashinfo *hashinfo,
				     struct inet_diag_req_v2 *req);

=======
>>>>>>> 146ce814822a0d5a65e6449572d9afc6e6c08b7c
int inet_diag_bc_sk(const struct nlattr *_bc, struct sock *sk);

extern int  inet_diag_register(const struct inet_diag_handler *handler);
extern void inet_diag_unregister(const struct inet_diag_handler *handler);
#endif /* _INET_DIAG_H_ */
