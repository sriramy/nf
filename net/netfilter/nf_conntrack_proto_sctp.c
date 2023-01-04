// SPDX-License-Identifier: GPL-2.0-only
/*
 * Connection tracking protocol helper module for SCTP.
 *
 * Copyright (c) 2004 Kiran Kumar Immidi <immidi_kiran@yahoo.com>
 * Copyright (c) 2004-2012 Patrick McHardy <kaber@trash.net>
 *
 * SCTP is defined in RFC 4960. References to various sections in this code
 * are to this RFC.
 */

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/netfilter.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/sctp/checksum.h>

#include <net/netfilter/nf_log.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_timeout.h>

#define	SCTP_FLAG_HEARTBEAT_VTAG_FAILED	1

static const char *const sctp_conntrack_names[] = {
	"NONE",
	"OPEN_WAIT",
	"ESTABLISHED",
};

#define SECS  * HZ

static const unsigned int sctp_timeouts[SCTP_CONNTRACK_MAX] = {
	[SCTP_CONNTRACK_OPEN_WAIT]			= 3 SECS,
	[SCTP_CONNTRACK_ESTABLISHED]		= 210 SECS,
};

#ifdef CONFIG_NF_CONNTRACK_PROCFS
/* Print out the private part of the conntrack. */
static void sctp_print_conntrack(struct seq_file *s, struct nf_conn *ct)
{
	seq_printf(s, "%s ", sctp_conntrack_names[ct->proto.sctp.state]);
}
#endif

static bool sctp_error(struct sk_buff *skb,
		       unsigned int dataoff,
		       const struct nf_hook_state *state)
{
	const struct sctphdr *sh;
	const char *logmsg;

	if (skb->len < dataoff + sizeof(struct sctphdr)) {
		logmsg = "nf_ct_sctp: short packet ";
		goto out_invalid;
	}
	if (state->hook == NF_INET_PRE_ROUTING &&
	    state->net->ct.sysctl_checksum &&
	    skb->ip_summed == CHECKSUM_NONE) {
		if (skb_ensure_writable(skb, dataoff + sizeof(*sh))) {
			logmsg = "nf_ct_sctp: failed to read header ";
			goto out_invalid;
		}
		sh = (const struct sctphdr *)(skb->data + dataoff);
		if (sh->checksum != sctp_compute_cksum(skb, dataoff)) {
			logmsg = "nf_ct_sctp: bad CRC ";
			goto out_invalid;
		}
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return false;
out_invalid:
	nf_l4proto_log_invalid(skb, state, IPPROTO_SCTP, "%s", logmsg);
	return true;
}

static void sctp_new(struct nf_conn *ct,
		     enum ip_conntrack_info ctinfo,
		     u32 init_vtag,
		     u32 vtag,
		     unsigned long *map)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);

	memset(&ct->proto.sctp, 0, sizeof(ct->proto.sctp));
	ct->proto.sctp.state = SCTP_CONNTRACK_OPEN_WAIT;
	nf_conntrack_event_cache(IPCT_PROTOINFO, ct);

	if (test_bit(SCTP_CID_INIT, map))
		ct->proto.sctp.vtag[!dir] = init_vtag;
	else if (test_bit(SCTP_CID_SHUTDOWN_ACK, map))
		/* If it is a shutdown ack OOTB packet, we expect a return
		 * shutdown complete, otherwise an ABORT Sec 8.4 (5) and (8)
		 */
		ct->proto.sctp.vtag[!dir] = vtag;
	else
		ct->proto.sctp.vtag[dir] = vtag;
}

static bool sctp_vtag_check(struct nf_conn *ct,
			    enum ip_conntrack_info ctinfo,
			    u32 vtag,
			    unsigned long *map,
			    unsigned long *tflags)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);

	/* Check the verification tag (Sec 8.5) */
	if (!test_bit(SCTP_CID_INIT, map) &&
	    !test_bit(SCTP_CID_SHUTDOWN_COMPLETE, map) &&
	    !test_bit(SCTP_CID_COOKIE_ECHO, map) &&
	    !test_bit(SCTP_CID_ABORT, map) &&
	    !test_bit(SCTP_CID_SHUTDOWN_ACK, map) &&
	    !test_bit(SCTP_CID_HEARTBEAT, map) &&
	    !test_bit(SCTP_CID_HEARTBEAT_ACK, map) &&
	    vtag != ct->proto.sctp.vtag[dir]) {
		return false;
	}

	/* Special cases of Verification tag check (Sec 8.5.1) */
	if (test_bit(SCTP_CID_INIT, map)) {
		/* (A) vtag MUST be zero */
		if (vtag != 0)
			return false;
	}
	if (test_bit(SCTP_CID_ABORT, map)) {
		/* (B) vtag MUST match own vtag if T flag is unset OR
		 * MUST match peer's vtag if T flag is set
		 */
		if ((!test_bit(SCTP_CID_ABORT, tflags) &&
		     vtag != ct->proto.sctp.vtag[dir]) ||
		    (test_bit(SCTP_CID_ABORT, tflags) &&
		     vtag != ct->proto.sctp.vtag[!dir]))
			return false;
	}
	if (test_bit(SCTP_CID_SHUTDOWN_COMPLETE, map)) {
		/* (C) vtag MUST match own vtag if T flag is unset OR
		 * MUST match peer's vtag if T flag is set
		 */
		if ((!test_bit(SCTP_CID_SHUTDOWN_COMPLETE, tflags) &&
		     vtag != ct->proto.sctp.vtag[dir]) ||
		    (test_bit(SCTP_CID_SHUTDOWN_COMPLETE, tflags) &&
		     vtag != ct->proto.sctp.vtag[!dir]))
			return false;
	}
	if (test_bit(SCTP_CID_COOKIE_ECHO, map)) {
		/* (D) vtag must be same as init_vtag as found in INIT_ACK */
		if (vtag != ct->proto.sctp.vtag[dir])
			return false;
	}

	return true;
}

#define for_each_sctp_chunk(skb, sch, _sch, offset, dataoff)	\
for ((offset) = (dataoff) + sizeof(struct sctphdr);	\
	((sch) = skb_header_pointer((skb), (offset), sizeof(_sch), &(_sch))) &&	\
	(sch)->length;	\
	(offset) += (ntohs((sch)->length) + 3) & ~3)

/* Returns verdict for packet, or -NF_ACCEPT for invalid. */
int nf_conntrack_sctp_packet(struct nf_conn *ct,
			     struct sk_buff *skb,
			     unsigned int dataoff,
			     enum ip_conntrack_info ctinfo,
			     const struct nf_hook_state *state)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned long map[256 / sizeof(unsigned long)] = { 0 };
	unsigned long tflags[256 / sizeof(unsigned long)] = { 0 };
	unsigned int *timeouts;
	u32 init_vtag = 0;
	u32 offset, count;
	struct sctphdr _sctph, *sctph;
	struct sctp_chunkhdr _sch, *sch;

	if (sctp_error(skb, dataoff, state))
		return -NF_ACCEPT;

	sctph = skb_header_pointer(skb, dataoff, sizeof(_sctph), &_sctph);
	if (!sctph)
		return -NF_ACCEPT;

	for_each_sctp_chunk (skb, sch, _sch, offset, dataoff) {
		set_bit(sch->type, map);
		if (sch->flags & SCTP_CHUNK_FLAG_T)
			set_bit(sch->type, tflags);

		if (sch->type == SCTP_CID_INIT ||
		    sch->type == SCTP_CID_INIT_ACK) {
			struct sctp_inithdr _inith, *inith;

			inith = skb_header_pointer(skb, offset + sizeof(_sch),
						   sizeof(_inith), &_inith);
			if (inith)
				init_vtag = inith->init_tag;
			else
				return -NF_ACCEPT;
		}
	}

	if (!nf_ct_is_confirmed(ct)) {
		/* If an OOTB packet has any of these chunks discard (Sec 8.4) */
		if (test_bit(SCTP_CID_ABORT, map) ||
		    test_bit(SCTP_CID_SHUTDOWN_COMPLETE, map) ||
		    test_bit(SCTP_CID_COOKIE_ACK, map))
			return -NF_ACCEPT;

		sctp_new(ct, ctinfo, init_vtag, sctph->vtag, map);
		goto out;
	}

	/* don't renew timeout on init retransmit so
	 * port reuse by client or NAT middlebox cannot
	 * keep entry alive indefinitely (incl. nat info).
	 */
	if (test_bit(SCTP_CID_INIT, map))
		return NF_ACCEPT;

	spin_lock_bh(&ct->lock);
	if (!ct->proto.sctp.vtag[!dir] &&
	    test_bit(SCTP_CID_INIT_ACK, map))
		ct->proto.sctp.vtag[!dir] = init_vtag;

	if (!ct->proto.sctp.vtag[dir])
		ct->proto.sctp.vtag[dir] = sctph->vtag;

	/* we have seen traffic both ways, go to established */
	if (dir == IP_CT_DIR_REPLY &&
	    ct->proto.sctp.state == SCTP_CONNTRACK_OPEN_WAIT) {
		ct->proto.sctp.state = SCTP_CONNTRACK_ESTABLISHED;
		nf_conntrack_event_cache(IPCT_PROTOINFO, ct);

		if (!test_and_set_bit(IPS_ASSURED_BIT, &ct->status))
			nf_conntrack_event_cache(IPCT_ASSURED, ct);
	}

	if (test_bit(SCTP_CID_HEARTBEAT, map)) {
		if (sctph->vtag != ct->proto.sctp.vtag[dir]) {
			if (test_bit(SCTP_CID_DATA, map))
				goto out_unlock;

			ct->proto.sctp.flags |= SCTP_FLAG_HEARTBEAT_VTAG_FAILED;
			ct->proto.sctp.last_dir = dir;
		} else if (ct->proto.sctp.flags & SCTP_FLAG_HEARTBEAT_VTAG_FAILED) {
			ct->proto.sctp.flags &= ~SCTP_FLAG_HEARTBEAT_VTAG_FAILED;
		}
	}
	if (test_bit(SCTP_CID_HEARTBEAT_ACK, map)) {
		if (sctph->vtag != ct->proto.sctp.vtag[dir]) {
			if (test_bit(SCTP_CID_DATA, map))
				goto out_unlock;

			if ((ct->proto.sctp.flags & SCTP_FLAG_HEARTBEAT_VTAG_FAILED) == 0 ||
			    ct->proto.sctp.last_dir == dir)
				goto out_unlock;

			ct->proto.sctp.flags &= ~SCTP_FLAG_HEARTBEAT_VTAG_FAILED;
			ct->proto.sctp.vtag[dir] = sctph->vtag;
			ct->proto.sctp.vtag[!dir] = 0;
		} else if (ct->proto.sctp.flags & SCTP_FLAG_HEARTBEAT_VTAG_FAILED) {
			ct->proto.sctp.flags &= ~SCTP_FLAG_HEARTBEAT_VTAG_FAILED;
		}
	}
	spin_unlock_bh(&ct->lock);

	if (!sctp_vtag_check(ct, ctinfo, sctph->vtag, map, tflags)) {
		nf_ct_l4proto_log_invalid(skb, ct, state,
					  "verification tag check failed %x vs (%x: dir %d) and (%x: dir %d)",
					  sctph->vtag, ct->proto.sctp.vtag[dir], dir,
					  ct->proto.sctp.vtag[!dir], !dir);
		return -NF_ACCEPT;
	}

out:
	timeouts = nf_ct_timeout_lookup(ct);
	if (!timeouts)
		timeouts = nf_sctp_pernet(nf_ct_net(ct))->timeouts;

	nf_ct_refresh_acct(ct, ctinfo, skb, timeouts[ct->proto.sctp.state]);

	return NF_ACCEPT;

out_unlock:
	spin_unlock_bh(&ct->lock);
	return -NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int sctp_to_nlattr(struct sk_buff *skb, struct nlattr *nla,
			  struct nf_conn *ct, bool destroy)
{
	struct nlattr *nest_parms;

	spin_lock_bh(&ct->lock);
	nest_parms = nla_nest_start(skb, CTA_PROTOINFO_SCTP);
	if (!nest_parms)
		goto nla_put_failure;

	if (nla_put_u8(skb, CTA_PROTOINFO_SCTP_STATE, ct->proto.sctp.state))
		goto nla_put_failure;

	if (destroy)
		goto skip_state;

	if (nla_put_be32(skb, CTA_PROTOINFO_SCTP_VTAG_ORIGINAL,
			 ct->proto.sctp.vtag[IP_CT_DIR_ORIGINAL]) ||
	    nla_put_be32(skb, CTA_PROTOINFO_SCTP_VTAG_REPLY,
			 ct->proto.sctp.vtag[IP_CT_DIR_REPLY]))
		goto nla_put_failure;

skip_state:
	spin_unlock_bh(&ct->lock);
	nla_nest_end(skb, nest_parms);

	return 0;

nla_put_failure:
	spin_unlock_bh(&ct->lock);
	return -1;
}

static const struct nla_policy sctp_nla_policy[CTA_PROTOINFO_SCTP_MAX+1] = {
	[CTA_PROTOINFO_SCTP_STATE]	    = { .type = NLA_U8 },
	[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL]  = { .type = NLA_U32 },
	[CTA_PROTOINFO_SCTP_VTAG_REPLY]     = { .type = NLA_U32 },
};

#define SCTP_NLATTR_SIZE ( \
		NLA_ALIGN(NLA_HDRLEN + 1) + \
		NLA_ALIGN(NLA_HDRLEN + 4) + \
		NLA_ALIGN(NLA_HDRLEN + 4))

static int nlattr_to_sctp(struct nlattr *cda[], struct nf_conn *ct)
{
	struct nlattr *attr = cda[CTA_PROTOINFO_SCTP];
	struct nlattr *tb[CTA_PROTOINFO_SCTP_MAX+1];
	int err;

	/* updates may not contain the internal protocol info, skip parsing */
	if (!attr)
		return 0;

	err = nla_parse_nested_deprecated(tb, CTA_PROTOINFO_SCTP_MAX, attr,
					  sctp_nla_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[CTA_PROTOINFO_SCTP_STATE] ||
	    !tb[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL] ||
	    !tb[CTA_PROTOINFO_SCTP_VTAG_REPLY])
		return -EINVAL;

	spin_lock_bh(&ct->lock);
	ct->proto.sctp.state = nla_get_u8(tb[CTA_PROTOINFO_SCTP_STATE]);
	ct->proto.sctp.vtag[IP_CT_DIR_ORIGINAL] =
		nla_get_be32(tb[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL]);
	ct->proto.sctp.vtag[IP_CT_DIR_REPLY] =
		nla_get_be32(tb[CTA_PROTOINFO_SCTP_VTAG_REPLY]);
	spin_unlock_bh(&ct->lock);

	return 0;
}
#endif

#ifdef CONFIG_NF_CONNTRACK_TIMEOUT

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

static int sctp_timeout_nlattr_to_obj(struct nlattr *tb[],
				      struct net *net, void *data)
{
	unsigned int *timeouts = data;
	struct nf_sctp_net *sn = nf_sctp_pernet(net);
	int i;

	if (!timeouts)
		timeouts = sn->timeouts;

	/* set default SCTP timeouts. */
	for (i=0; i<SCTP_CONNTRACK_MAX; i++)
		timeouts[i] = sn->timeouts[i];

	/* there's a 1:1 mapping between attributes and protocol states. */
	for (i=CTA_TIMEOUT_SCTP_UNSPEC+1; i<CTA_TIMEOUT_SCTP_MAX+1; i++) {
		if (tb[i]) {
			timeouts[i] = ntohl(nla_get_be32(tb[i])) * HZ;
		}
	}

	timeouts[CTA_TIMEOUT_SCTP_UNSPEC] = timeouts[CTA_TIMEOUT_SCTP_OPEN_WAIT];
	return 0;
}

static int
sctp_timeout_obj_to_nlattr(struct sk_buff *skb, const void *data)
{
        const unsigned int *timeouts = data;
	int i;

	for (i=CTA_TIMEOUT_SCTP_UNSPEC+1; i<CTA_TIMEOUT_SCTP_MAX+1; i++) {
	        if (nla_put_be32(skb, i, htonl(timeouts[i] / HZ)))
			goto nla_put_failure;
	}
        return 0;

nla_put_failure:
        return -ENOSPC;
}

static const struct nla_policy
sctp_timeout_nla_policy[CTA_TIMEOUT_SCTP_MAX+1] = {
	[CTA_TIMEOUT_SCTP_OPEN_WAIT]		= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_ESTABLISHED]		= { .type = NLA_U32 },
};
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */

void nf_conntrack_sctp_init_net(struct net *net)
{
	struct nf_sctp_net *sn = nf_sctp_pernet(net);
	int i;

	for (i = 0; i < SCTP_CONNTRACK_MAX; i++)
		sn->timeouts[i] = sctp_timeouts[i];

	/* timeouts[0] is unused, init it so ->timeouts[0] contains
	 * 'new' timeout, like udp or icmp.
	 */
	sn->timeouts[0] = sctp_timeouts[SCTP_CONNTRACK_OPEN_WAIT];
}

const struct nf_conntrack_l4proto nf_conntrack_l4proto_sctp = {
	.l4proto 		= IPPROTO_SCTP,
#ifdef CONFIG_NF_CONNTRACK_PROCFS
	.print_conntrack	= sctp_print_conntrack,
#endif
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.nlattr_size		= SCTP_NLATTR_SIZE,
	.to_nlattr		= sctp_to_nlattr,
	.from_nlattr		= nlattr_to_sctp,
	.tuple_to_nlattr	= nf_ct_port_tuple_to_nlattr,
	.nlattr_tuple_size	= nf_ct_port_nlattr_tuple_size,
	.nlattr_to_tuple	= nf_ct_port_nlattr_to_tuple,
	.nla_policy		= nf_ct_port_nla_policy,
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
	.ctnl_timeout		= {
		.nlattr_to_obj	= sctp_timeout_nlattr_to_obj,
		.obj_to_nlattr	= sctp_timeout_obj_to_nlattr,
		.nlattr_max	= CTA_TIMEOUT_SCTP_MAX,
		.obj_size	= sizeof(unsigned int) * SCTP_CONNTRACK_MAX,
		.nla_policy	= sctp_timeout_nla_policy,
	},
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */
};
