/*
 * https://lwn.net/Articles/330797/
 */

#include <linux/module.h>
#include <linux/types.h>

#include "elb.h"

#include <linux/init.h>
#include <linux/pci.h>

#include <linux/if_ether.h>
#include <linux/if_arp.h>


int dbg_elb_kkai = 0;

static int dbg_kkai = 0;
module_param_named(dbg_kkai, dbg_kkai, int, 0400);
MODULE_PARM_DESC(dbg_kkai, "KKAI debug level");

/*
 * incoming packet handling
 */

/*
 * Prevent this station from responding to UC ECTP packets?
 */
static int ectp_uc_ignore __read_mostly = 0;

/*
 * Prevent this station from responding to BMC ECTP packets?
 */
static int ectp_bmc_ignore __read_mostly = 0;

/*
 * ECTP Loopback Assistant multicast address
 */
static const uint8_t ectp_la_mcaddr[ETH_ALEN] = { 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, };

static bool ectp_la_mcaddr_dst_ok(const struct sk_buff *skb);

static bool ectp_send_frame_ok(const int rxed_pkt_type,
			       struct sk_buff *rx_skb);

#if !defined(NET_RX_BAD)
#define NET_RX_BAD		5  /* packet dropped due to kernel error */
#endif/*!defined(NET_RX_BAD)*/

/*
 * ectp_rcv()
 *
 * ECTP incoming packet handler
 *
 */
static int ectp_rcv(struct sk_buff *skb,
		    struct net_device *netdev,
		    struct packet_type *pt,
		    struct net_device *orig_netdev)
{
	const unsigned int pkt_type = skb->pkt_type;

	if (netdev->type != ARPHRD_ETHER)
		goto drop;

	switch (pkt_type) {
	case PACKET_HOST:
		if (ectp_uc_ignore)
			goto drop;
		break;
	case PACKET_MULTICAST:
		if (ectp_bmc_ignore)
			goto drop;
		if (!ectp_la_mcaddr_dst_ok(skb))
			goto drop;
		break;
	case PACKET_BROADCAST:
		if (ectp_bmc_ignore)
			goto drop;
		break;
	default:
		goto drop;
		break;
	}

	#if 0
	if (likely(!skb_is_nonlinear(skb))) {
		if (!ectp_linear_skb_ok(skb, netdev->name, pkt_type))
			goto drop;
	} else {
		switch (ectp_nonlinear_skb_ok(&skb, netdev->name, pkt_type)) {
		case ECTP_NONL_SKB_OK:
			break;
		case ECTP_NONL_SKB_DROP:
			goto drop;
			break;
		case ECTP_NONL_SKB_BAD:
			goto bad;
			break;
		default:
			goto drop;
			break;
		};
	}

	if (likely(ectp_send_frame_ok(pkt_type, skb)))
		return NET_RX_SUCCESS;
	else
		return NET_RX_BAD;
	#endif/*0*/
	if (likely(ectp_send_frame_ok(pkt_type, skb)))
		return NET_RX_SUCCESS;
	else
		return NET_RX_BAD;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;

bad:
	return NET_RX_BAD;

} /* ectp_rcv() */

/*
 * ectp_la_mcaddr_dst_ok()
 *
 * checks if dest mac address of supplied skb is the ECTP loopback assist
 * multicast address
 */
static bool ectp_la_mcaddr_dst_ok(const struct sk_buff *skb)
{
	const struct ethhdr *ehdr = (struct ethhdr *)skb_mac_header(skb);

	if (likely(ether_addr_equal(ehdr->h_dest, ectp_la_mcaddr) == 0))
		return true;
	else
		return false;
}

/*
 * ectp_send_frame_ok()
 *
 * Send off the supplied ECTP packet, by building a new skb
 * and then transmitting it if it is response to a unicast, or queuing it
 * if it is a response to a broadcast or multicast.
 */
static bool ectp_send_frame_ok(const int rxed_pkt_type,
			       struct sk_buff *rx_skb)
{
	struct sk_buff *tx_skb;

	return false;
	#if 0
	if (likely((rxed_pkt_type == PACKET_HOST) ||
		   ((!ectp_bmc_rply_jttr_randmask) &&
		    (!ectp_bmc_rply_jttr_min_msecs)))) {

		if (!ectp_build_tx_skb_ok(rx_skb, &tx_skb,
					  ectp_uc_rply_skb_prio))
			return false;

		if (unlikely(dev_queue_xmit(tx_skb) < 0))
			return false;
		else
			return true;
	}
	else {
		/* delayed broadcast / multicast reply */
		if (!ectp_build_delayed_tx_skb_ok(rx_skb, &tx_skb,
						  TC_PRIO_BESTEFFORT,
						  ectp_bmc_delay()))
			return false;

		ectp_queue_delayed_tx_skb(&ectp_bmc_rply_q, tx_skb);
		return true;
	}
	#endif/*0*/
}

/*
 * Packet type handler structure for ECTP type 0x9000 packets
 */
static struct packet_type ectp_packet_type = {
	.type		= htons(ETH_P_LOOPBACK),
	.dev		= NULL, /* all interfaces */
	.func		= ectp_rcv,
};

static void elb_sess_work(struct work_struct *ws)
{
	struct elb_test_sess *elb_sess = container_of(ws, struct elb_test_sess,
						sess_work);

	pr_info("%s: elb_sess_work: stat_running=%d\n",
	       _DBG_PREF, elb_sess->stat_running);
	elb_sess->stat_running --;

	usleep_range(20000, 80000);
	if (elb_sess->stat_running >  0) {
		schedule_work(&elb_sess->sess_work);
	}
}

static struct sk_buff *_elb_alloc_skb(struct elb_test_sess *elb_sess)
{
	//unsigned int extralen = LL_RESERVED_SPACE(dev);
	struct sk_buff *skb = NULL;
	unsigned int size;

	#if 0
	size = pkt_dev->cur_pkt_size + 64 + extralen + pkt_dev->pkt_overhead;
	if (pkt_dev->flags & F_NODE) {
		int node = pkt_dev->node >= 0 ? pkt_dev->node : numa_node_id();

		skb = __alloc_skb(NET_SKB_PAD + size, GFP_NOWAIT, 0, node);
		if (likely(skb)) {
			skb_reserve(skb, NET_SKB_PAD);
			skb->dev = dev;
		}
	} else {
		 skb = __netdev_alloc_skb(dev, size, GFP_NOWAIT);
	}

	/* the caller pre-fetches from skb->data and reserves for the mac hdr */
	if (likely(skb))
		skb_reserve(skb, extralen - 16);
	#endif/*0*/
	size = elb_sess->conf_pktsize;
	skb  = __netdev_alloc_skb(elb_sess->sess_dev, size, GFP_NOWAIT);

	/* the caller pre-fetches from skb->data and reserves for the mac hdr */
	if (likely(skb))
		skb_reserve(skb, sizeof(struct ethhdr));

	return skb;
}

static int  _elb_test_main(struct elb_test_sess *elb_sess)
{
	struct sk_buff *skb=NULL;

	pr_info("%s: _elb_test_main(10) ..\n",
	       _DBG_PREF);

	// skb = _elb_alloc_skb(elb_sess);
	INIT_WORK(&elb_sess->sess_work, elb_sess_work);

	schedule_work(&elb_sess->sess_work);
#if 0
	elb_sess->stat_running = 0;
	elb_sess_work(&elb_sess->sess_work);
#endif/*0*/
	return 0;
}

/**
 *  elb_init_module - Driver Debug Registration Routine
 **/
static int __init elb_init_module(void)
{
	int ret = 0;

	pr_info("%s - version %s\n",
	       _DBG_PREF, "0.1");

	// KKAI/Li ZhiGang, 20191014
	if (dbg_kkai >  0) {
		dbg_elb_kkai = dbg_kkai;
		pr_info("%s: dbg_kkai=%d\n",
	       _DBG_PREF, dbg_kkai);
	}

	//
	dev_add_pack(&ectp_packet_type);

	static struct elb_test_sess st_elb_sess;
	do {
		struct elb_test_sess *elb_sess = &st_elb_sess;
		memset(elb_sess, 0, sizeof(*elb_sess));

		elb_sess->stat_running = 10;
		_elb_test_main(elb_sess);
	} while (0);

	return ret;
}

module_init(elb_init_module);

/**
 *  elb_exit_module - Driver Exit Cleanup Routine
 **/
static void __exit elb_exit_module(void)
{
	//
	dev_remove_pack(&ectp_packet_type);
}

module_exit(elb_exit_module);

MODULE_AUTHOR("KKAI/Li ZhiGang");
MODULE_DESCRIPTION("Ethernet LoopBack Linux testing Module");
MODULE_LICENSE("GPL");

