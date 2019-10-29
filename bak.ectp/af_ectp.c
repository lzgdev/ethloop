/*
 * af_ectp.c:
 *
 *	An implementation of the Ethernet v2.0 Configuration Testing Protocol
 *	(ECTP).
 *
 * copyright:
 *
 *	Copyright (C) 2008-2009, Mark Smith <markzzzsmith@yahoo.com.au>
 *	All rights reserved.
 *
 * license:
 *
 *	GPLv2 only
 *
 */

#include <asm/byteorder.h>

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/notifier.h>
#include <linux/interrupt.h>

#include <linux/net.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/pkt_sched.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include <linux/ectp.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif /* CONFIG_SYSCTL */

#define MOD_DESC "Ethernet V2.0 Configuration Testing Protocol"

MODULE_DESCRIPTION(MOD_DESC);
MODULE_VERSION("0.99");
MODULE_AUTHOR("Mark Smith <markzzzsmith@yahoo.com.au>");
MODULE_LICENSE("GPL v2");


/*
 *	*** struct and enum definitions ***
 */


/*
 * generic skb queue
 */
struct ectp_skb_queue {
	spinlock_t spinlock;
	struct sk_buff_head head;
	unsigned int maxlen;
};


/*
 * high res timer reply queue
 */
struct ectp_reply_queue {
	struct ectp_skb_queue skb_q;
	struct hrtimer q_hrt_kernt;
	struct tasklet_struct q_tasklet;
	bool resched_q_kernt;
};


/*
 * Return values for ectp_nonlinear_skb_ok()
 */
enum ectp_nonl_skb_ok {
	ECTP_NONL_SKB_OK,
	ECTP_NONL_SKB_DROP,
	ECTP_NONL_SKB_BAD
};


/*
 *	*** function prototypes ***
 */

/*
 * module initialisation
 */
static int __init ectp_init(void);

static void __init ectp_init_ktimes(void);

static void __init ectp_setup_bmc_rply_q(void);

static void __init ectp_init_skb_q(struct ectp_skb_queue *skb_q,
				   const unsigned int q_maxlen);

static void __init ectp_setup_rply_q_hrt(struct ectp_reply_queue *rply_q,
					 enum hrtimer_restart (*kernt_func)
						(struct hrtimer *));

static void __init ectp_setup_ifaces(void);

static void __init ectp_register_ifaces_notif(void);

static void __init ectp_register_packet_hdlr(void);

static void __init ectp_register_sysctl(void);

static void __init ectp_print_banner(void);

/*
 * module exit
 */
static void __exit ectp_exit(void);

static void __exit ectp_unregister_sysctl(void);

static void __exit ectp_unregister_packet_hdlr(void);

static void __exit ectp_reset_ifaces(void);

static void __exit ectp_unregister_ifaces_notif(void);

static void __exit ectp_allifaces_del_la_mcaddr(void);

static void __exit ectp_shutdown_bmc_rply_q(void);

static void __exit ectp_allifaces_netdev_put(void);

/*
 * interface related
 */
static void ectp_netdev_add_la_mcaddr(struct net_device *netdev);

static void ectp_netdev_del_la_mcaddr(struct net_device *netdev);

static int ectp_iface_notif_hdlr(struct notifier_block *nb,
				 unsigned long event,
				 void *ptr);

static void ectp_rply_q_purge_skb_netdev(struct ectp_reply_queue *rply_q,
					 const struct net_device *netdev);

static void ectp__move_netdev_skbs(struct sk_buff_head *from_skb_q,
				   struct sk_buff_head *to_skb_q,
				   const struct net_device *netdev);


/*
 * incoming packet handling
 */
static int ectp_rcv(struct sk_buff *skb,
		    struct net_device *netdev,
		    struct packet_type *pt,
		    struct net_device *orig_netdev);

static bool ectp_la_mcaddr_dst_ok(const struct sk_buff *skb);


static bool ectp_linear_skb_ok(const struct sk_buff *skb,
			       const unsigned char rx_netdev_name[IFNAMSIZ],
			       const unsigned int pkt_type);

static bool ectp_skipcount_valid(const unsigned int skipcount,
				 const unsigned int msgs_len);

static unsigned int ectp_skipc_to_num_fwdmsgs(const unsigned int skipcount);

static bool ectp_full_fwdmsg_avail(const unsigned int msgs_len,
				   const unsigned int skipcount);

static bool ectp_fwdmsg_chk_ok(const unsigned char
				rx_netdev_name[IFNAMSIZ],
			       const unsigned int rxed_pkt_type,
			       const uint8_t srcmac[ETH_ALEN],
			       const unsigned int skipcount,
			       const uint8_t fwdaddr[ETH_ALEN]);

static void ectp_log_bad_fwdmsg(const unsigned int skipcount,
				const uint8_t bad_fwdaddr[ETH_ALEN],
				const uint8_t srcmac[ETH_ALEN],
				const unsigned char rx_netdev_name[IFNAMSIZ]);

static bool ectp_fwdaddr_chk_ok(const uint8_t fwdaddr[ETH_ALEN],
				const unsigned int skipcount,
				const uint8_t srcmac[ETH_ALEN],
				const unsigned char
					rx_netdev_name[IFNAMSIZ]);

static bool ectp_srcmac_rpf_chk_ok(const uint8_t srcmac[ETH_ALEN],
				   const uint8_t fwdaddr[ETH_ALEN]);

static bool ectp_srcmac_fwdaddr_match(const uint8_t srcmac[ETH_ALEN],
				      const uint8_t fwdaddr[ETH_ALEN]);

static bool ectp_next_msgtype_avail(const unsigned int skipcount,
				    const unsigned int msgs_len);

static bool ectp_bmc_nextmsg_chk_ok(const struct ectp_packet *ectp_pkt,
				    const unsigned int skipcount,
				    const unsigned int rxed_pkt_type,
				    const uint8_t srcmac[ETH_ALEN],
				    const unsigned char
					rx_netdev_name[IFNAMSIZ]);

static void ectp_log_bad_bmc(const unsigned int rxed_pkt_type,
			     const uint8_t srcmac[ETH_ALEN],
			     const unsigned char rx_netdev_name[IFNAMSIZ]);

static enum ectp_nonl_skb_ok
			ectp_nonlinear_skb_ok(struct sk_buff **skb_p,
					      const unsigned char
						rx_netdev_name[IFNAMSIZ],
					      const unsigned int pkt_type);

static bool ectp_private_skb_ok(struct sk_buff **skb_p);

static bool ectp_pskb_pull_ok(struct sk_buff *skb,
			      const unsigned int pull_len,
			      struct ectp_packet **ectp_pkt_p,
			      struct ectp_message **ectp_curr_msg_p,
			      struct ethhdr **ectp_ethhdr_p);


/*
 * building and sending outgoing frames
 */
static bool ectp_send_frame_ok(const int rxed_pkt_type,
			       struct sk_buff *rx_skb);

static ktime_t ectp_bmc_delay(void);

static ktime_t ectp_ms_to_ktime(const unsigned int msecs);

static bool ectp_build_tx_skb_ok(struct sk_buff *rx_skb,
				 struct sk_buff **tx_skb_p,
				 const uint32_t tx_prio);

static bool ectp_build_delayed_tx_skb_ok(struct sk_buff *rx_skb,
					 struct sk_buff **tx_skb_p,
					 const uint32_t tx_prio,
					 const ktime_t delay);

static void ectp_queue_delayed_tx_skb(struct ectp_reply_queue *rply_q,
				      struct sk_buff *tx_skb);

static bool ectp__skb_q_full(struct ectp_skb_queue *skb_q);

static void ectp_rply_q_kernt_start(struct ectp_reply_queue *rply_q,
				    const ktime_t start_ktime);

static void ectp_rply_q_kernt_try_resched(struct ectp_reply_queue *rply_q,
					  const ktime_t start_ktime);

static void ectp_rply_q_kernt_try_stop(struct ectp_reply_queue *rply_q);

static void ectp_rply_q_kernt_stop(struct ectp_reply_queue *rply_q);

static enum hrtimer_restart ectp_bmc_sched_tasklet(struct hrtimer *timer);

static void ectp_bmc_tx_skb(unsigned long data);

#ifdef CONFIG_SYSCTL
/*
 * sysctl / /proc/sys/net/ectp handlers
 */
static int ectp_sysctl_bmc_rply_jttr_randmask_len(ctl_table *table,
						  int write,
						  struct file *filp,
						  void __user *buffer,
						  size_t *lenp,
						  loff_t *ppos);

static int ectp_sysctl_uc_prio_ctrl(ctl_table *table,
				    int write,
				    struct file *filp,
				    void __user *buffer,
				    size_t *lenp,
				    loff_t *ppos);

static int ectp_sysctl_bmc_rply_jttr_min_msecs(ctl_table *table,
					       int write,
					       struct file *filp,
					       void __user *buffer,
					       size_t *lenp,
					       loff_t *ppos);
#endif /* CONFIG_SYSCTL */

/*
 * ECTP packet utility functions
 */

static inline uint16_t ectp_htons(uint16_t i);

static inline uint16_t ectp_ntohs(uint16_t i);

static unsigned int ectp_get_skipcount(const struct ectp_packet *ectp_pkt);

static void ectp_set_skipcount(struct ectp_packet *ectp_pkt,
			       const unsigned int skipcount);


static struct ectp_message *ectp_get_msg_ptr(const unsigned int skipcount,
					     const struct ectp_packet
						*ectp_pkt);

static struct ectp_message *ectp_get_curr_msg_ptr(const struct ectp_packet
							*ectp_pkt);

static uint16_t ectp_get_msg_type(const struct ectp_message *ectp_msg);

static bool ectp_fwdaddr_ok(const uint8_t fwdaddr[ETH_ALEN]);

static uint8_t *ectp_get_fwdaddr(const struct ectp_message *ectp_fwd_msg);

static void ectp_inc_skipcount(struct ectp_packet *ectp_pkt);


/*
 *	*** global variables ***
 */


static const unsigned char proto_name[] = "ectp";

static const unsigned char proto_banner[] __initconst = MOD_DESC;

/*
 * ECTP Loopback Assistant multicast address
 */
static const uint8_t ectp_la_mcaddr[ETH_ALEN] = ECTP_LA_MCADDR;

/*
 * Device notifier event handler structure
 */
static struct notifier_block ectp_notifblock = {
	.notifier_call	= ectp_iface_notif_hdlr,
};

/*
 * Packet type handler structure for ECTP type 0x9000 packets
 */
static struct packet_type ectp_packet_type = {
	.type		= htons(ETH_P_ECTP),
	.dev		= NULL, /* all interfaces */
	.func		= ectp_rcv,
};

/*
 * Minimum jitter milliseconds to wait before sending a unicast
 * response to a broadcast or multicast (bmc) ECTP packet.
 */
static int ectp_bmc_rply_jttr_min_msecs __read_mostly = 10;

/*
 * Minimum jitter milliseconds in ktime format
 */
static ktime_t ectp_bmc_rply_jttr_min_msecs_ktime __read_mostly;

/*
 * Jitter random mask length, must match the initial
 * ectp_bmc_rply_jttr_randmask bit length below at compile time
 */
static unsigned int ectp_bmc_rply_jttr_randmask_len __read_mostly = 6;

/*
 * Binary mask ANDed with net_rand() result to limit jitter value range.
 * Binary mask value must match bit count in ectp_bmc_rply_jttr_randmask_len at
 * compile time
 */
static uint32_t ectp_bmc_rply_jttr_randmask __read_mostly = 63;

/*
 * Set unicast reply skb->priority to TC_PRIO_CONTROL or default of
 * TC_PRIO_BESTEFFORT?
 */
static int ectp_uc_rply_prio_ctrl __read_mostly = 0;

/*
 * TC_PRIO value set in tx'd SKBs
 */
static uint32_t ectp_uc_rply_skb_prio __read_mostly = TC_PRIO_BESTEFFORT;

/*
 * Maximum number of forward messages in a source routed packet.
 * Default value of zero means only permit replies back to the ECTP
 * originator
 */
static unsigned int ectp_src_rt_max_fwdmsgs __read_mostly = 0;

/*
 * broadcast/multicast reply queue
 */
static struct ectp_reply_queue ectp_bmc_rply_q;

/*
 * initial queue maximum length for bmc reply queues
 */
static const unsigned int ectp_init_bmc_q_maxlen __initconst = 10;

/*
 * high res timer range accuracy nanoseconds
 */
static const unsigned long ectp_hrt_range_ns = 900000;

/*
 * high res timer range accuracy nanoseconds in ktime_t
 */
static ktime_t ectp_hrt_range_ns_ktime __read_mostly;

/*
 * Log bad forward messages?
 */
static unsigned int ectp_fwdmsg_log_bad __read_mostly = 0;

/*
 * Log bad broadcast or multicast ECTP packets?
 */
static unsigned int ectp_bmc_log_bad __read_mostly = 0;

/*
 * Prevent this station from responding to UC ECTP packets?
 */
static int ectp_uc_ignore __read_mostly = 0;

/*
 * Prevent this station from responding to BMC ECTP packets?
 */
static int ectp_bmc_ignore __read_mostly = 0;

#ifdef CONFIG_SYSCTL

/*
 * /proc/sys/net/ectp entries
 */

static const int zero = 0;
static const int one = 1;

static const int ectp_bmc_rply_jttr_randmask_len_max = 10;

static const int ectp_src_rt_max_fwdmsgs_max = 1000; /* should be plenty */

static const int ectp_bmc_rply_jttr_min_msecs_max = 1000;

static const int ectp_bmc_q_maxlen_max = 30;

static struct ctl_table ectp_table[] = {
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "src_rt_max_fwdmsgs",
		.data		= &ectp_src_rt_max_fwdmsgs,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&ectp_src_rt_max_fwdmsgs_max
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "bmc_jitter_min_msecs",
		.data		= &ectp_bmc_rply_jttr_min_msecs,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= ectp_sysctl_bmc_rply_jttr_min_msecs,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&ectp_bmc_rply_jttr_min_msecs_max
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "bmc_jitter_randmask_len",
		.data		= &ectp_bmc_rply_jttr_randmask_len,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= ectp_sysctl_bmc_rply_jttr_randmask_len,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&ectp_bmc_rply_jttr_randmask_len_max
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "bmc_rply_q_maxlen",
		.data		= &ectp_bmc_rply_q.skb_q.maxlen,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&ectp_bmc_q_maxlen_max
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "bmc_ignore",
		.data		= &ectp_bmc_ignore,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&one
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "uc_ignore",
		.data		= &ectp_uc_ignore,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&one
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "uc_rply_prio_ctrl",
		.data		= &ectp_uc_rply_prio_ctrl,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= ectp_sysctl_uc_prio_ctrl,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&one
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "fwdmsg_log_bad",
		.data		= &ectp_fwdmsg_log_bad,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&one
	},
	{
		.ctl_name	= CTL_UNNUMBERED,
		.procname	= "bmc_log_bad",
		.data		= &ectp_bmc_log_bad,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.strategy	= sysctl_intvec,
		.extra1		= (void *)&zero,
		.extra2		= (void *)&one
	},
	{ 0 },
};

/*
 * /proc/sys/net/ectp
 */
static struct ctl_path ectp_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET, },
	{ .procname = "ectp", .ctl_name = CTL_UNNUMBERED, },
	{ }
};

static struct ctl_table_header *ectp_table_header;

#endif /* CONFIG_SYSCTL */


/*
 *	*** functions ***
 */

/*
 * module initialisation
 */

/*
 * main ectp_init() routine at the end of the file
 */

/*
 * ectp_init_ktimes()
 *
 * Initialise a few ktime values used by the module
 */
static void __init ectp_init_ktimes(void)
{


	ectp_bmc_rply_jttr_min_msecs_ktime =
		ectp_ms_to_ktime(ectp_bmc_rply_jttr_min_msecs);

	ectp_hrt_range_ns_ktime = ns_to_ktime(ectp_hrt_range_ns);

}


/*
 * ectp_setup_bmc_rply_q()
 *
 * Sets up the broadcast/multicast reply queue
 */
static void __init ectp_setup_bmc_rply_q(void)
{


	ectp_init_skb_q(&ectp_bmc_rply_q.skb_q, ectp_init_bmc_q_maxlen);

	ectp_setup_rply_q_hrt(&ectp_bmc_rply_q, ectp_bmc_sched_tasklet);

	tasklet_init(&ectp_bmc_rply_q.q_tasklet, ectp_bmc_tx_skb, 0);

}


/*
 * ectp_init_skb_q()
 *
 * Initialise skb queue parameters
 */
static void __init ectp_init_skb_q(struct ectp_skb_queue *skb_q,
				   const unsigned int q_maxlen)
{


	skb_queue_head_init(&skb_q->head);

	skb_q->maxlen = q_maxlen;

	spin_lock_init(&skb_q->spinlock);

}


/*
 * ectp_setup_rply_q_hrt()
 *
 * setup high res timer parameters for a reply queue
 */
static void __init ectp_setup_rply_q_hrt(struct ectp_reply_queue *rply_q,
					 enum hrtimer_restart (*kernt_func)
						(struct hrtimer *))
{


	hrtimer_init(&rply_q->q_hrt_kernt, CLOCK_REALTIME, HRTIMER_MODE_ABS);

	rply_q->q_hrt_kernt.function = kernt_func;

}


/*
 * ectp_setup_ifaces()
 *
 * Setup ethernet interfaces to receive ECTP loopback assist multicasts.
 */
static void __init ectp_setup_ifaces(void)
{


	ectp_register_ifaces_notif();

}


/*
 * ectp_register_ifaces_notif()
 *
 * Register new interface notifier. Notifier called automatically on
 * registration.
 */
static void __init ectp_register_ifaces_notif(void)
{


	register_netdevice_notifier(&ectp_notifblock);

}


/*
 * ectp_register_packet_hdlr()
 *
 * Register ECTP rx packet handler function
 */
static void __init ectp_register_packet_hdlr(void)
{


	dev_add_pack(&ectp_packet_type);

}


/*
 * ectp_register_sysctl()
 *
 * Register sysctl, which includes creating files under /proc/sys/net/ectp
 */
static void __init ectp_register_sysctl(void)
{


#ifdef CONFIG_SYSCTL
	ectp_table_header = register_sysctl_paths(ectp_path, ectp_table);
#endif

}


/*
 * ectp_print_banner()
 *
 * Print protocol name and version banner
 */
static void __init ectp_print_banner(void)
{


	pr_info("%s: %s\n", proto_name, proto_banner);

}


/*
 * module exit
 */

/*
 * ectp_exit() routine at end of file
 */


/*
 * ectp_unregister_sysctl()
 *
 * Remove sysctls, which also includes removing /proc/sys/net/ectp directory
 */
static void __exit ectp_unregister_sysctl(void)
{


#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(ectp_table_header);
#endif

}


/*
 * ectp_unregister_packet_hdlr()
 *
 * Deregister ECTP rx packet handler
 */
static void __exit ectp_unregister_packet_hdlr(void)
{


	dev_remove_pack(&ectp_packet_type);

}


/*
 * ectp_reset_ifaces()
 *
 * Remove ECTP loopback assist multicast addr from ethernet interfaces,
 * and remove ECTP notifier
 */
static void __exit ectp_reset_ifaces(void)
{


	ectp_unregister_ifaces_notif();

	ectp_allifaces_del_la_mcaddr();

}


/*
 * ectp_unregister_ifaces_notif()
 *
 * Remove new interface notifier.
 */
static void __exit ectp_unregister_ifaces_notif(void)
{


	unregister_netdevice_notifier(&ectp_notifblock);

}


/*
 * ectp_allifaces_del_la_mcaddr()
 *
 * Remove ectp loopback assist multicast address from all existing
 * interfaces.
 */
static void __exit ectp_allifaces_del_la_mcaddr(void)
{
	struct net_device *netdev;


	rtnl_lock();

	for_each_netdev(&init_net, netdev) {
		if (netdev->type == ARPHRD_ETHER)
			ectp_netdev_del_la_mcaddr(netdev);
	}

	rtnl_unlock();

}


/*
 * ectp_shutdown_bmc_rply_q()
 *
 * shutdown / clean up the bmc reply queue
 *
 * n.b. ectp related notifiers / softirqs are assumed to have been disabled
 * / shutdown, so reply queue locking isn't needed after kernel timer stopped
 */
static void __exit ectp_shutdown_bmc_rply_q(void)
{


	ectp_rply_q_kernt_stop(&ectp_bmc_rply_q);

	tasklet_disable(&ectp_bmc_rply_q.q_tasklet);

	if (!skb_queue_empty(&ectp_bmc_rply_q.skb_q.head))
		skb_queue_purge(&ectp_bmc_rply_q.skb_q.head);

}


/*
 * ectp_allifaces_netdev_put()
 *
 * Release net_device refcount for all ECTP interfaces
 */
static void __exit ectp_allifaces_netdev_put(void)
{
	struct net_device *netdev;


	rtnl_lock();

	for_each_netdev(&init_net, netdev) {
		if (netdev->type == ARPHRD_ETHER)
			dev_put(netdev);
	}

	rtnl_unlock();

}


/*
 * interface notifier and related
 */

/*
 * ectp_netdev_add_la_mcaddr()
 *
 * Add the ECTP loopback assist multicast address to the specified device.
 */
static void ectp_netdev_add_la_mcaddr(struct net_device *netdev)
{


	dev_mc_add(netdev, (void *)ectp_la_mcaddr, ETH_ALEN, 0);

}


/*
 * ectp_netdev_del_la_mcaddr()
 *
 * Remove the ECTP loopback assist multicast address from the specified
 * device.
 */
static void ectp_netdev_del_la_mcaddr(struct net_device *netdev)
{


	dev_mc_delete(netdev, (void *)ectp_la_mcaddr, ETH_ALEN, 0);

}


/*
 * ectp_iface_notif_hdlr()
 *
 * Interface notifier event handler.
 */
static int ectp_iface_notif_hdlr(struct notifier_block *nb,
				 unsigned long event,
				 void *ptr)
{
	struct net_device *netdev = (struct net_device *)ptr;


	if (netdev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		dev_hold(netdev);
		ectp_netdev_add_la_mcaddr(netdev);
		break;
	case NETDEV_DOWN:
		ectp_rply_q_purge_skb_netdev(&ectp_bmc_rply_q, netdev);
		break;
	case NETDEV_UNREGISTER:
		ectp_netdev_del_la_mcaddr(netdev);
		dev_put(netdev);
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;

}


/*
 * ectp_rply_q_purge_skb_netdev()
 *
 * Purge skbs off of reply queue that would be tx'd out specified net device
 *
 */
static void ectp_rply_q_purge_skb_netdev(struct ectp_reply_queue *rply_q,
					 const struct net_device *netdev)
{
	struct sk_buff_head skb_purge_q;
	struct sk_buff *head_skb;
	struct sk_buff *tmp_skb;



	spin_lock_bh(&rply_q->skb_q.spinlock);

	if (skb_queue_empty(&rply_q->skb_q.head)) {
		spin_unlock_bh(&rply_q->skb_q.spinlock);
		return;
	}

	head_skb = skb_peek(&rply_q->skb_q.head);

	skb_queue_head_init(&skb_purge_q);
	ectp__move_netdev_skbs(&rply_q->skb_q.head, &skb_purge_q, netdev);

	if (unlikely(!skb_queue_empty(&rply_q->skb_q.head))) {
		tmp_skb = skb_peek(&rply_q->skb_q.head);
		if (head_skb != tmp_skb)
			ectp_rply_q_kernt_try_resched(rply_q, tmp_skb->tstamp);
	} else {
		ectp_rply_q_kernt_try_stop(rply_q);
	}

	spin_unlock_bh(&rply_q->skb_q.spinlock);

	if (!skb_queue_empty(&skb_purge_q))
		skb_queue_purge(&skb_purge_q);

}


/*
 * ectp__move_netdev_skbs()
 *
 * Move skbs on from_skb_q to to_skb_q with matching net_device
 *
 * n.b. caller must be holding appropriate locks on the queues
 */
static void ectp__move_netdev_skbs(struct sk_buff_head *from_skb_q,
				   struct sk_buff_head *to_skb_q,
				   const struct net_device *netdev)
{
	struct sk_buff *skb;
	struct sk_buff *tmp_skb;


	skb_queue_walk_safe(from_skb_q, skb, tmp_skb) {
		if (skb->dev == netdev) {
			skb_unlink(skb, from_skb_q);
			skb_queue_tail(to_skb_q, skb);
		}
	}


}


/*
 * incoming packet handling
 */

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


	if (likely(compare_ether_addr(ehdr->h_dest, ectp_la_mcaddr) == 0))
		return true;
	else
		return false;

}


/*
 * ectp_linear_skb_ok()
 *
 * Perform validation checks on linear skbs.
 */
static bool ectp_linear_skb_ok(const struct sk_buff *skb,
			       const unsigned char rx_netdev_name[IFNAMSIZ],
			       const unsigned int pkt_type)
{
	const unsigned int pkt_len = skb->len;
	const struct ectp_packet *ectp_pkt;
	unsigned int skipcount;
	unsigned int msgs_len;
	const struct ectp_message *curr_msg;
	const struct ethhdr *ectp_ethhdr;
	const uint8_t *curr_msg_fwdaddr;


	if (pkt_len <= ECTP_SKIPCOUNT_HDR_SZ)
		goto drop;

	ectp_pkt = (struct ectp_packet *)skb_network_header(skb);
	skipcount = ectp_get_skipcount(ectp_pkt);

	msgs_len = pkt_len - ECTP_SKIPCOUNT_HDR_SZ;

	if (!ectp_skipcount_valid(skipcount, msgs_len))
		goto drop;

	curr_msg = ectp_get_msg_ptr(skipcount, ectp_pkt);
	if (ectp_get_msg_type(curr_msg) != ECTP_FWDMSG)
		goto drop;

	if (!ectp_full_fwdmsg_avail(msgs_len, skipcount))
		goto drop;

	ectp_ethhdr = eth_hdr(skb);
	curr_msg_fwdaddr = ectp_get_fwdaddr(curr_msg);

	if (!ectp_fwdmsg_chk_ok(rx_netdev_name, pkt_type,
				ectp_ethhdr->h_source, skipcount,
				curr_msg_fwdaddr))
		goto drop;

	/*
	 * If it's a broadcast or multicast forward message, ensure the
	 * next message in the packet is not a forward message as per
	 * "8.4.2.1 Restrictions on Forward Data Messages" in spec.
	 */
	if (pkt_type != PACKET_HOST) {

		if (!ectp_next_msgtype_avail(skipcount, msgs_len))
			goto drop;

		if (!ectp_bmc_nextmsg_chk_ok(ectp_pkt, skipcount, pkt_type,
					     ectp_ethhdr->h_source,
					     rx_netdev_name))
			goto drop;
	}

	return true;

drop:
	return false;

} /* ectp_linear_skb_ok() */


/*
 * ectp_skipcount_valid()
 *
 * Check if the skipcount value in the specified packet is ok to use to refer
 * to a message
 */
static bool ectp_skipcount_valid(const unsigned int skipcount,
				 const unsigned int msgs_len)
{


	if (likely(skipcount == 0)) {

		if (unlikely(msgs_len < ECTP_MSG_HDR_SZ))
			return false;
		else
			return true;

	} else {

		if (ectp_src_rt_max_fwdmsgs == 0)
			return false;

		BUILD_BUG_ON((ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ) != 8);
		if ((skipcount & ((ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ)-1)) != 0)
			return false;

		if (ectp_skipc_to_num_fwdmsgs(skipcount) >
		    ectp_src_rt_max_fwdmsgs)
			return false;

		if (skipcount > (msgs_len - ECTP_MSG_HDR_SZ))
			return false;

		return true;

	}

}


/*
 * ectp_skipc_to_num_fwdmsgs()
 *
 * Return number of forward messages represented by the supplied skipcount
 */
static unsigned int ectp_skipc_to_num_fwdmsgs(const unsigned int skipcount)
{


	return (skipcount >> 3) + 1;

}


/*
 * ectp_full_fwdmsg_avail()
 *
 * Check if room within specified messages length for a full forward message
 */
static bool ectp_full_fwdmsg_avail(const unsigned int msgs_len,
				   const unsigned int skipcount)
{


	if (likely((msgs_len - skipcount) >=
	    (ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ)))
		return true;
	else
		return false;

}


/*
 * ectp_fwdmsg_chk_ok()
 *
 * performs various validation checks on the forward message attributes
 */
static bool ectp_fwdmsg_chk_ok(const unsigned char
				rx_netdev_name[IFNAMSIZ],
			       const unsigned int rxed_pkt_type,
			       const uint8_t srcmac[ETH_ALEN],
			       const unsigned int skipcount,
			       const uint8_t fwdaddr[ETH_ALEN])
{


	if (!ectp_fwdaddr_chk_ok(fwdaddr, skipcount, srcmac, rx_netdev_name))
		return false;

	if (!ectp_srcmac_rpf_chk_ok(srcmac, fwdaddr))
		return false;

	return true;

}


/*
 * ectp_fwdaddr_chk_ok()
 *
 * checks the supplied forward address is valid, optionally logs a message
 * if not
 */
static bool ectp_fwdaddr_chk_ok(const uint8_t fwdaddr[ETH_ALEN],
				const unsigned int skipcount,
				const uint8_t srcmac[ETH_ALEN],
				const unsigned char
					rx_netdev_name[IFNAMSIZ])
{


	if (unlikely(!ectp_fwdaddr_ok(fwdaddr))) {
		if (ectp_fwdmsg_log_bad)
			ectp_log_bad_fwdmsg(skipcount, fwdaddr, srcmac,
					    rx_netdev_name);

		return false;
	} else {
		return true;
	}

}


/*
 * ectp_log_bad_fwdmsg()
 *
 * Log a kernel message about a bad forward message, but only if
 * skipcount == 0, which means we've caught the originator source
 * mac address
 */
static void ectp_log_bad_fwdmsg(const unsigned int skipcount,
				const uint8_t bad_fwdaddr[ETH_ALEN],
				const uint8_t srcmac[ETH_ALEN],
				const unsigned char rx_netdev_name[IFNAMSIZ])
{


	if ((skipcount == 0) && net_ratelimit())
		pr_warning("%s: Bad forward addr %pM from %pM, rcvd on %s\n",
			    proto_name, bad_fwdaddr, srcmac, rx_netdev_name);

}


/*
 * ectp_srcmac_rpf_chk_ok()
 *
 * perform a srcmac / forward address reverse path forwarding check if
 * source routed ECTP packets aren't allowed
 */
static bool ectp_srcmac_rpf_chk_ok(const uint8_t srcmac[ETH_ALEN],
				   const uint8_t fwdaddr[ETH_ALEN])
{


	if (likely(ectp_src_rt_max_fwdmsgs == 0)) {
		if (unlikely(!ectp_srcmac_fwdaddr_match(srcmac, fwdaddr)))
			return false;
		else
			return true;
	} else {
		return true;
	}

}


/*
 * ectp_srcmac_fwdaddr_match()
 *
 * checks if supplied ECTP packet source mac address matches supplied
 * forward address
 */
static bool ectp_srcmac_fwdaddr_match(const uint8_t srcmac[ETH_ALEN],
				      const uint8_t fwdaddr[ETH_ALEN])
{


	if (unlikely(compare_ether_addr((u8 *)srcmac, (u8 *)fwdaddr) != 0))
		return false;
	else
		return true;

}


/*
 * ectp_next_msgtype_avail()
 *
 * Check if next message type available after the current one pointed to by
 * supplied skipcount
 */
static bool ectp_next_msgtype_avail(const unsigned int skipcount,
				    const unsigned int msgs_len)
{


	if (likely((skipcount + ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ) <=
	    (msgs_len - ECTP_MSG_HDR_SZ)))
		return true;
	else
		return false;


}


/*
 * ectp_bmc_nextmsg_chk_ok()
 *
 * Check if bmc packet next message is a forward message, log a warning if
 * necessary
 */
static bool ectp_bmc_nextmsg_chk_ok(const struct ectp_packet *ectp_pkt,
				    const unsigned int skipcount,
				    const unsigned int rxed_pkt_type,
				    const uint8_t srcmac[ETH_ALEN],
				    const unsigned char
					rx_netdev_name[IFNAMSIZ])
{
	struct ectp_message *ectp_next_msg =
		ectp_get_msg_ptr(skipcount + ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ,
				 ectp_pkt);


	if (unlikely(ectp_get_msg_type(ectp_next_msg) == ECTP_FWDMSG)) {
		if (ectp_bmc_log_bad) {
			ectp_log_bad_bmc(rxed_pkt_type, srcmac,
					 rx_netdev_name);
		}
		return false;
	} else {
		return true;
	}

}


/*
 * ectp_log_bad_bmc()
 *
 * Log a kernel message about receiving a bad broadcast/multicast message
 */
static void ectp_log_bad_bmc(const unsigned int rxed_pkt_type,
			     const uint8_t srcmac[ETH_ALEN],
			     const unsigned char rx_netdev_name[IFNAMSIZ])
{


	if (net_ratelimit()) {
		const unsigned char *pkt_type_text;

		switch (rxed_pkt_type) {
		case PACKET_MULTICAST:
			pkt_type_text = "multicast";
			break;
		case PACKET_BROADCAST:
			pkt_type_text = "broadcast";
			break;
		default:
			pkt_type_text = "unknown";
		}

		pr_warning("%s: Bad %s packet, > 1 fwd msg, from %pM, "
			   "rcvd on %s\n", proto_name, pkt_type_text,
			   srcmac, rx_netdev_name);

	}

}


/*
 * ectp_nonlinear_skb_ok()
 *
 * Perform validation checks on non-linear skbs.
 */
static enum ectp_nonl_skb_ok
			ectp_nonlinear_skb_ok(struct sk_buff **skb_p,
					      const unsigned char
						rx_netdev_name[IFNAMSIZ],
					      const unsigned int pkt_type)
{
	const unsigned int pkt_len = (*skb_p)->len;
	unsigned int skb_pull_len;
	struct ectp_packet *ectp_pkt;
	unsigned int skipcount;
	unsigned int msgs_len;
	struct ectp_message *curr_msg;
	struct ethhdr *ectp_ethhdr;
	const uint8_t *curr_msg_fwdaddr;


	if (pkt_len <= ECTP_SKIPCOUNT_HDR_SZ)
		goto drop;

	if (!ectp_private_skb_ok(skb_p))
		goto bad;

	skb_pull_len = ECTP_SKIPCOUNT_HDR_SZ;
	if (!ectp_pskb_pull_ok(*skb_p, ECTP_SKIPCOUNT_HDR_SZ, NULL, NULL,
			       NULL))
		goto drop;

	ectp_pkt = (struct ectp_packet *)skb_network_header(*skb_p);
	skipcount = ectp_get_skipcount(ectp_pkt);

	msgs_len = pkt_len - ECTP_SKIPCOUNT_HDR_SZ;

	if (!ectp_skipcount_valid(skipcount, msgs_len))
		goto drop;

	skb_pull_len += skipcount + ECTP_MSG_HDR_SZ;
	if (skb_pull_len >= pkt_len)
		goto drop;

	if (!ectp_pskb_pull_ok(*skb_p, skb_pull_len, &ectp_pkt, NULL, NULL))
		goto drop;

	curr_msg = ectp_get_msg_ptr(skipcount, ectp_pkt);
	if (ectp_get_msg_type(curr_msg) != ECTP_FWDMSG)
		goto drop;

	if (!ectp_full_fwdmsg_avail(msgs_len, skipcount))
		goto drop;

	skb_pull_len += ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ;
	if (skb_pull_len >= pkt_len)
		goto drop;

	if (!ectp_pskb_pull_ok(*skb_p, skb_pull_len, &ectp_pkt, &curr_msg,
	    NULL))
		goto drop;

	ectp_ethhdr = eth_hdr(*skb_p);
	curr_msg_fwdaddr = ectp_get_fwdaddr(curr_msg);

	if (!ectp_fwdmsg_chk_ok(rx_netdev_name, pkt_type,
	    ectp_ethhdr->h_source, skipcount, curr_msg_fwdaddr))
		goto drop;

	/*
	 * If it's a broadcast or multicast forward message, ensure the
	 * next message in the packet is not a forward message as per
	 * "8.4.2.1 Restrictions on Forward Data Messages" in spec.
	 */
	if (pkt_type != PACKET_HOST) {

		if (!ectp_next_msgtype_avail(skipcount, msgs_len))
			goto drop;

		skb_pull_len += ECTP_MSG_HDR_SZ;
		if (skb_pull_len >= pkt_len)
			goto drop;

		if (!ectp_pskb_pull_ok(*skb_p, skb_pull_len, &ectp_pkt,
				       &curr_msg, &ectp_ethhdr))
			goto drop;

		if (!ectp_bmc_nextmsg_chk_ok(ectp_pkt, skipcount, pkt_type,
					     ectp_ethhdr->h_source,
					     rx_netdev_name))
			goto drop;
	}


	if (!ectp_pskb_pull_ok(*skb_p, pkt_len, NULL, NULL, NULL))
		goto drop;


	return ECTP_NONL_SKB_OK;

drop:
	return ECTP_NONL_SKB_DROP;

bad:
	return ECTP_NONL_SKB_BAD;

} /* ectp_nonlinear_skb_ok() */


/*
 * ectp_private_skb_ok()
 *
 * Check if skb shared, if so, copy it, because we're probably going
 * to modify it
 */
static bool ectp_private_skb_ok(struct sk_buff **skb_p)
{


	*skb_p = skb_share_check(*skb_p, GFP_ATOMIC);

	if (likely(*skb_p != NULL))
		return true;
	else
		return false;

}


/*
 * ectp_pskb_pull_ok()
 *
 * Pull specified bytes into main data buffer if necessary,
 * and then update effected pointers if required
 */
static bool ectp_pskb_pull_ok(struct sk_buff *skb,
			      const unsigned int pull_len,
			      struct ectp_packet **ectp_pkt_p,
			      struct ectp_message **ectp_curr_msg_p,
			      struct ethhdr **ectp_ethhdr_p)
{


	if (likely(pskb_may_pull(skb, pull_len))) {

		if (ectp_pkt_p != NULL) {
			*ectp_pkt_p =
				(struct ectp_packet *)skb_network_header(skb);

			if (ectp_curr_msg_p != NULL)
				*ectp_curr_msg_p =
					ectp_get_curr_msg_ptr(*ectp_pkt_p);
		}

		if (ectp_ethhdr_p != NULL)
			*ectp_ethhdr_p = eth_hdr(skb);

		return true;

	} else {
		return false;
	}

}


/*
 * building and sending outgoing packets
 */

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

	} else {
		/* delayed broadcast / multicast reply */

		if (!ectp_build_delayed_tx_skb_ok(rx_skb, &tx_skb,
						  TC_PRIO_BESTEFFORT,
						  ectp_bmc_delay()))
			return false;

		ectp_queue_delayed_tx_skb(&ectp_bmc_rply_q, tx_skb);

		return true;

	}

}


/*
 * ectp_bmc_delay()
 *
 * Returns the current bmc delay, the sum of the current minimimum msec
 * delay and the jitter delay.
 */
static ktime_t ectp_bmc_delay(void)
{
	unsigned int jttr_msecs;
	ktime_t kt;


	if (likely(ectp_bmc_rply_jttr_randmask)) {

		jttr_msecs = net_random() & ectp_bmc_rply_jttr_randmask;

		kt = ktime_add(ectp_bmc_rply_jttr_min_msecs_ktime,
			       ectp_ms_to_ktime(jttr_msecs));
	} else {
		/* don't waste random numbers when jitter mask is 0 */
		kt = ectp_bmc_rply_jttr_min_msecs_ktime;
	}

	return kt;

}


/*
 * ectp_ms_to_ktime()
 *
 * Convert milliseconds into ktime
 */
static ktime_t ectp_ms_to_ktime(const unsigned int msecs)
{


	return ns_to_ktime(msecs * NSEC_PER_MSEC);

}


/*
 * ectp_build_tx_skb_ok()
 *
 * build the ECTP tx skb, by modifying the rx'd skb or a copy of it
 * if it is shared. rx'd skb is assumed to be linear.
 */
static bool ectp_build_tx_skb_ok(struct sk_buff *rx_skb,
				 struct sk_buff **tx_skb_p,
				 const uint32_t tx_prio)
{
	struct sk_buff *trailer;
	struct ectp_packet *ectp_pkt;
	uint8_t *fwdaddr;


	*tx_skb_p = skb_share_check(rx_skb, GFP_ATOMIC);
	if (*tx_skb_p == NULL)
		return false;

	if (skb_cow_data(*tx_skb_p, 0, &trailer) < 0) {
		if (*tx_skb_p != rx_skb)
			kfree_skb(*tx_skb_p);
		return false;
	}

	(*tx_skb_p)->priority = tx_prio;
	(*tx_skb_p)->ip_summed = CHECKSUM_NONE;

	ectp_pkt = (struct ectp_packet *)skb_network_header(*tx_skb_p);

	fwdaddr = ectp_get_fwdaddr(ectp_get_curr_msg_ptr(ectp_pkt));

	ectp_inc_skipcount(ectp_pkt);

	(*tx_skb_p)->dev->header_ops->create(*tx_skb_p, (*tx_skb_p)->dev,
					     ETH_P_ECTP, fwdaddr, NULL, 0);

	return true;

}


/*
 * ectp_build_delayed_tx_skb_ok()
 *
 * Build a delayed tx skb
 */
static bool ectp_build_delayed_tx_skb_ok(struct sk_buff *rx_skb,
					 struct sk_buff **tx_skb_p,
					 const uint32_t tx_prio,
					 const ktime_t delay)
{


	if (!ectp_build_tx_skb_ok(rx_skb, tx_skb_p, ectp_uc_rply_skb_prio))
		return false;

	if (!(rx_skb->tstamp.tv64))
		__net_timestamp(*tx_skb_p);

	(*tx_skb_p)->tstamp = ktime_add((*tx_skb_p)->tstamp, delay);

	return true;

}


/*
 * ectp_queue_delayed_tx_skb()
 *
 * Queue a skb for delayed delivery.
 */
static void ectp_queue_delayed_tx_skb(struct ectp_reply_queue *rply_q,
				      struct sk_buff *tx_skb)
{
	struct sk_buff *skb;
	bool rply_q_full = false;


	spin_lock_bh(&rply_q->skb_q.spinlock);

	if (likely(!ectp__skb_q_full(&rply_q->skb_q))) {

		if (likely(skb_queue_empty(&rply_q->skb_q.head))) {
			skb_queue_tail(&rply_q->skb_q.head, tx_skb);
			ectp_rply_q_kernt_start(rply_q, tx_skb->tstamp);
		} else {
			skb_queue_reverse_walk(&rply_q->skb_q.head, skb) {
				if (tx_skb->tstamp.tv64 >= skb->tstamp.tv64)
					break;
			}
			skb_append(skb, tx_skb, &rply_q->skb_q.head);

			if (skb_queue_is_first(&rply_q->skb_q.head, tx_skb))
				ectp_rply_q_kernt_try_resched(rply_q,
							      tx_skb->tstamp);
		}
	} else {
		rply_q_full = true;
	}

	spin_unlock_bh(&rply_q->skb_q.spinlock);

	if (rply_q_full)
		kfree_skb(tx_skb);

}


/*
 * ectp__skb_q_full();
 *
 * Is specified skb queue full?
 *
 * n.b. doesn't hold a lock on the queue, so it's caller needs to
 */
static bool ectp__skb_q_full(struct ectp_skb_queue *skb_q)
{


	if (unlikely(skb_queue_len(&skb_q->head) >= skb_q->maxlen))
		return true;
	else
		return false;

}


/*
 * ectp_rply_q_kernt_start()
 *
 * Start the kernel timer associated with the specified reply queue. The
 * kernel timer will start dequeuing and tx'ing skbs on the reply queue
 */
static void ectp_rply_q_kernt_start(struct ectp_reply_queue *rply_q,
				    const ktime_t start_ktime)
{


	rply_q->resched_q_kernt = true;
	hrtimer_start_range_ns(&rply_q->q_hrt_kernt, start_ktime,
			       ectp_hrt_range_ns, HRTIMER_MODE_ABS);

}


/*
 * ectp_rply_q_kernt_try_resched()
 *
 * Try to reschedule an active kernel timer.
 */
static void ectp_rply_q_kernt_try_resched(struct ectp_reply_queue *rply_q,
					  const ktime_t start_ktime)
{


	if (hrtimer_try_to_cancel(&rply_q->q_hrt_kernt) == 1) {
		hrtimer_start_range_ns(&rply_q->q_hrt_kernt, start_ktime,
				       ectp_hrt_range_ns, HRTIMER_MODE_ABS);
	}


}

/*
 * ectp_rply_q_kernt_try_stop()
 *
 * Try to stop the kernel timer associated with the specified reply queue,
 * also preventing it from being rescheduled
 */
static void ectp_rply_q_kernt_try_stop(struct ectp_reply_queue *rply_q)
{


	rply_q->resched_q_kernt = false;
	hrtimer_try_to_cancel(&rply_q->q_hrt_kernt);

}

/*
 * ectp_rply_q_kernt_stop()
 *
 * Stop the kernel timer associated with the specified reply queue,
 * also preventing it from being rescheduled
 */
static void ectp_rply_q_kernt_stop(struct ectp_reply_queue *rply_q)
{


	rply_q->resched_q_kernt = false;
	hrtimer_cancel(&rply_q->q_hrt_kernt);

}


/*
 * ectp_bmc_sched_tasklet()
 *
 * high res timer function to schedule the bmc tasklet. the tasklet does
 * the sending of the skb at the head of the queue, and the rescheduling
 * of the timer
 */
static enum hrtimer_restart ectp_bmc_sched_tasklet(struct hrtimer *timer)
{


	tasklet_hi_schedule(&ectp_bmc_rply_q.q_tasklet);

	return HRTIMER_NORESTART;

}


/*
 * ectp_bmc_tx_skb()
 *
 * tasklet to send head skb on bmc reply queue, and reschedule
 * hrtimer for skbs left on queue if there are any
 */
static void ectp_bmc_tx_skb(unsigned long data)
{
	struct sk_buff *head_skb;
	struct sk_buff *tx_skb;


	spin_lock_bh(&ectp_bmc_rply_q.skb_q.spinlock);

	if (!ectp_bmc_rply_q.resched_q_kernt) {
		spin_unlock_bh(&ectp_bmc_rply_q.skb_q.spinlock);
		return;
	}

	if (skb_queue_empty(&ectp_bmc_rply_q.skb_q.head)) {
		spin_unlock_bh(&ectp_bmc_rply_q.skb_q.spinlock);
		return;
	}

	tx_skb = skb_dequeue(&ectp_bmc_rply_q.skb_q.head);

	if (unlikely(!skb_queue_empty(&ectp_bmc_rply_q.skb_q.head))) {
		head_skb = skb_peek(&ectp_bmc_rply_q.skb_q.head);
		ectp_rply_q_kernt_start(&ectp_bmc_rply_q, head_skb->tstamp);

		spin_unlock_bh(&ectp_bmc_rply_q.skb_q.spinlock);

		dev_queue_xmit(tx_skb);
	} else {
		spin_unlock_bh(&ectp_bmc_rply_q.skb_q.spinlock);

		dev_queue_xmit(tx_skb);
	}

}


#ifdef CONFIG_SYSCTL
/*
 * sysctl / /proc/sys/net/ectp handlers
 */

/*
 * ectp_sysctl_bmc_rply_jttr_randmask_len()
 *
 * sysctl function to convert supplied random mask length into bitmask
 */
static int ectp_sysctl_bmc_rply_jttr_randmask_len(ctl_table *table,
						  int write,
						  struct file *filp,
						  void __user *buffer,
						  size_t *lenp,
						  loff_t *ppos)
{
	int ret;


	ret = proc_dointvec_minmax(table, write, filp, buffer, lenp, ppos);

	if (write && (!ret))
		ectp_bmc_rply_jttr_randmask =
			(1 << ectp_bmc_rply_jttr_randmask_len) - 1;

	return ret;

}


/*
 * ectp_sysctl_uc_prio_ctrl()
 *
 * sysctl function to set ectp_uc_rply_skb_prio to either TC_PRIO_CONTROL or
 * TC_PRIO_BESTEFFORT
 */
static int ectp_sysctl_uc_prio_ctrl(ctl_table *table,
				    int write,
				    struct file *filp,
				    void __user *buffer,
				    size_t *lenp,
				    loff_t *ppos)
{
	int ret;


	ret = proc_dointvec_minmax(table, write, filp, buffer, lenp, ppos);

	if (write && (!ret)) {
		if (ectp_uc_rply_prio_ctrl)
			ectp_uc_rply_skb_prio = TC_PRIO_CONTROL;
		else
			ectp_uc_rply_skb_prio = TC_PRIO_BESTEFFORT;
	}

	return ret;

}


/*
 * ectp_sysctl_bmc_rply_jttr_min_msecs()
 *
 * sysctl function to convert supplied bmc delay msecs into ktime
 */
static int ectp_sysctl_bmc_rply_jttr_min_msecs(ctl_table *table,
					       int write,
					       struct file *filp,
					       void __user *buffer,
					       size_t *lenp,
					       loff_t *ppos)
{
	int ret;


	ret = proc_dointvec_minmax(table, write, filp, buffer, lenp, ppos);

	if (write && (!ret))
		ectp_bmc_rply_jttr_min_msecs_ktime =
			ectp_ms_to_ktime(ectp_bmc_rply_jttr_min_msecs);

	return ret;

}

#endif /* CONFIG_SYSCTL */


/*
 * ECTP packet utility functions
 */

/*
 * ectp_htons()
 *
 * ECTP host order to network order
 */
static inline uint16_t ectp_htons(uint16_t i)
{


	return cpu_to_le16(i);

}


/*
 * ectp_ntohs()
 *
 * ECTP network order to host order
 */
static inline uint16_t ectp_ntohs(uint16_t i)
{


	return le16_to_cpu(i);

}


/*
 * ectp_get_skipcount()
 *
 * Get the skipcount value from a ectp packet, and return it in host order
 */
static unsigned int ectp_get_skipcount(const struct ectp_packet *ectp_pkt)
{


	return (unsigned int) ectp_ntohs(ectp_pkt->hdr.skipcount);

}


/*
 * ectp_set_skipcount()
 *
 * Set the skipcount value in an ectp packet, supplied in host order
 */
static void ectp_set_skipcount(struct ectp_packet *ectp_pkt,
			       const unsigned int skipcount)
{


	ectp_pkt->hdr.skipcount = ectp_htons((uint16_t)skipcount);

}


/*
 * ectp_get_msg_ptr()
 *
 * Returns a pointer to the message pointed to by the supplied skipcount
 * value.
 */
static struct ectp_message *ectp_get_msg_ptr(const unsigned int skipcount,
					     const struct ectp_packet
						*ectp_pkt)
{

	return (struct ectp_message *)&(ectp_pkt->payload[skipcount]);

}


/*
 * ectp_get_curr_msg_ptr()
 *
 * Returns a pointer to the message pointed to by skipcount in the supplied
 * ECTP packet
 */
static struct ectp_message *ectp_get_curr_msg_ptr(const struct ectp_packet
							*ectp_pkt)
{


	return ectp_get_msg_ptr(ectp_get_skipcount(ectp_pkt), ectp_pkt);

}


/*
 * ectp_get_msg_type()
 *
 * Returns the numeric message type value in host order for the supplied
 * message
 */
static uint16_t ectp_get_msg_type(const struct ectp_message *ectp_msg)
{


	return ectp_ntohs(ectp_msg->hdr.func_code);

}

/*
 * ectp_fwdaddr_ok()
 *
 * checks if supplied forward message address is ok
 */
static bool ectp_fwdaddr_ok(const uint8_t fwdaddr[ETH_ALEN])
{

	if (likely(!is_multicast_ether_addr((u8 *)fwdaddr)))
		return true;
	else
		return false;

}


/*
 * ectp_get_fwdaddr()
 *
 * Returns a pointer to the forwarding address in the supplied forward
 * message
 */
static uint8_t *ectp_get_fwdaddr(const struct ectp_message *ectp_fwd_msg)
{


	return (uint8_t *) ectp_fwd_msg->fwd_msg.fwdaddr;

}


/*
 * ectp_inc_skipcount()
 *
 * Makes skipcount point to the next ECTP message in the supplied packet
 */
static void ectp_inc_skipcount(struct ectp_packet *ectp_pkt)
{
	unsigned int skipcount;


	skipcount = ectp_get_skipcount(ectp_pkt);

	skipcount += (ECTP_MSG_HDR_SZ + ECTP_FWDMSG_SZ);

	ectp_set_skipcount(ectp_pkt, skipcount);

}



/*
 * ectp_init()
 *
 * Initialise ECTP protocol / module
 */
static int __init ectp_init(void)
{


	ectp_init_ktimes();

	ectp_setup_bmc_rply_q();

	ectp_setup_ifaces();

	ectp_register_packet_hdlr();

	ectp_register_sysctl();

	ectp_print_banner();

	return 0;

}


/*
 * ectp_exit()
 *
 * Shutdown ECTP protocol / module
 */
static void __exit ectp_exit(void)
{


	ectp_unregister_sysctl();

	ectp_unregister_packet_hdlr();

	ectp_reset_ifaces();

	ectp_shutdown_bmc_rply_q();

	ectp_allifaces_netdev_put();

}


module_init(ectp_init);
module_exit(ectp_exit);

/* EOF */
