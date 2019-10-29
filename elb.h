#if !defined(_KKAI_ETH_LOOPBACK_TEST_H)
#define _KKAI_ETH_LOOPBACK_TEST_H

#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#if defined(__cplusplus)
extern "C" {
#endif/*defined(__cplusplus)*/

#if !defined(_DBG_PREF)
#define _DBG_PREF       "ELB-DEV"
#endif/*!defined(_DBG_PREF)*/

extern int  dbg_elb_kkai;

struct elb_test_stat {
};

struct elb_test_sess {
	// config fields
	char    conf_ifname[IFNAMSIZ];
	int     conf_pktsize;

	int     stat_running;

	struct net_device *sess_dev;

	struct work_struct    sess_work;

	struct sk_buff_head   sess_queue;
	struct elb_test_stat  sess_stat;
};

#if defined(__cplusplus)
}
#endif/*defined(__cplusplus)*/
#endif/*!defined(_KKAI_ETH_LOOPBACK_TEST_H)*/

