#ifndef _NET_INET_ECTP_H_
#define _NET_INET_ECTP_H_

/*
 *	ectp.h
 *
 *	Ethernet Configuration Testing Protocol (ECTP) defines and structures
 *
 */

#include <linux/types.h>
#include <linux/if_ether.h>


/*
 * ECTP loopback assistance multicast address
 */
#define ECTP_LA_MCADDR { 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00 }


/*
 * Function Code field values
 */

enum {
	ECTP_RPLYMSG		= 1,	/* Reply message */
	ECTP_FWDMSG		= 2,	/* Forward message */
};


/*
 * ECTP packet structures
 */


/*
 * ECTP common header - only consists of the single 2 octet skip count
 * field.
 *
 * note: skipcount is little endian, i.e. _not_ traditional big endian
 * network order - don't use traditional ntohs() or htons() functions
 * on it, because they won't work.
 */
struct ectp_packet_header {
	uint16_t skipcount;
} __attribute__ ((packed));


/*
 * ECTP packet
 */
struct ectp_packet {
	struct ectp_packet_header hdr;
	uint8_t payload[];
} __attribute__ ((packed));


/*
 * ECTP Message Header
 */
struct ectp_message_header {
	uint16_t func_code;
} __attribute__ ((packed));


/*
 * ECTP Reply Message (minus Function Code field)
 */
struct ectp_reply_message {
	uint16_t rcpt_num;
	uint8_t data[];
} __attribute__ ((packed));


/*
 * ECTP Forward Message (minus Function Code field)
 */
struct ectp_forward_message {
	uint8_t fwdaddr[ETH_ALEN];
} __attribute__ ((packed));


/*
 * ECTP Message
 */
struct ectp_message {
	struct ectp_message_header hdr;
	union {
		struct ectp_forward_message fwd_msg;
		struct ectp_reply_message rply_msg;
	};
} __attribute__ ((packed));


/*
 * ECTP protocol header sizes
 */
enum {
	ECTP_SKIPCOUNT_HDR_SZ	= sizeof(struct ectp_packet_header),
	ECTP_MSG_HDR_SZ		= sizeof(struct ectp_message_header),
	ECTP_FWDMSG_SZ		= sizeof(struct ectp_forward_message),
	ECTP_REPLYMSG_MINSZ	= sizeof(struct ectp_reply_message),
};


#endif /* _NET_INET_ECTP_H_ */

/* EOF */
