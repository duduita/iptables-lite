#include <nuttx/include/net/if.h>
#include <lib/netfilter_min/x_tables.h>

/*
	DON'T USE THE TYPE DEFINITIONS BELOW!
	We need to choose the right data types.
	NuttX has a bunch of definitions accordingly to each structure.
	
	Check it out:
	https://nuttx.apache.org/docs/latest/reference/user/structures.html
	http://nuttx.incubator.apache.org/docs/latest/contributing/coding_style.html
	https://github.com/robbie-cao/nuttx/blob/master/include/sys/types.h
	
	TODO: Ask Risadolas how can we choose the types correctly
	TODO: Ask Risadolas why libiptc functions are defined instead of being called directly
*/

typedef unsigned char __u8;
typedef unsigned short __u16;

/* Yes, Virginia, you have to zero the padding. */
struct ipt_ip {
	/* Source and destination IP addr */
	struct in_addr src, dst;
	/* Mask for src and dest IP addr */
	struct in_addr smsk, dmsk;
	char iniface[IFNAMSIZ], outiface[IFNAMSIZ];
	unsigned char iniface_mask[IFNAMSIZ], outiface_mask[IFNAMSIZ];

	/* Protocol, 0 = ANY */
	__u16 proto;

	/* Flags word */
	__u8 flags;
	/* Inverse flags */
	__u8 invflags;
};

/* This structure defines each of the firewall rules.  Consists of 3
   parts which are 1) general IP header stuff 2) match specific
   stuff 3) the target to perform if the rule matches */
struct ipt_entry {
	struct ipt_ip ip;

	/* Mark with fields that we care about. */
	unsigned int nfcache;

	/* Size of ipt_entry + matches */
	__u16 target_offset;
	/* Size of ipt_entry + matches + target */
	__u16 next_offset;

	/* Back pointer */
	unsigned int comefrom;

	/* Packet and byte counters. */
	struct xt_counters counters;

	/* The matches (if any), then the target. */
	unsigned char elems[0];
};