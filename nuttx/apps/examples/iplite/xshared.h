#ifndef IPTABLES_XSHARED_H
#define IPTABLES_XSHARED_H 1

#include "lib/netfilter_ipv4_min/ip_tables.h"

enum {
	OPT_NONE        = 0,
	OPT_NUMERIC     = 1 << 0,
	OPT_SOURCE      = 1 << 1,
	OPT_DESTINATION = 1 << 2,
	OPT_PROTOCOL    = 1 << 3,
	OPT_JUMP        = 1 << 4,
	OPT_VERBOSE     = 1 << 5,
	OPT_EXPANDED    = 1 << 6,
	OPT_VIANAMEIN   = 1 << 7,
	OPT_VIANAMEOUT  = 1 << 8,
	OPT_LINENUMBERS = 1 << 9,
	OPT_COUNTERS    = 1 << 10,
	OPT_FRAGMENT	= 1 << 11,
	/* below are for arptables only */
	OPT_S_MAC	= 1 << 12,
	OPT_D_MAC	= 1 << 13,
	OPT_H_LENGTH	= 1 << 14,
	OPT_OPCODE	= 1 << 15,
	OPT_H_TYPE	= 1 << 16,
	OPT_P_TYPE	= 1 << 17,
};

enum {
	CMD_NONE		= 0,
	CMD_INSERT		= 1 << 0,
	CMD_DELETE		= 1 << 1,
	CMD_DELETE_NUM		= 1 << 2,
	CMD_REPLACE		= 1 << 3,
	CMD_APPEND		= 1 << 4,
	CMD_LIST		= 1 << 5,
	CMD_FLUSH		= 1 << 6,
	CMD_ZERO		= 1 << 7,
	CMD_NEW_CHAIN		= 1 << 8,
	CMD_DELETE_CHAIN	= 1 << 9,
	CMD_SET_POLICY		= 1 << 10,
	CMD_RENAME_CHAIN	= 1 << 11,
	CMD_LIST_RULES		= 1 << 12,
	CMD_ZERO_NUM		= 1 << 13,
	CMD_CHECK		= 1 << 14,
};

struct iptables_command_state {
	union {
		struct ebt_entry eb;
		struct ipt_entry fw;
		struct ip6t_entry fw6;
		struct arpt_entry arp;
	};
	int c;
	unsigned int options;
	struct xtables_rule_match *matches;
	struct ebt_match *match_list;
	struct xtables_target *target;
	struct xt_counters counters;
	char *protocol;
	int proto_used;
	const char *jumpto;
	char **argv;
	bool restore;
};

#endif /* IPTABLES_XSHARED_H */
