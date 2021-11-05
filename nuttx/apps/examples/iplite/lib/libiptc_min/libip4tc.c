#include <lib/netfilter_ipv4_min/ip_tables.h>
#include "libiptc.h"

#define STRUCT_ENTRY		struct ipt_entry
#define STRUCT_GETINFO		struct ipt_getinfo
#define STRUCT_GET_ENTRIES	struct ipt_get_entries
#define STRUCT_COUNTERS		struct xt_counters

#define TABLE_MAXNAMELEN	XT_TABLE_MAXNAMELEN