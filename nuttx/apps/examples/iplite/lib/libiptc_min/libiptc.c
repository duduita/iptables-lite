#include <xtcshared.h>
#include "linux_list.h"
#include "libip4tc.c"

/* Convenience structures */
struct chain_head;
struct rule_head;

struct counter_map
{
	enum {
		COUNTER_MAP_NOMAP,
		COUNTER_MAP_NORMAL_MAP,
		COUNTER_MAP_ZEROED,
		COUNTER_MAP_SET
	} maptype;
	unsigned int mappos;
};

enum iptcc_rule_type {
	IPTCC_R_STANDARD,		/* standard target (ACCEPT, ...) */
	IPTCC_R_MODULE,			/* extension module (SNAT, ...) */
	IPTCC_R_FALLTHROUGH,		/* fallthrough rule */
	IPTCC_R_JUMP,			/* jump to other chain */
};

struct rule_head
{
	struct list_head list;
	struct chain_head *chain;
	struct counter_map counter_map;

	unsigned int index;		/* index (needed for counter_map) */
	unsigned int offset;		/* offset in rule blob */

	enum iptcc_rule_type type;
	struct chain_head *jump;	/* jump target, if IPTCC_R_JUMP */

	unsigned int size;		/* size of entry data */
	STRUCT_ENTRY entry[0];
};

struct chain_head
{
	struct list_head list;
	char name[TABLE_MAXNAMELEN];
	unsigned int hooknum;		/* hook number+1 if builtin */
	unsigned int references;	/* how many jumps reference us */
	int verdict;			/* verdict if builtin */

	STRUCT_COUNTERS counters;	/* per-chain counters */
	struct counter_map counter_map;

	unsigned int num_rules;		/* number of rules in list */
	struct list_head rules;		/* list of rules */

	unsigned int index;		/* index (needed for jump resolval) */
	unsigned int head_offset;	/* offset in rule blob */
	unsigned int foot_index;	/* index (needed for counter_map) */
	unsigned int foot_offset;	/* offset in rule blob */
};

struct xtc_handle {
	int sockfd;
	int changed;			 /* Have changes been made? */

	struct list_head chains;

	struct chain_head *chain_iterator_cur;
	struct rule_head *rule_iterator_cur;

	unsigned int num_chains;         /* number of user defined chains */

	struct chain_head **chain_index;   /* array for fast chain list access*/
	unsigned int        chain_index_sz;/* size of chain index array */

	int sorted_offsets; /* if chains are received sorted from kernel,
			     * then the offsets are also sorted. Says if its
			     * possible to bsearch offsets using chain_index.
			     */

	STRUCT_GETINFO info;
	STRUCT_GET_ENTRIES *entries;
};
