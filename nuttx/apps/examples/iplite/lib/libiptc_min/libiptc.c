/*
	DON'T USE THE TYPE DEFINITIONS BELOW!
	We need to choose the right data types.
	NuttX has a bunch of definitions accordingly to each structure.
	
	Check it out:
	https://nuttx.apache.org/docs/latest/reference/user/structures.html
	http://nuttx.incubator.apache.org/docs/latest/contributing/coding_style.html
	https://github.com/robbie-cao/nuttx/blob/master/include/sys/types.h
	
	TODO: Ask Lourenço how can we choose the types correctly
*/

#include <xtcshared.h>
#include "linux_list.h"

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