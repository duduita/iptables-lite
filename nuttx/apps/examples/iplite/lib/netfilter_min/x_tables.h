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

typedef unsigned long long __u64;

struct xt_counters {
	__u64 pcnt, bcnt;			/* Packet and byte counters */
};