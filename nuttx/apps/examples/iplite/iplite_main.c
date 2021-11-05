/****************************************************************************
 * examples/iplite/iplite_main.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdio.h>
#include "iplite.h"
#include "xshared.h"
#include "xshared.c"

/****************************************************************************
 * Definitions
 ****************************************************************************/

/* Values for "inv" field in struct ipt_ip. */
#define IPT_INV_SRCIP		0x08	/* Invert the sense of SRC IP. */
#define IPT_INV_DSTIP		0x10	/* Invert the sense of DST OP. */

#define OPT_SOURCE 0x01
#define XT_STANDARD_TARGET ""

static const char unsupported_rev[] = " [unsupported revision]";

static struct option original_opts[] = {
	{.name = "insert",        .has_arg = 1, .val = 'I'},
	{.name = "list-rules",    .has_arg = 2, .val = 'S'},
	{.name = "flush",         .has_arg = 2, .val = 'F'},
	{NULL},
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

static int insert_entry(const xt_chainlabel chain,
						struct ipt_entry *fw,	   // incompleto
						unsigned int rulenum,
						unsigned int nsaddrs,
						const struct in_addr saddrs[],
						const struct in_addr smasks[],
						unsigned int ndaddrs,
						const struct in_addr daddrs[],
						const struct in_addr dmasks[],
						int verbose,
						struct xtc_handle *handle) // incompleto
{
	printf("insert_entry executed\n");

	return 0;
}

/****************************************************************************
 * iplite_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
	printf("Hello, iplite!!\n");

	xt_chainlabel chain = "blau";
	struct ipt_entry *fw = NULL;
	unsigned int rulenum = 0;
	unsigned int nsaddrs = 0;
	struct in_addr saddrs[] = {};
	struct in_addr smasks[] = {};
	unsigned int ndaddrs = 0;
	struct in_addr daddrs[] = {};
	struct in_addr dmasks[] = {};
	int verbose = 0;
	struct xtc_handle *handle = NULL;

	int res = insert_entry(chain, fw, rulenum, nsaddrs, saddrs, smasks,
				ndaddrs, daddrs, dmasks, verbose, handle);

	printf("res = %d\n", res);

	return 0;
}



void iptables_exit_error(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf,2,3)));

struct xtables_globals iptables_globals = {
	.option_offset = 0,
	.program_version = PACKAGE_VERSION,
	.orig_opts = original_opts,
	.exit_err = iptables_exit_error,
	.compat_rev = xtables_compatible_revision,
};

#define opts iptables_globals.opts
#define prog_name iptables_globals.program_name
#define prog_vers iptables_globals.program_version

int do_command4(int argc, char *argv[], char **table,
				struct xtc_handle **handle, bool restore)
{
	struct iptables_command_state cs = {
		.jumpto	= "",
		.argv	= argv,
	};
	struct ipt_entry *e = NULL;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in_addr *saddrs = NULL, *smasks = NULL;
	struct in_addr *daddrs = NULL, *dmasks = NULL;
	struct timeval wait_interval = {
		.tv_sec = 1,
	};
	bool wait_interval_set = false;
	int verbose = 0;
	int wait = 0;
	const char *chain = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *policy = NULL, *newname = NULL;
	unsigned int rulenum = 0, command = 0;
	const char *pcnt = NULL, *bcnt = NULL;
	int ret = 1;
	struct xtables_match *m;
	struct xtables_rule_match *matchp;
	struct xtables_target *t;
	unsigned long long cnt;
	bool table_set = false;
	uint16_t invflags = 0;
	bool invert = false;

	/* re-set optind to 0 in case do_command4 gets called
	 * a second time */
	optind = 0;

	/* clear mflags in case do_command4 gets called a second time
	 * (we clear the global list of all matches for security)*/
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}

	/* Suppress error messages: we may add new options if we
           demand-load a protocol. */
	opterr = 0;
	opts = xt_params->orig_opts;
	while ((cs.c = getopt_long(argc, argv,
	   "-:A:C:D:R:I:L::S::M:F::Z::N:X::E:P:Vh::o:p:s:d:j:i:fbvw::W::nt:m:xc:g:46",
					   opts, NULL)) != -1) {
		switch (cs.c) {
			/*
			 * Command selection
			 */

		case 'I':
			add_command(&command, CMD_INSERT, CMD_NONE, invert);
			chain = optarg;
			if (xs_has_arg(argc, argv))
				rulenum = parse_rulenumber(argv[optind++]);
			else rulenum = 1;
			break;

		case 'S':
			add_command(&command, CMD_LIST_RULES,
				    CMD_ZERO|CMD_ZERO_NUM, invert);
			if (optarg) chain = optarg;
			else if (xs_has_arg(argc, argv))
				chain = argv[optind++];
			if (xs_has_arg(argc, argv))
				rulenum = parse_rulenumber(argv[optind++]);
			break;

		case 'F':
			add_command(&command, CMD_FLUSH, CMD_NONE, invert);
			if (optarg) chain = optarg;
			else if (xs_has_arg(argc, argv))
				chain = argv[optind++];
			break;

			/*
			 * Option selection
			 */

		case 's':
			set_option(&cs.options, OPT_SOURCE, &invflags, invert);
			shostnetworkmask = optarg;
			break;

		default:
			if (command_default(&cs, &iptables_globals, invert))
				/* cf. ip6tables.c */
				continue;
			break;
		}
		invert = false;
	}

	if (!wait && wait_interval_set)
		xtables_error(PARAMETER_PROBLEM,
			      "--wait-interval only makes sense with --wait\n");

	if (strcmp(*table, "nat") == 0 &&
	    ((policy != NULL && strcmp(policy, "DROP") == 0) ||
	    (cs.jumpto != NULL && strcmp(cs.jumpto, "DROP") == 0)))
		xtables_error(PARAMETER_PROBLEM,
			"\nThe \"nat\" table is not intended for filtering, "
		        "the use of DROP is therefore inhibited.\n\n");

	for (matchp = cs.matches; matchp; matchp = matchp->next)
		xtables_option_mfcall(matchp->match);
	if (cs.target != NULL)
		xtables_option_tfcall(cs.target);

	/* Fix me: must put inverse options checking here --MN */

	if (optind < argc)
		xtables_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!command)
		xtables_error(PARAMETER_PROBLEM, "no command specified");
	if (invert)
		xtables_error(PARAMETER_PROBLEM,
			   "nothing appropriate following !");

	cs.fw.ip.invflags = invflags;

	if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND | CMD_CHECK)) {
		if (!(cs.options & OPT_DESTINATION))
			dhostnetworkmask = "0.0.0.0/0";
		if (!(cs.options & OPT_SOURCE))
			shostnetworkmask = "0.0.0.0/0";
	}

	if (shostnetworkmask)
		xtables_ipparse_multiple(shostnetworkmask, &saddrs,
					 &smasks, &nsaddrs);

	if (dhostnetworkmask)
		xtables_ipparse_multiple(dhostnetworkmask, &daddrs,
					 &dmasks, &ndaddrs);

	if ((nsaddrs > 1 || ndaddrs > 1) &&
	    (cs.fw.ip.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
		xtables_error(PARAMETER_PROBLEM, "! not allowed with multiple"
			   " source or destination IP addresses");

	if (command == CMD_REPLACE && (nsaddrs != 1 || ndaddrs != 1))
		xtables_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(command, cs.options);

	/* Attempt to acquire the xtables lock */
	if (!restore)
		xtables_lock_or_exit(wait, &wait_interval);

	/* only allocate handle if we weren't called with a handle */
	if (!*handle)
		*handle = iptc_init(*table);

	/* try to insmod the module if iptc_init failed */
	if (!*handle && xtables_load_ko(xtables_modprobe_program, false) != -1)
		*handle = iptc_init(*table);

	if (!*handle)
		xtables_error(VERSION_PROBLEM,
			   "can't initialize iptables table `%s': %s",
			   *table, iptc_strerror(errno));

	if (command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_CHECK
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {
		if (strcmp(chain, "PREROUTING") == 0
		    || strcmp(chain, "INPUT") == 0) {
			/* -o not valid with incoming packets. */
			if (cs.options & OPT_VIANAMEOUT)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}

		if (strcmp(chain, "POSTROUTING") == 0
		    || strcmp(chain, "OUTPUT") == 0) {
			/* -i not valid with outgoing packets */
			if (cs.options & OPT_VIANAMEIN)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   chain);
		}

		if (cs.target && iptc_is_chain(cs.jumpto, *handle)) {
			fprintf(stderr,
				"Warning: using chain %s, not extension\n",
				cs.jumpto);

			if (cs.target->t)
				free(cs.target->t);

			cs.target = NULL;
		}

		/* If they didn't specify a target, or it's a chain
		   name, use standard. */
		if (!cs.target
		    && (strlen(cs.jumpto) == 0
			|| iptc_is_chain(cs.jumpto, *handle))) {
			size_t size;

			cs.target = xtables_find_target(XT_STANDARD_TARGET,
					 XTF_LOAD_MUST_SUCCEED);

			size = sizeof(struct xt_entry_target)
				+ cs.target->size;
			cs.target->t = xtables_calloc(1, size);
			cs.target->t->u.target_size = size;
			strcpy(cs.target->t->u.user.name, cs.jumpto);
			if (!iptc_is_chain(cs.jumpto, *handle))
				cs.target->t->u.user.revision = cs.target->revision;
			xs_init_target(cs.target);
		}

		if (!cs.target) {
			/* It is no chain, and we can't load a plugin.
			 * We cannot know if the plugin is corrupt, non
			 * existent OR if the user just misspelled a
			 * chain.
			 */
			xtables_find_target(cs.jumpto, XTF_LOAD_MUST_SUCCEED);
		} else {
			e = generate_entry(&cs.fw, cs.matches, cs.target->t);
			free(cs.target->t);
		}
	}

	switch (command) {
	case CMD_INSERT:
		ret = insert_entry(chain, e, rulenum - 1,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle);
		break;
	case CMD_FLUSH:
		ret = flush_entries4(chain, cs.options&OPT_VERBOSE, *handle);
		break;
	case CMD_LIST_RULES:
		ret = list_rules(chain,
				   rulenum,
				   cs.options&OPT_VERBOSE,
				   *handle);
		if (ret && (command & CMD_ZERO))
			ret = zero_entries(chain,
					   cs.options&OPT_VERBOSE, *handle);
		if (ret && (command & CMD_ZERO_NUM))
			ret = iptc_zero_counter(chain, rulenum, *handle);
		break;
	case CMD_SET_POLICY:
		ret = iptc_set_policy(chain, policy, cs.options&OPT_COUNTERS ? &cs.fw.counters : NULL, *handle);
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}

	if (verbose > 1)
		dump_entries(*handle);

	xtables_rule_matches_free(&cs.matches);

	if (e != NULL) {
		free(e);
		e = NULL;
	}

	free(saddrs);
	free(smasks);
	free(daddrs);
	free(dmasks);
	xtables_free_opts(1);

	return ret;
}
