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
	printf("Hello World!");

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

	printf("insert_entry executed -> res = %d\n", res);

	return 0;
}
