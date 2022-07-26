/*
 * p4tc_names.c		P4 TC entity names DB.
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <dirent.h>
#include <limits.h>

#include <asm/types.h>
#include <linux/rtnetlink.h>

#include "p4tc_names.h"
#include "names.h"
#include "utils.h"

static char *p4tc_ctrlent_tab[256];

static int p4tc_ctrlent_init;

/* Not able to detect duplicate names, only ID */
static void p4tc_ctrlent_initialise(void)
{
	struct dirent *de;
	DIR *d;

	p4tc_ctrlent_init = 1;
	names_tab_initialize(CONFDIR "/p4tc_entities",
			    p4tc_ctrlent_tab, 256);

	d = opendir(CONFDIR "/p4tc_entities.d");
	if (!d) {
		fprintf(stderr, "Unable to open p4tc_entities dir\n");
		return;
	}

	while ((de = readdir(d)) != NULL) {
		char path[PATH_MAX];
		size_t len;

		if (*de->d_name == '.')
			continue;

		len = strlen(de->d_name);
		if (len <= 5)
			continue;
		/* Must only consider files ending with ".conf" */
		if (strcmp(de->d_name + len - 5, ".conf"))
			continue;

		snprintf(path, sizeof(path), CONFDIR "/p4tc_entities.d/%s",
			 de->d_name);
		names_tab_initialize(path, p4tc_ctrlent_tab, 256);
	}
	closedir(d);
}

/* Jamal: Should we return char *, or create some structure to put in the table?
 */
int p4tc_ctrltable_getbyid(__u8 id, char *str)
{
	if (!p4tc_ctrlent_init)
		p4tc_ctrlent_initialise();

	if (id >= 256) {
		fprintf(stderr, "id must be smaller than 256");
		return -1;
	}

	if (p4tc_ctrlent_tab[id]) {
		strncpy(str, p4tc_ctrlent_tab[id], NAME_MAX_LEN);
		return 0;
	}

	fprintf(stderr, "Control entity id not found\n");
	return -1;
}
