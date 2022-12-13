/*
 * p4_tc_introspection.c	P4 TC Introspection
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

#include "p4tc_introspection.h"
#include <limits.h>
#include <stdbool.h>
#include <dirent.h>

static char *get_introspection_path(void)
{
	if (!getenv(ENV_VAR))
		return INTROSPECTION_PATH;

	return getenv(ENV_VAR);
}

static int concat_pipeline_path(char *path, const char *pname)
{
	char *introspection_path = get_introspection_path();
	int ret;

	ret = snprintf(path, PATH_MAX, "%s/%s", introspection_path,
		       pname);
	if (ret < 0) {
		fprintf(stderr, "Pipeline name too long\n");
		return -1;
	}

	return 0;
}

/* XXX: Introspection will do this properly.
 * For now we are using our own format, see: file introspection/ptables
 */
static int p4tc_find_obj(FILE *f, const char *obj_name, __u32 *pipeid,
			 __u32 *objid, const char *obj_type)
{
	const size_t tobj_len = strlen(obj_type);
	char parsed_obj_name[TEMPLATENAMSZ];
	size_t obj_name_len = 0;
	char *line = NULL;
	size_t len = 0;
	char fmtstr[256] = {0};
	__u32 parsed_pipeid, parsed_objid;

	if (!obj_name && !*objid) {
		fprintf(stderr, "Must specify object name or id\n");
		return -1;
	}

	if (obj_name)
		obj_name_len = strlen(obj_name);

	strcpy(fmtstr, obj_type);
	strcat(fmtstr, "%s %u %u");

	while (getline(&line, &len, f) != -1) {
		char *objline = strstr(line, obj_type);

		if (!objline)
			continue;
		const size_t objline_len = strlen(objline);

		if (objline_len < obj_name_len + tobj_len)
			continue;

		if (sscanf(objline, fmtstr, parsed_obj_name, &parsed_pipeid, &parsed_objid) != 3) {
			fprintf(stderr, "Invalid file format\n");
			return -1;
		}

		if ((!*pipeid || (*pipeid && parsed_pipeid == *pipeid)) &&
		    *objid && parsed_objid == *objid)
			return 0;

		if (obj_name_len && strncmp(parsed_obj_name, obj_name, obj_name_len) == 0) {
			if (*pipeid) {
				if (*pipeid != parsed_pipeid)
					continue;
			} else {
				*pipeid = parsed_pipeid;
			}
			if (!*objid)
				*objid = parsed_objid;
			return 0;
		}
	}

	return -1;
}

#define find_table(f, obj_name, pipeid, objid) (p4tc_find_obj(f, obj_name, pipeid, objid, "table "))

int p4tc_get_tables(const char *pname, const char *tname, __u32 *pipeid,
		    __u32 *tbcid)
{
	char path[PATH_MAX];
	FILE *f;
	int ret;

	if (!getenv(ENV_VAR))
		ret = snprintf(path, PATH_MAX, "%s/%s", INTROSPECTION_PATH,
			       pname);
	else
		ret = snprintf(path, PATH_MAX, "%s/%s", getenv(ENV_VAR),
			       pname);

	if (ret < 0) {
		fprintf(stderr, "Pipeline name too long\n");
		return -1;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	if (find_table(f, tname, pipeid, tbcid) < 0)
		return -1;

	return 0;
}

int p4tc_get_table_keys(struct tkey keys[], const char *pname,
			const char *tname, __u32 tbl_id)
{
	int i = 0;
	char *line = NULL;
	__u32 pipeid = 0;
	char key_name[TABLEKEYNAMSIZ];
	char type_str[TABLENAMSIZ];
	char path[PATH_MAX];
	char key_str[4];
	size_t len;
	FILE *f;
	int ret;

	if (!pname)
		return -1;

	if (concat_pipeline_path(path, pname) < 0)
		return -1;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	if (find_table(f, tname, &pipeid, &tbl_id) < 0) {
		ret = -1;
		goto out;
	}

	while (getline(&line, &len, f) != -1) {
		struct p4_type_s *p4_type;
		int scanned;
		__u32 bitsz;
		__u32 key_id;

		scanned = sscanf(line, "%s %s %s %u[^\n]", key_str, key_name,
				 type_str, &key_id);
		if (scanned != 4)
			break;
		if (strcmp(key_str, "key") != 0)
			continue;

		p4_type = get_p4type_byarg(type_str, &bitsz);
		if (!p4_type)
			return -1;
		strncpy(keys[i].name, key_name, ACTPARAMNAMSIZ);
		keys[i].type = p4_type;
		keys[i].key_id = key_id;
		i++;
	}
	ret = i;

	fclose(f);
	return ret;

out:
	fclose(f);
	return ret;
}

struct tkey *p4tc_find_table_key(struct tkey keys[], const char *key_name,
				 __u32 num_keys)
{
	int i;

	for (i = 0; i < num_keys; i++) {
		if (strncmp(keys[i].name, key_name, TABLEKEYNAMSIZ) == 0)
			return &keys[i];
	}

	return NULL;
}
