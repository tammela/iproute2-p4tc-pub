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
#include "p4_types.h"
#include <limits.h>
#include <stdbool.h>

/* XXX: Introspection will do this properly.
 * For now we are using our own format, see: file introspection/ptables
 */
static int p4tc_find_obj(FILE *f, const char *obj_name, const __u32 objid,
			 const char *obj_type)
{
	const size_t tobj_len = strlen(obj_type);
	char parsed_obj_name[TEMPLATENAMSZ];
	size_t obj_name_len = 0;
	char *line = NULL;
	size_t len = 0;
	char fmtstr[32] = {0};
	__u32 parsed_objid;

	if (!obj_name && !objid) {
		fprintf(stderr, "Must specify object name or id\n");
		return -1;
	}

	if (obj_name)
		obj_name_len = strlen(obj_name);

	strcpy(fmtstr, obj_type);
	strcat(fmtstr, "%s %u");
	while (getline(&line, &len, f) != -1) {
		char *objline = strstr(line, obj_type);

		if (!objline)
			continue;
		const size_t objline_len = strlen(objline);

		if (objline_len < obj_name_len + tobj_len)
			continue;

		if (sscanf(objline, fmtstr, parsed_obj_name, &parsed_objid) != 2) {
			fprintf(stderr, "Invalid file format\n");
			return -1;
		}

		if (objid && parsed_objid == objid)
			return 0;

		if (obj_name_len && strncmp(parsed_obj_name, obj_name, obj_name_len) == 0)
			return 0;
	}

	return -1;
}

#define find_table(f, obj_name, objid) (p4tc_find_obj(f, obj_name, objid, "table "))

#define p4tc_find_header(f, obj_name, objid) (p4tc_find_obj(f, obj_name, objid, "header "))

int p4tc_get_header_fields(struct hdrfield fields[], const char *pname,
			   const char *hdrname)
{
	int i = 0;
	__u16 hdr_offset = 0;
	char *line = NULL;
	char field_name[TEMPLATENAMSZ];
	char type_str[32];
	char path[PATH_MAX];
	char field_str[6];
	size_t len;
	FILE *f;
	int ret;

	if (!getenv(ENV_VAR)) {
		fprintf(stderr, "INTROSPECTION Environment variable not set\n");
		return -1;
	}

	if (!pname) {
		fprintf(stderr, "Must specify pipeline name for introspection");
		return -1;
	}

	if (snprintf(path, PATH_MAX, "%s/%s", getenv(ENV_VAR), pname) >= PATH_MAX) {
		fprintf(stderr, "Pipeline name too long\n");
		return -1;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	if (p4tc_find_header(f, hdrname, 0) < 0) {
		fprintf(stderr, "Unable to find header %s in introspection file\n",
			hdrname);
		ret = -1;
		goto out;
	}

	while (getline(&line, &len, f) != -1) {
		__u32 bitsz = 0;
		struct p4_type_s *p4_type;
		int scanned;
		__u32 id;

		scanned = sscanf(line, "%s %s %s %u[^\n]", field_str, field_name,
				 type_str, &id);

		if (scanned != 4)
			break;
		if (strcmp(field_str, "field") != 0)
			continue;

		p4_type = get_p4type_byarg(type_str, &bitsz);
		if (!p4_type) {
			fprintf(stderr, "Invalid P4 type %s\n", type_str);
			ret = -1;
			goto out;
		}

		bitsz = bitsz ? bitsz : p4_type->bitsz;

		fields[i].id = id;
		fields[i].ty = p4_type;

		fields[i].startbit = hdr_offset;
		fields[i].endbit = fields[i].startbit + bitsz - 1;
		strcpy(fields[i].name, field_name);

		hdr_offset += bitsz;
		i++;
	}
	ret = i;

out:
	fclose(f);
	return ret;

}

struct hdrfield *p4tc_find_hdrfield(struct hdrfield fields[],
				    const char *fieldname,
				    __u32 num_fields)
{
	int i;

	for (i = 0; i < num_fields; i++) {
		if (strncmp(fields[i].name, fieldname, TEMPLATENAMSZ) == 0)
			return &fields[i];
	}

	return NULL;
}

int p4tc_get_table_keys(struct tkey keys[], const char *pname,
			const char *tname, const __u32 tbc_id)
{
	int i = 0;
	char *line = NULL;
	char key_name[TABLEKEYNAMSIZ];
	char type_str[TCLASSNAMSIZ];
	char path[PATH_MAX];
	char key_str[4];
	size_t len;
	FILE *f;
	int ret;

	if (!getenv(ENV_VAR))
		return -1;

	if (!pname)
		return -1;

	if (snprintf(path, PATH_MAX, "%s/%s", getenv(ENV_VAR), pname) >= PATH_MAX)
		return -1;

	f = fopen(path, "r");
	if (f == NULL)
		return -1;

	if (find_table(f, tname, tbc_id) < 0) {
		ret = -1;
		goto out;
	}

	while (getline(&line, &len, f) != -1) {
		struct p4_type_s *p4_type;
		int scanned;
		__u32 bitsz;

		scanned = sscanf(line, "%s %s %s[^\n]", key_str, key_name,
				 type_str);
		if (scanned != 3)
			break;
		if (strcmp(key_str, "key") != 0)
			continue;

		p4_type = get_p4type_byarg(type_str, &bitsz);
		if (!p4_type)
			return -1;
		strncpy(keys[i].name, key_name, ACTPARAMNAMSIZ);
		keys[i].type = p4_type;
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
