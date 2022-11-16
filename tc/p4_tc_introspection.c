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

#define p4tc_find_header(f, obj_name, pipeid, objid) (p4tc_find_obj(f, obj_name, pipeid, &objid, "header "))

#define p4tc_find_act(f, obj_name, pipeid, objid) (p4tc_find_obj(f, obj_name, pipeid, objid, "action "))

int p4tc_get_header_fields(struct hdrfield fields[], const char *pname,
			   const char *hdrname, __u32 *pipeid)
{
	int i = 0;
	__u16 hdr_offset = 0;
	char *line = NULL;
	char field_name[TEMPLATENAMSZ];
	__u32 tbcid;
	char type_str[32];
	char path[PATH_MAX];
	char field_str[6];
	size_t len;
	FILE *f;
	int ret;

	if (!pname) {
		fprintf(stderr, "Must specify pipeline name for introspection");
		return -1;
	}

	if (concat_pipeline_path(path, pname) < 0)
		return -1;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	if (p4tc_find_header(f, hdrname, pipeid, tbcid) < 0) {
		fprintf(stderr, "Unable to find header %s in introspection file\n",
			hdrname);
		ret = -1;
		goto out;
	}

	while (getline(&line, &len, f) != -1) {
		__u32 bitsz = 0;
		struct p4_type_s *p4_type;
		__u32 parserid;
		int scanned;
		__u32 id;

		scanned = sscanf(line, "%s %s %s %u %u[^\n]", field_str,
				 field_name, type_str, &id, &parserid);

		if (scanned != 5)
			break;
		if (strcmp(field_str, "field") != 0)
			continue;

		p4_type = get_p4type_byarg(type_str, &bitsz);
		if (!p4_type) {
			fprintf(stderr, "Invalid P4 type %s\n", type_str);
			ret = -1;
			goto out;
		}

		fields[i].id = id;
		fields[i].parserid = parserid;
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

static int p4tc_get_pipeline_metadata(struct p4_metat_s metadata[],
				      const char *pname, int *i)
{
	char *line = NULL;
	int ret = 0;
	char m_name[TEMPLATENAMSZ];
	char type_str[32];
	char path[PATH_MAX];
	size_t len;
	FILE *f;

	if (!pname) {
		fprintf(stderr, "Must specify pipeline name for introspection");
		return -1;
	}

	if (concat_pipeline_path(path, pname) < 0)
		return -1;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		__u32 bitsz = 0;
		struct p4_type_s *p4_type;
		__u32 m_id, pipeid;
		int scanned;

		scanned = sscanf(line, "metadata %s %s %u %u[^\n]", m_name,
				 type_str, &pipeid, &m_id);

		if (scanned != 4)
			continue;

		p4_type = get_p4type_byarg(type_str, &bitsz);
		if (!p4_type) {
			fprintf(stderr, "Invalid P4 type %s\n", type_str);
			ret = -1;
			goto out;
		}

		bitsz = bitsz ? bitsz : p4_type->bitsz;

		metadata[*i].id = m_id;
		metadata[*i].containid = p4_type->containid;
		metadata[*i].startbit = p4_type->startbit;
		metadata[*i].endbit = bitsz + p4_type->startbit - 1;
		strncpy(metadata[*i].name, m_name, TEMPLATENAMSZ);
		strncpy(metadata[*i].pname, pname, TEMPLATENAMSZ);
		metadata[*i].pipeid = pipeid;

		(*i)++;
	}

out:
	fclose(f);
	return ret;
}

int p4tc_get_act(const char *pname, const char *act_name, __u32 *pipeid,
		 __u32 *act_id)
{
	int ret = 0;
	char path[PATH_MAX];
	FILE *f;

	if (concat_pipeline_path(path, pname) < 0)
		return -1;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		ret = -1;
		goto out;
	}

	if (p4tc_find_act(f, act_name, pipeid, act_id) < 0) {
		fprintf(stderr, "Unable to find action %s\n", act_name);
		ret = -1;
		goto out;
	}

out:
	fclose(f);
	return ret;
}

int p4tc_get_act_params(struct p4_param_s params[], const char *pname,
			const char *act_name, __u32 *pipeid, __u32 *act_id)
{
	char *line = NULL;
	int ret = 0;
	int i = 0;
	char param_name[TEMPLATENAMSZ];
	char path[PATH_MAX];
	char type_str[32];
	size_t len;
	FILE *f;

	if (concat_pipeline_path(path, pname) < 0)
		return -1;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Unable to open introspection file\n");
		return -1;
	}

	if (p4tc_find_act(f, act_name, pipeid, act_id) < 0) {
		fprintf(stderr, "Unable to find action %s\n", act_name);
		return -1;
	}

	while (getline(&line, &len, f) != -1) {
		__u32 bitsz = 0;
		struct p4_type_s *p4_type;
		__u32 param_id;
		int scanned;

		scanned = sscanf(line, "%s %s %u %u[^\n]", param_name,
				 type_str, pipeid, &param_id);

		if (strcmp(param_name, "action") == 0)
			break;
		if (scanned != 4)
			continue;

		/* Will have to change this to bit%u or int%u */
		scanned = sscanf(type_str, "u%u", &bitsz);
		if (scanned == 1) {
			p4_type = get_p4type_bysize(bitsz, P4T_TYPE_UNSIGNED);
			if (!p4_type) {
				fprintf(stderr, "Invalid P4 type %s\n", type_str);
				ret = -1;
				goto out;
			}
		} else {
			p4_type = get_p4type_byname(type_str);
			if (!p4_type) {
				fprintf(stderr, "Invalid P4 type %s\n", type_str);
				ret = -1;
				goto out;
			}
		}

		params[i].id = param_id;
		params[i].containid = p4_type->containid;
		strlcpy(params[i].name, param_name, TEMPLATENAMSZ);
		strlcpy(params[i].pname, pname, TEMPLATENAMSZ);
		params[i].startbit = p4_type->startbit;
		params[i].endbit = p4_type->endbit;
		params[i].pipeid = *pipeid;

		i++;
	}
	ret = i;

out:
	fclose(f);
	return ret;
}

int p4tc_get_metadata(struct p4_metat_s metadata[])
{
	char *introspection_path = get_introspection_path();
	struct dirent *de;
	int ret = 0;
	int i = 0;
	DIR *d;

	d = opendir(introspection_path);
	if (!d) {
		fprintf(stderr, "Unable to opendir\n");
		return -1;
	}

	while ((de = readdir(d)) != NULL) {
		if (*de->d_name == '.')
			continue;

		ret = p4tc_get_pipeline_metadata(metadata, de->d_name, &i);
		if (ret < 0)
			return ret;
	}

	return i;
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
			const char *tname, __u32 tbc_id)
{
	int i = 0;
	char *line = NULL;
	__u32 pipeid = 0;
	char key_name[TABLEKEYNAMSIZ];
	char type_str[TCLASSNAMSIZ];
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

	if (find_table(f, tname, &pipeid, &tbc_id) < 0) {
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
