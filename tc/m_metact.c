/*
 * m_metact.c             P4 metact action
 *
 *              This program is free software; you can distribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022, Mojatatu Networks
 * Copyright (c) 2022, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <alloca.h>
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"
#include "p4_types.h"
#include "p4tc_common.h"
#include "p4tc_introspection.h"
#include <linux/tc_act/tc_metact.h>

#ifndef MAX_PATH_COMPONENTS
#define MAX_PATH_COMPONENTS 5
#endif

struct p4_metact_ins_v {
	struct tca_u_meta_operate ins;
        struct tca_u_meta_operand opA;
        struct tca_u_meta_operand opB;
        struct tca_u_meta_operand opC;
	void *pathA;
	void *pathB;
	void *pathC;
	bool Apresent;
	bool Bpresent;
	bool Cpresent;
};

static struct p4_metact_ins_v INS[TCA_METACT_LIST_MAX];

static void explain(void)
{
	fprintf(stderr,
		"Usage: metact ... [index INDEX] \n"
		"where:\n"
		"\tINDEX  is the specific policy instance id\n");
}

static void usage(void)
{
	explain();
	exit(-1);
}

static int parse_set_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins);
static int parse_act_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins);
static int parse_brn_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins);
static int parse_print_operands(struct action_util *a, int *argc_p,
				char ***argv_p, struct p4_metact_ins_v *ins);
static int parse_tblapp_operands(struct action_util *a, int *argc_p,
				   char ***argv_p, struct p4_metact_ins_v *ins);
static int parse_sndportegr_operands(struct action_util *a, int *argc_p,
				     char ***argv_p, struct p4_metact_ins_v *ins);

struct op_type_s {
        int id;
        const char *name;
	int (*parse_operands)(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins);
	void (*print_op)(struct tca_u_meta_operand *oper,
			 void *oppath, FILE *f);
};

static struct op_type_s op_types [] = {
	{METACT_OP_SET, "set", parse_set_operands, NULL},
	{METACT_OP_ACT, "act", parse_act_operands, NULL},
	{METACT_OP_BEQ, "beq", parse_brn_operands, NULL},
	{METACT_OP_BNE, "bne", parse_brn_operands, NULL},
	{METACT_OP_BNE, "bne", parse_brn_operands, NULL},
	{METACT_OP_BGT, "bgt", parse_brn_operands, NULL},
	{METACT_OP_BLT, "blt", parse_brn_operands, NULL},
	{METACT_OP_BGE, "bge", parse_brn_operands, NULL},
	{METACT_OP_BLE, "ble", parse_brn_operands, NULL},
	{METACT_OP_PRINT, "print", parse_print_operands, NULL},
	{METACT_OP_TBLAPP, "tableapply", parse_tblapp_operands, NULL},
	{METACT_OP_SNDPORTEGR, "send_port_egress", parse_sndportegr_operands,
		NULL},
	{METACT_OP_MIRPORTEGR, "mirror_port_egress", parse_sndportegr_operands,
		NULL},
};

static struct op_type_s *get_op_byname(const char *name)
{
        int arr_sz = sizeof(op_types)/sizeof(op_types[0]);
        int i;

        for (i = 0; i < arr_sz; i++) {
		if (strcasecmp(op_types[i].name, name) == 0)
			return &op_types[i];
	}

	return NULL;
}

static struct op_type_s *get_op_byid(int id)
{
        int arr_sz = sizeof(op_types)/sizeof(op_types[0]);
        int i;

        for (i = 0; i < arr_sz; i++) {
		if (id == op_types[i].id)
			return &op_types[i];
	}

	return NULL;
}

struct opnd_type_s {
        int id;
        int type_id;
        const char *name;
	int (*get_opertype)(const char *op_components[],
			    struct tca_u_meta_operand *op, void **path);
	void (*print_opertype)(struct tca_u_meta_operand *oper, void *oppath,
			       FILE *f);
};

int get_metadata_type(const char *op_components[],
		      struct tca_u_meta_operand *op, void **path);
int get_key_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path);
int get_const_type(const char *op_components[],
		   struct tca_u_meta_operand *op, void **path);
int get_act_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path);
int get_table_type(const char *op_components[],
		   struct tca_u_meta_operand *op, void **path);
int get_res_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path);
int get_hdrfield_type(const char *op_components[],
		      struct tca_u_meta_operand *op, void **path);
int get_act_param_type(const char *op_components[],
		       struct tca_u_meta_operand *op, void **path);
int get_dev_type(const char *op_components[], struct tca_u_meta_operand *op,
		 void **path);

static void print_constant_type(struct tca_u_meta_operand *oper, void *oppath,
				FILE *f);
static void print_metadata_type(struct tca_u_meta_operand *oper,
				void *oppath, FILE *f);
static void print_act_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f);
static void print_key_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f);
static void print_table_type(struct tca_u_meta_operand *oper, void *oppath,
			     FILE *f);
static void print_res_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f);
static void print_hdrfield_type(struct tca_u_meta_operand *oper, void *oppath,
				FILE *f);
static void print_dev_type(struct tca_u_meta_operand *oper, void *oppath,
			       FILE *f);
static void print_act_param_type(struct tca_u_meta_operand *oper, void *oppath,
				 FILE *f);

static struct opnd_type_s opnd_types [] = {
	{METACT_OPER_META, P4T_PATH, "metadata", get_metadata_type,
	 print_metadata_type},
	{METACT_OPER_HDRFIELD, P4T_PATH, "hdrfield", get_hdrfield_type,
		print_hdrfield_type},
	{METACT_OPER_KEY, P4T_PATH, "key", get_key_type, print_key_type },
	{METACT_OPER_CONST, P4T_UNSPEC, "constant", get_const_type,
	 print_constant_type},
	{METACT_OPER_ACTID, P4T_U32, "act", get_act_type,
	 print_act_type},
	{METACT_OPER_TBL, P4T_PATH, "table", get_table_type, print_table_type },
	{METACT_OPER_RES, P4T_PATH, "results", get_res_type, print_res_type },
	{METACT_OPER_PARAM, P4T_PATH, "param", get_act_param_type,
	 print_act_param_type},
	{METACT_OPER_CONST, P4T_PATH, "dev", get_dev_type,
	 print_dev_type},
};

static struct opnd_type_s *get_optype_byname(const char *name)
{
        int arr_sz = sizeof(opnd_types)/sizeof(opnd_types[0]);
        int i;

        for (i = 0; i < arr_sz; i++) {
		if (strcasecmp(opnd_types[i].name, name) == 0)
			return &opnd_types[i];
	}

	return NULL;
}

static struct opnd_type_s *get_optype_byid(int id)
{
        int arr_sz = sizeof(opnd_types)/sizeof(opnd_types[0]);
        int i;

        for (i = 0; i < arr_sz; i++) {
                 if (opnd_types[i].id == id) {
			return &opnd_types[i];
		}
	}

	return NULL;
}

int get_act_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[0], *f2 = op_components[1];
	const char *f3 = op_components[2];
	bool is_gact = false;
	struct action_util *a;
	__u32 actionindex;
	__u32 pipeid = 0, actionid = 0;
	char buf[256];
	int rc;

	if (strcmp("kernel", f1) == 0) {
		strcpy(buf, f2);
		rc = action_a2n(buf, NULL, false);
		if (!rc) {
			is_gact = true;
			strcpy(buf, "gact");
		}

		a = get_action_kind(buf);
		if (!is_gact && strcasecmp(a->id, "gact") == 0) {
			fprintf(stderr, "Invalid action %s:%s\n", f2, f3);
			return -1;
		}
		pipeid = 0;
		actionid = a->aid;
	} else {
		if (p4tc_get_act(f1, f2, &pipeid, &actionid) < 0)
		    return -1;
	}

	if (get_u32(&actionindex, f3, 0)) {
		fprintf(stderr, "Invalid actionindex %s:%s\n", f2, f3);
		return -1;
	}

	op->pipeid = pipeid;
	op->oper_datatype = METACT_OPER_ACTID;
	op->immedv = actionid;
	op->immedv2 = actionindex;
	op->oper_cbitsize = 32;

	return 0;
}

int get_const_type(const char *op_components[],
		   struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	bool isslice = false, israw = false;
	struct p4_type_value val = {NULL};
	int rc = 0, bitsz=0, l=0, r=0;
	struct p4_type_s *t = NULL;
	char *pr = NULL;

	rc = sscanf(f1, "%m[a-z.%]%d[%d-%d]", &pr, &bitsz, &l, &r);
	if (rc == 4 && l>=0 && r>=0)
		isslice = true;
	if (strcasecmp(pr, "bit") == 0)
		israw = true;

	free(pr);

	if (!israw) {
		if (isslice) {
			char *f1p3 = strdupa(f1);
			char *f1p2 = strchr(f1p3, '[');
			if (f1p2) {
				*f1p2= '\0';
				f1p2++;
			} else {
				fprintf(stderr, "unknown type %s\n", f1);
				return -1;
			}

			t = get_p4type_byname(f1p3);
			if (!t) {
				fprintf(stderr, "unknown type %s\n", f1);
				return -1;
			}
			bitsz = 1 + r - l;
		} else {
			t = get_p4type_byname(f1);
			if (!t) {
				fprintf(stderr, "unknown type %s\n", f1);
				return -1;
			}
			l = 0;
			r = t->bitsz-1;
			bitsz = t->bitsz;
		}

		op->oper_startbit = l;
		op->oper_endbit = r;
	} else {
		int containersz;

		if (bitsz < 1) {
			fprintf(stderr, "data type %s bad size %d\n",
				f1, bitsz);
			return -1;
		}

		/* round up to the nearest power of two */
		if (bitsz <= 8) {
			containersz = 8;
		} else if (bitsz <= 16) {
			containersz = 16;
		} else if (bitsz <= 32) {
			containersz = 32;
		} else if (bitsz <= 64) {
			containersz = 64;
		} else {
			fprintf(stderr, "data type %s bad size %d\n",
				f1, bitsz);
			return -1;
		}
		t = get_p4type_bysize(containersz, P4T_TYPE_UNSIGNED);
		if (!t) {
			fprintf(stderr, "data type %s not found\n", f1);
			return -1;
		}
		if (isslice) {
			op->oper_startbit = l;
			op->oper_endbit = r;
			bitsz = 1 + r - l;
		} else {
			op->oper_startbit = 0;
			op->oper_endbit = bitsz-1;
		}
	}

	if (israw)
		op->oper_flags |= DATA_IS_RAW;
	if (isslice)
		op->oper_flags |= DATA_IS_SLICE;
	op->oper_datatype = t->containid;
	op->oper_cbitsize = t->bitsz;
	op->pipeid = 0;

	if (t->bitsz > 32) {
		*path = calloc(1, t->bitsz >> 3);
		if (!*path) {
			fprintf(stderr, "Unable to allocate path\n");
			return -1;
		}
		val.value = *path;
		rc = t->parse_p4t(&val, f2, 0);
	} else {
		val.value = &op->immedv;
		rc = t->parse_p4t(&val, f2, 0);
	}
	if (rc) {
		fprintf(stderr, "Invalid operand Value %s\n", f2);
		return -1;
	}

	return 0;
}

int get_metadata_type(const char *op_components[],
		      struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	struct p4_metat_s *m = NULL;
	struct p4_type_s *t = NULL;
	int rc = 0, l=0, r=0;
	bool isslice = false;
	char *pr = NULL;

	rc = sscanf(f2, "%m[a-z0-9_/.%][%d-%d]", &pr, &l, &r);
	if (rc == 3 && l>=0 && r>=0)
		isslice = true;

	m = get_meta_byname(f1, pr);
	if (!m) {
		fprintf(stderr, "metadata %s not found\n", f2);
		free(pr);
		return -1;
	}

	free(pr);
	t = get_p4type_byid(m->containid);
	if (!t) {
		fprintf(stderr, "metadata %s kind %s not found\n", f1,
			m->name);
		return -1;
	}

	op->pipeid = m->pipeid;
	op->oper_datatype = m->containid;
	op->immedv = m->id;
	op->oper_cbitsize = t->bitsz;

	if (isslice) {
		op->oper_startbit = l;
		op->oper_endbit = r;
		op->oper_flags |= DATA_IS_SLICE;
	} else {
		op->oper_startbit = m->startbit;
		op->oper_endbit = m->endbit;
	}

	return 0;
}

int get_table_type(const char *op_components[],
		   struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	__u32 pipeid = 0, tbcid = 0;
	int rc = 0;

	rc = p4tc_get_tables(f1, f2, &pipeid, &tbcid);
	if (rc < 0) {
		fprintf(stderr, "Unable to find table class %s.%s\n", f1, f2);
		return -1;
	}

	op->pipeid = pipeid;
	op->immedv = tbcid;

	return 0;
}

int get_hdrfield_type(const char *op_components[],
		      struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	const char *f3 = op_components[3], *f4 = op_components[4];
	struct hdrfield fields[32] = {0};
	__u32 pipeid = 0, parserid = 0;
	struct hdrfield *field;
	int num_fields;

	num_fields = p4tc_get_header_fields(fields, f1, f3, &pipeid);
	if (num_fields < 0) {
		fprintf(stderr, "Unable to get header %s\n", f3);
		return -1;
	}

	parserid = atoi(f2);
	field = p4tc_find_hdrfield(fields, f4, num_fields);
	if (!field) {
		fprintf(stderr,
			"Unable to find header field in introspection file\n");
		return -1;
	}

	op->pipeid = pipeid;
	op->immedv = parserid;
	op->immedv2 = field->id;

	op->oper_datatype = field->ty->containid;
	op->oper_startbit = field->startbit;
	op->oper_endbit = field->endbit;
	op->oper_cbitsize = field->ty->bitsz;

	return 0;
}

int get_act_param_type(const char *op_components[],
		       struct tca_u_meta_operand *op, void **path)
{
	const char *pname = op_components[1], *act_name = op_components[2];
	const char *param_name = op_components[3];
	int param_index = -1;
	struct p4_param_s params[32];
	__u32 pipeid, act_id;
	int i, num_acts;

	num_acts = p4tc_get_act_params(params, pname, act_name, &pipeid,
				       &act_id);
	if (num_acts < 0)
		return -1;

	for (i = 0; i < num_acts; i++) {
		if (!strncmp(params[i].name, param_name, TEMPLATENAMSZ)) {
			param_index = i;
			break;
		}
	}

	if (param_index < 0) {
		fprintf(stderr, "Unable to find action param %s\n", param_name);
		return -1;
	}

	op->pipeid = pipeid;
	op->immedv = act_id;
	op->immedv2 = params[param_index].id;
	op->oper_datatype = params[param_index].containid;
	op->oper_startbit = params[param_index].startbit;
	op->oper_endbit = params[param_index].endbit;
	op->oper_cbitsize = op->oper_endbit - op->oper_startbit + 1;

	return 0;
}
int get_dev_type(const char *op_components[], struct tca_u_meta_operand *op,
		     void **path)
{
	const char *f1 = op_components[1];
	struct p4_type_s *t;
	int idx;

	idx = ll_name_to_index(f1);
	if (!idx) {
		fprintf(stderr, "Invalid dev %s\n", f1);
		return -1;
	}

	op->immedv = idx;

	t = get_p4type_byid(P4T_DEV);
	op->oper_datatype = t->containid;
	op->oper_startbit = t->startbit;
	op->oper_endbit = t->endbit;
	op->oper_cbitsize = t->bitsz;

	return 0;
}

int get_key_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	const char *f3 = op_components[3];
	__u32 pipeid = 0, tbcid = 0;
	__u32 tot_key_len = 0;
	struct p4_type_s *type;
	struct tkey keys[32];
	__u32 key_id;
	int num_keys;
	int i, rc;

	rc = p4tc_get_tables(f1, f2, &pipeid, &tbcid);
	if (rc < 0) {
		fprintf(stderr, "Unable to find table class %s.%s\n", f1, f2);
		return -1;
	}

	num_keys = p4tc_get_table_keys(keys, f1, f2, 0);
	if (num_keys < 0)
		return num_keys;

	if (get_u32(&key_id, f3, 0)) {
		fprintf(stderr, "Invalid key id %u\n", key_id);
		return -1;
	}

	for (i = 0; i < num_keys; i++) {
		if (key_id == keys[i].key_id)
			tot_key_len += keys[i].type->bitsz;
	}

	type = get_p4type_bysize(tot_key_len, P4T_TYPE_UNSIGNED);
	if (!type) {
		fprintf(stderr, "data type not found\n");
		return -1;
	}

	op->pipeid = pipeid;
	op->oper_datatype = type->containid;
	op->oper_startbit = type->startbit;
	op->oper_endbit = type->endbit;
	op->immedv = tbcid;
	op->immedv2 = key_id;
	op->oper_cbitsize = type->bitsz;

	return 0;
}

int get_res_type(const char *op_components[],
		 struct tca_u_meta_operand *op, void **path)
{
	const char *f1 = op_components[1];
	struct p4_type_s *type;

	if (strcmp(f1, "hit") == 0) {
		op->immedv = METACT_RESULTS_HIT;
	} else if (strcmp(f1, "miss") == 0) {
		op->immedv = METACT_RESULTS_MISS;
	} else {
		fprintf(stderr, "Unknown results field %s\n", f1);
		return -1;
	}

	type = get_p4type_byname("bool");
	op->pipeid = 0;
	op->oper_datatype = type->containid;
	op->oper_startbit = type->startbit;
	op->oper_endbit = type->endbit;
	op->oper_cbitsize = type->bitsz;

	return 0;
}

static void print_operation(struct tca_u_meta_operate *ins, FILE *f)
{
	struct op_type_s *op = get_op_byid(ins->op_type);

	if (!op)
		print_uint(PRINT_ANY, "instruction", "\n\t Instruction: %d\n",
			     ins->op_type);
	else
		print_string(PRINT_ANY, "instruction", "\n\t Instruction: %s\n",
			     op->name);

	print_string(PRINT_FP, NULL, "\t  control: ", NULL);
	print_action_control(f, "", ins->op_ctl1, "");
	print_action_control(f, " / ", ins->op_ctl2, "\n");
}

static void print_constant_type(struct tca_u_meta_operand *oper, void *oppath,
				FILE *f)
{
	struct p4_type_s *t = get_p4type_byid(oper->oper_datatype);

	print_string(PRINT_ANY, "type", " type %s\n", "constant");
	if (!t) {
		print_string(PRINT_ANY, "container", "\t    container %s\n", "unknown");
		return;
	} else
		print_string(PRINT_ANY, "container", "\t    container %s", t->name);

	print_uint(PRINT_ANY, "startbit", " startbit %u", oper->oper_startbit);
	print_uint(PRINT_ANY, "endbit", " endbit %u\n", oper->oper_endbit);

	print_string(PRINT_FP, NULL, "\t    ", "");
	if (t->print_p4t) {
		struct p4_type_value val = {NULL};

		if (t->bitsz > 32) {
			val.value = oppath;
			t->print_p4t(t->name, &val, f);
		} else {
			val.value = &oper->immedv;
			t->print_p4t(t->name, &val, f);
		}
	}
}


static void print_key_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f)
{
	struct p4_type_s *type;

	type = get_p4type_byid(oper->oper_datatype);
	if (!type) {
		fprintf(stderr, "Invalid oper->datatype %u\n",
			oper->oper_datatype);
		return;
	}

	print_string(PRINT_ANY, "type", " type %s\n", "key");
	print_string(PRINT_ANY, "container", "\t    container %s", type->name);
}

static void print_table_type(struct tca_u_meta_operand *oper, void *oppath,
			     FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s", "table");
}

static void print_hdrfield_type(struct tca_u_meta_operand *oper, void *oppath,
				FILE *f)
{
	struct p4_type_s *type;

	type = get_p4type_byid(oper->oper_datatype);
	if (!type) {
		fprintf(stderr, "Invalid oper->datatype %u\n",
			oper->oper_datatype);
		return;
	}

	print_string(PRINT_ANY, "type", " type %s\n", "hdrfield");
	print_string(PRINT_ANY, "container", "\t    container %s", type->name);
}

static void print_dev_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f)
{
	int ifindex = oper->immedv;
	const char *ifname = ll_index_to_name(ifindex);

	print_string(PRINT_ANY, "type", " type %s\n", "dev");
	print_string(PRINT_ANY, "dev", "\t    dev %s", ifname);
}

static void print_res_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s\n", "result");
	if (oper->immedv == METACT_RESULTS_HIT)
		print_string(PRINT_ANY, "result", "\t    results.%s", "hit");
	else
		print_string(PRINT_ANY, "result", "\t    results.%s", "miss");
}

static void print_act_type(struct tca_u_meta_operand *oper, void *oppath,
			   FILE *f)
{
	discover_actions();

	print_string(PRINT_ANY, "type", " type %s\n", "action");
	if (oper->pipeid) {
		print_uint(PRINT_ANY, "pipeid", "\t    pipeline id %u\n", oper->pipeid);
		print_uint(PRINT_ANY, "id", "\t    action id %u", oper->immedv);
	} else {
		struct action_util *a;
		char pname[] = "kernel";

		a = get_action_byid(oper->immedv);

		print_string(PRINT_ANY, "pname", "\t    pipeline name %s\n", pname);

		if (a)
			print_string(PRINT_ANY, "id", "\t    action id %s", a->id);
	}
}

static void print_act_param_type(struct tca_u_meta_operand *oper, void *oppath,
				 FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s\n", "param");

	print_uint(PRINT_ANY, "pipeid", "\t    pipeid %u\n", oper->pipeid);
	print_uint(PRINT_ANY, "actid", "\t    actid %u\n", oper->immedv);
	print_uint(PRINT_ANY, "paramid", "\t    param id %u", oper->immedv2);
}

static void print_metadata_type(struct tca_u_meta_operand *oper,
				void *oppath, FILE *f)
{
	struct p4_type_s *t = get_p4type_byid(oper->oper_datatype);
	struct p4_metat_s *m;
	__u32 metaid;

	print_string(PRINT_ANY, "type", " type %s\n", "metadata");

	print_string(PRINT_ANY, "container", "\t    container %s", t->name);
	print_uint(PRINT_ANY, "startbit", " startbit %u", oper->oper_startbit);
	print_uint(PRINT_ANY, "endbit", " endbit %u\n", oper->oper_endbit);

	metaid = oper->immedv;
	m = get_meta_byid(oper->pipeid, metaid);
	if (m) {
		print_string(PRINT_ANY, "pname", "\t    pname %s\n", m->pname);
		print_string(PRINT_ANY, "name", "\t    name %s", m->name);
	}

	print_uint(PRINT_ANY, "id", " id %u", metaid);

	if (oppath)
		print_string(PRINT_ANY, "path", "\t    path %s", oppath);

}

static void print_operand_content(const char *ABC,
				  struct tca_u_meta_operand *oper,
				  void *oppath, FILE *f)
{
	struct opnd_type_s *o;

	if (!oper)
		return;

	print_string(PRINT_FP, NULL, "\t   operand %s", ABC);
	o = get_optype_byid(oper->oper_type);
	if (!o) {
		fprintf(f, "UNKNOWN opnd type: ??%d??\n", oper->oper_type);
		return;
	}

	o->print_opertype(oper, oppath, f);

	print_nl();
}

static int parse_operand_path(char *path, char **components)
{
        const char separator[2] = ".";
        char *token;
        int i, tokens = 0;

        token = strtok(path, separator);
        if (token) {
		tokens++;
                components[0] = token;
	} else
                return -1;

        for (i = 1; i < MAX_PATH_COMPONENTS && token; i++) {
                token = strtok(NULL, separator);
		if (token) {
			components[i] = token;
			tokens++;
		}
        }

        return tokens;
}

static int populate_oper_path(char *fields[],
			      struct tca_u_meta_operand *op,
			      void *path)
{
	struct opnd_type_s *o;

	o = get_optype_byname(fields[0]);
	if (!o) {
		fprintf(stderr, "Invalid operand datatype %s\n",
			fields[0]);
		return -1;
	}

	op->oper_type = o->id;

	if (o->get_opertype((const char **)fields, op, path)) {
		fprintf(stderr, "Invalid operand datatype %s.%s\n",
			fields[1], fields[2]);
		return -1;
	}

	return 0;
}

static int parse_cmd_control(int *argc_p, char ***argv_p,
			     struct tca_u_meta_operate *op)
{
	char **argv = *argv_p;
	int argc = *argc_p;

	if (strcmp(*argv, "control") == 0) {
		if (!NEXT_ARG_OK()) {
			fprintf(stderr, "control needs an arguement\n");
			return -1;
		}
		NEXT_ARG();

		if (parse_action_control_slash(&argc, &argv,
						(int *)&op->op_ctl1,
						(int *)&op->op_ctl2,
						false)) {
			fprintf(stderr, "Failed to parse control\n");
			return -1;
		}
	} else {
		fprintf(stderr, "need keyword \"control\"\n");
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_act_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins)
{
	struct tca_u_meta_operand *A = &ins->opA;
	char *Af[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	struct opnd_type_s *o;
	char *argsA;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Af);
	if (num_Acomponents < 3) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	o = get_optype_byid(METACT_OPER_ACTID);
	if (!o) {
		fprintf(stderr, "Invalid action datatype %s\n",
			Af[0]);
		return -1;
	}

	A->oper_type = o->id;
        if (o->get_opertype((const char **)Af, A, NULL)) {
		fprintf(stderr, "Invalid operand datatype %s.%s\n",
			Af[1], Af[2]);
		return -1;
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct tca_u_meta_operate *op = &ins->ins;
		int rc = parse_cmd_control(&argc, &argv, op);

		if (rc) {
			fprintf(stderr, "Invalid act \"control\"\n");
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_set_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins)
{
	int num_Acomponents = 0, num_Bcomponents = 0, num_Ccomponents = 0;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char *Bcomponents[MAX_PATH_COMPONENTS] = { };
	char *Ccomponents[MAX_PATH_COMPONENTS] = { };
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA, *argsB, *argsC;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 3) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	if (ins->ins.op_type == METACT_OP_ACT)
		goto done_p_operand;

	NEXT_ARG();
	argsB = strdupa(*argv);

	num_Bcomponents = parse_operand_path(argsB, Bcomponents);
	if (num_Bcomponents < 3)
		return -1;

	ins->Bpresent = true;
	if (NEXT_ARG_OK()) {
		NEXT_ARG();

		argsC = strdupa(*argv);

		num_Ccomponents = parse_operand_path(argsC, Ccomponents);
		if (!argsC || num_Ccomponents < 3)
			PREV_ARG();
		else
			ins->Cpresent = true;
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct tca_u_meta_operate *op = &ins->ins;
		rc = parse_cmd_control(&argc, &argv, op);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	if (ins->Apresent) {
		rc = populate_oper_path(Acomponents, &ins->opA, &ins->pathA);
		if (rc < 0 ) {
			fprintf(stderr, "XXX: Invalid operand A %s\n",
				Acomponents[0]);
			return -1;
		}

		if (ins->ins.op_type == METACT_OP_SET &&
		    ins->opA.oper_type == METACT_OPER_CONST) {
			fprintf(stderr, "Invalid SET const operand A %s\n",
				Acomponents[0]);
			return -1;
		}
	}

	if (ins->Bpresent) {
		rc = populate_oper_path(Bcomponents, &ins->opB, &ins->pathB);
		if (rc < 0 ) {
			fprintf(stderr, "...Invalid operand B %s\n",
				Bcomponents[0]);
			return -1;
		}
	}

	if (ins->Cpresent) {
		rc = populate_oper_path(Ccomponents, &ins->opC, &ins->pathC);
		if (rc < 0 ) {
			fprintf(stderr, "...Invalid operand C %s\n",
				Ccomponents[0]);
			return -1;
		}
	}

done_p_operand:
	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_brn_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4_metact_ins_v *ins)
{
	int num_Acomponents = 0, num_Bcomponents = 0;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char *Bcomponents[MAX_PATH_COMPONENTS] = { };
	struct tca_u_meta_operate *op = &ins->ins;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA, *argsB;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	NEXT_ARG();
	argsB = strdupa(*argv);

	num_Bcomponents = parse_operand_path(argsB, Bcomponents);
	if (num_Bcomponents < 3) {
		fprintf(stderr, "Invalid operand B %s\n", *argv);
		return -1;
	}

	ins->Bpresent = true;

	NEXT_ARG_FWD();
	if (strcmp(*argv, "control") == 0) {
		rc = parse_cmd_control(&argc, &argv, op);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return rc;
		}
	} else {
		fprintf(stderr, "Invalid branch construct. Needs \"control\"\n");
		return -1;
	}

	if (ins->Apresent) {
		rc = populate_oper_path(Acomponents, &ins->opA, &ins->pathA);
		if (rc < 0 ) {
			fprintf(stderr, "XXX: Invalid operand A %s\n",
				Acomponents[0]);
			return -1;
		}
	}

	if (ins->Bpresent) {
		rc = populate_oper_path(Bcomponents, &ins->opB, &ins->pathB);
		if (rc < 0 ) {
			fprintf(stderr, "...Invalid operand B %s\n",
				Bcomponents[0]);
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_print_operands(struct action_util *a, int *argc_p,
				char ***argv_p, struct p4_metact_ins_v *ins)
{
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char prefix[METACT_MAX_OPER_PATH_LEN];
	int num_Acomponents = 0;
	bool set_prefix = false;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA;
	int rc;

	if (strcmp(*argv, "prefix") == 0) {
		NEXT_ARG();
		set_prefix = true;
		strlcpy(prefix, *argv, METACT_MAX_OPER_PATH_LEN);
		NEXT_ARG();
	}

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct tca_u_meta_operate *op = &ins->ins;

		rc = parse_cmd_control(&argc, &argv, op);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	if (ins->Apresent) {
		struct tca_u_meta_operand *opA = &ins->opA;

		rc = populate_oper_path(Acomponents, opA, &ins->pathA);
		if (rc < 0 ) {
			fprintf(stderr, "XXX: Invalid operand A %s\n",
				Acomponents[0]);
			return -1;
		}

		if (set_prefix) {
			ins->pathA = calloc(METACT_MAX_OPER_PATH_LEN, sizeof(char));
			if (!ins->pathA) {
				fprintf(stderr, "Unable to allocate path\n");
				return -1;
			}
			strncpy(ins->pathA, prefix, METACT_MAX_OPER_PATH_LEN);
		}
	}

	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_tblapp_operands(struct action_util *a, int *argc_p,
				 char ***argv_p, struct p4_metact_ins_v *ins)
{
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 keyid = 0;
	char *argsA;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 3) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	NEXT_ARG_FWD();

	if (*argv && strcmp(*argv, "keyid") == 0) {
		NEXT_ARG();
		if (get_u32(&keyid, *argv, 10) < 0) {
			fprintf(stderr, "Invalid table class id\n");
			return -1;
		}
	}

	if (ins->Apresent) {
		rc = populate_oper_path(Acomponents, &ins->opA, &ins->pathA);
		if (rc < 0 ) {
			fprintf(stderr, "XXX: Invalid operand A %s\n",
				Acomponents[0]);
			return -1;
		}

		if (ins->opA.oper_type != METACT_OPER_TBL) {
			fprintf(stderr, "Table apply operand must be a table\n");
			return -1;
		}
		ins->opA.oper_startbit = 0;
		ins->opA.oper_endbit = 0;
		ins->opA.oper_datatype = METACT_OPER_TBL;

		ins->opA.immedv2 = keyid;
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_sndportegr_operands(struct action_util *a, int *argc_p,
				     char ***argv_p, struct p4_metact_ins_v *ins)
{
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	ins->Apresent = true;

	NEXT_ARG_FWD();

	if (ins->Apresent) {
		rc = populate_oper_path(Acomponents, &ins->opA, &ins->pathA);
		if (rc < 0 ) {
			fprintf(stderr, "XXX: Invalid operand A %s\n",
				Acomponents[0]);
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

int parse_commands(struct action_util *a, int *argc_p, char ***argv_p)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ins_cnt = -1;
	int ret = 0;
	struct p4_metact_ins_v *ins = NULL;
	struct op_type_s *op = NULL;

	while (argc > 0) {

		if (strcmp(*argv, "cmd") == 0) {
                        NEXT_ARG();
			ins_cnt++;
			if (ins_cnt > TCA_METACT_LIST_MAX) {
				fprintf(stderr, "metact too many ins: %d>%d\n",
					ins_cnt, TCA_METACT_LIST_MAX);
				return -1;
			}
			ins = &INS[ins_cnt];
			ins->ins.op_ctl1 = ins->ins.op_ctl2 = TC_ACT_PIPE;
			continue;

		} else if (strcmp(*argv, "set") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_SET;
			op = get_op_byname("set");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <set>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "act") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_ACT;
			op = get_op_byname("act");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}

			discover_actions();
			print_known_actions();
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <act>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "beq") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BEQ;
			op = get_op_byname("beq");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <beq>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "bne") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BNE;
			op = get_op_byname("bne");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <bne>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bgt") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BGT;
			op = get_op_byname("bgt");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <bgt>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "blt") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BLT;
			op = get_op_byname("blt");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <blt>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bge") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BGE;
			op = get_op_byname("bge");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <bge>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "ble") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_BLE;
			op = get_op_byname("ble");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <ble>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "print") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_PRINT;
			op = get_op_byname("print");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <print>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "tableapply") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_TBLAPP;
			op = get_op_byname("tableapply");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <tableapply>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "send_port_egress") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_SNDPORTEGR;
			op = get_op_byname("send_port_egress");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <send_port_egress>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "mirror_port_egress") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = METACT_OP_MIRPORTEGR;
			op = get_op_byname("mirror_port_egress");
			if (!op) {
				fprintf(stderr, "metact unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "metact bad <mirror_port_egress>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "index") == 0) {
			break;
		} else if (strcmp(*argv, "defact") == 0) {
			break;
		} else {
			fprintf(stderr, "metact: bad command %d:<%s>\n",
				argc, *argv);
			return -1;
		}

		NEXT_ARG();
	}

	*argc_p = argc;
	*argv_p = argv;

	if (ins_cnt == -1)
		return 0;

	ins_cnt +=1;
	return ins_cnt;
}

int add_commands(struct nlmsghdr *n, int ins_cnt, int tca_id)
{
	struct p4_metact_ins_v *ins = NULL;
	struct rtattr *tailoperA, *tailoperB, *tailoperC;
	struct rtattr *tailinsl, *tailins;
	int b2B;
	int i;

	if (!ins_cnt) {
		return 0;
	}

	tailinsl = addattr_nest(n, MAX_MSG, tca_id | NLA_F_NESTED);
	for (i = 0; i < ins_cnt; i++) {
		tailins = addattr_nest(n, MAX_MSG, i+1 | NLA_F_NESTED);

		ins = &INS[i];

		addattr_l(n, MAX_MSG, TCAA_METACT_OPERATION, &ins->ins,
			  sizeof(struct tca_u_meta_operate));

		if (ins->Apresent) {
			tailoperA = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_A | NLA_F_NESTED);

			if (ins->pathA) {
				addattrstrz(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					    ins->pathA);
				free(ins->pathA);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opA,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperA);
		}

		if (ins->Bpresent) {
			tailoperB = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_B | NLA_F_NESTED);
			if (ins->pathB) {
				b2B = (((ins->opB.oper_cbitsize-1) | 7)+1) >>3;
				addattr_l(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					  ins->pathB, b2B);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opB,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperB);
		}

		if (ins->Cpresent) {
			tailoperC = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_C | NLA_F_NESTED);
			if (ins->pathC) {
				b2B = (((ins->opC.oper_cbitsize-1) | 7)+1) >>3;
				addattr_l(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					  ins->pathC, b2B);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opC,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperC);
		}

		addattr_nest_end(n, tailins);
	}
	addattr_nest_end(n, tailinsl);

	return 0;
}

static int parse_metact(struct action_util *a, int *argc_p, char ***argv_p,
			int tca_id, struct nlmsghdr *n)
{
	struct p4_metat_s metadata[32];
	struct tc_metact p = {};
	char **argv = *argv_p;
	int ret = 0, i = 0;
	int argc = *argc_p;
	struct rtattr *tailoperA, *tailoperB, *tailoperC;
	struct rtattr *tailma, *tailinsl, *tailins;
	struct p4_metact_ins_v *ins;
	int ins_cnt;
	int b2B;

	if (argc < 0) {
		fprintf(stderr, "metact bad argument count %d\n", argc);
		return -1;
	}

	if (matches(*argv, "metact") == 0) {
		NEXT_ARG();
	} else if (matches(*argv, "help") == 0) {
		usage();
	} else {
		fprintf(stderr, "metact bad argument %s\n", *argv);
		return -1;
	}

	register_kernel_metadata();
	if (fill_user_metadata(metadata) < 0)
		return -1;

	ins_cnt = parse_commands(a, &argc, &argv);
	if (ins_cnt < 0) {
		ret = ins_cnt;
		goto unregister_meta;
	}

	ret = 0;

	p.action = TC_ACT_PIPE;
	if (*argv && matches(*argv, "defact") == 0) {
		NEXT_ARG();
		ret = parse_action_control(&argc, &argv, &p.action, false);

		if (ret < 0) {
			fprintf(stderr, "metact bad default action %s\n",
				*argv);
			ret = -1;
			goto unregister_meta;
		}
	}

	if (argc) {
		if (strcmp(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&p.index, *argv, 10)) {
				fprintf(stderr, "metact: Illegal \"index\"\n");
				ret = -1;
				goto unregister_meta;
			}
			argc--;
			argv++;
		}
	}

	tailma = addattr_nest(n, MAX_MSG, tca_id | NLA_F_NESTED);

	addattr_l(n, MAX_MSG, TCA_METACT_PARMS, &p, sizeof(p));

	if (ins_cnt)
		tailinsl = addattr_nest(n, MAX_MSG, TCA_METACT_LIST | NLA_F_NESTED);
	else
		goto skip_ins_encoding;

	for (i = 0; i < ins_cnt; i++) {
		tailins = addattr_nest(n, MAX_MSG, i+1 | NLA_F_NESTED);

		ins = &INS[i];

		addattr_l(n, MAX_MSG, TCAA_METACT_OPERATION, &ins->ins,
			  sizeof(struct tca_u_meta_operate));

		if (ins->Apresent) {
			tailoperA = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_A | NLA_F_NESTED);

			if (ins->pathA) {
				addattrstrz(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					    ins->pathA);
				free(ins->pathA);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opA,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperA);
		}

		if (ins->Bpresent) {
			tailoperB = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_B | NLA_F_NESTED);
			if (ins->pathB) {
				b2B = (((ins->opB.oper_cbitsize-1) | 7)+1) >>3;
				addattr_l(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					  ins->pathB, b2B);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opB,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperB);
		}

		if (ins->Cpresent) {
			tailoperC = addattr_nest(n, MAX_MSG, TCAA_METACT_OPER_C | NLA_F_NESTED);
			if (ins->pathC) {
				b2B = (((ins->opC.oper_cbitsize-1) | 7)+1) >>3;
				addattr_l(n, MAX_MSG, TCAA_METACT_OPND_PATH,
					  ins->pathC, b2B);
			}
			addattr_l(n, MAX_MSG, TCAA_METACT_OPND_INFO, &ins->opC,
				  sizeof(struct tca_u_meta_operand));
			addattr_nest_end(n, tailoperC);
		}

		addattr_nest_end(n, tailins);
	}

	addattr_nest_end(n, tailinsl);

skip_ins_encoding:
	addattr_nest_end(n, tailma);

	if (ret == 0) {
		*argc_p = argc;
		*argv_p = argv;
		return 0;
	}

unregister_meta:
	unregister_kernel_metadata();

	return ret;
}

static int metact_print_operand(const char *ABC, struct rtattr *op_attr,
				FILE *f)
{
        void *path = NULL;
	struct rtattr *tb[TCAA_METACT_OPND_MAX + 1];
	struct tca_u_meta_operand *opnd;

	if (!op_attr)
		return 0;

	parse_rtattr_nested(tb, TCAA_METACT_OPND_MAX, op_attr);

	if (tb[TCAA_METACT_OPND_PATH])
		path = RTA_DATA(tb[TCAA_METACT_OPND_PATH]);

	if (!tb[TCAA_METACT_OPND_INFO]) {
		fprintf(stderr, "Missing metact operand information\n");
		return -1;
	}

        opnd = RTA_DATA(tb[TCAA_METACT_OPND_INFO]);
	print_operand_content(ABC, opnd, path, stdout);

	return 0;
}

static int metact_print_ops(int i, struct rtattr *op_attr, FILE *f)
{
	struct rtattr *tb[TCAA_METACT_OPER_MAX + 1];
	struct tca_u_meta_operate *op_entry;
	int err;

	parse_rtattr_nested(tb, TCAA_METACT_OPER_MAX, op_attr);

	if (!tb[TCAA_METACT_OPERATION]) {
		fprintf(stderr, "Missing metact operation\n");
		return -1;
	}

	op_entry = RTA_DATA(tb[TCAA_METACT_OPERATION]);

	print_operation(op_entry, f);

	open_json_object("operands");

	open_json_object("OPA");
	print_string(PRINT_FP, NULL, "\t  operands:\n", NULL);
	err = metact_print_operand("A", tb[TCAA_METACT_OPER_A], f);
        if (err < 0)
                return err;
	close_json_object();

	open_json_object("OPB");
	err = metact_print_operand("B", tb[TCAA_METACT_OPER_B], f);
        if (err < 0)
                return err;
	close_json_object();

	open_json_object("OPC");
	err = metact_print_operand("C", tb[TCAA_METACT_OPER_C], f);
        if (err < 0)
                return err;
	close_json_object();

	close_json_object();

	return 0;
}

int print_metact_cmds(FILE *f, struct rtattr *arg)
{
	struct rtattr *oplist_attr[TCA_METACT_LIST_MAX + 1];
	struct p4_metat_s metadata[32];
	int err, i;

	register_kernel_metadata();
	if (fill_user_metadata(metadata) < 0) {
		unregister_kernel_metadata();
		return -1;
	}

	parse_rtattr_nested(oplist_attr, TCA_METACT_LIST_MAX, arg);

	open_json_array(PRINT_JSON, "operations");
	for (i = 1; i <= TCA_METACT_LIST_MAX && oplist_attr[i]; i++) {
		open_json_object(NULL);
		err = metact_print_ops(i, oplist_attr[i], f);
		if (err) {
			unregister_kernel_metadata();
			return err;
		}
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	print_nl();

	unregister_kernel_metadata();

	return 0;
}

int print_metact(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_METACT_MAX + 1];
	struct tc_metact *p;

	if (arg == NULL)
		return 0;

	parse_rtattr_nested(tb, TCA_METACT_MAX, arg);

	if (tb[TCA_METACT_ACT_NAME])
		print_string(PRINT_ANY, "kind", "%s ",
			     RTA_DATA(tb[TCA_METACT_ACT_NAME]));
	else
		print_string(PRINT_ANY, "kind", "%s ", "metact");

	if (!tb[TCA_METACT_PARMS] || !tb[TCA_METACT_LIST]) {
		fprintf(stderr, "Missing metact parameters\n");
		return -1;
	}

	p = RTA_DATA(tb[TCA_METACT_PARMS]);
	print_uint(PRINT_ANY, "index", " index %u", p->index);
	print_int(PRINT_ANY, "ref", " ref %d", p->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", p->bindcnt);

	if (show_stats) {
		if (tb[TCA_METACT_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_METACT_TM]);

			print_tm(f, tm);
		}
	}

	if (tb[TCA_METACT_ACT_PARMS]) {
		print_string(PRINT_FP, NULL, "\n\t params:\n", "");
		open_json_array(PRINT_JSON, "params");
		print_dyna_parms(tb[TCA_METACT_ACT_PARMS], f);
		close_json_array(PRINT_JSON, NULL);
	}

	return print_metact_cmds(f, tb[TCA_METACT_LIST]);
}

struct action_util metact_action_util = {
	.id = "metact",
	.aid = TCA_ID_METACT,
	.parse_aopt = parse_metact,
	.print_aopt = print_metact,
};
