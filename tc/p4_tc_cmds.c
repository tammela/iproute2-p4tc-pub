/*
 * p4_tc_cmds.c             P4 TC commands
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
#include "p4tc_cmds.h"
#include "p4_tc_json.h"
#include <linux/p4tc.h>
#include <ctype.h>

#ifndef MAX_PATH_COMPONENTS
#define MAX_PATH_COMPONENTS 5
#endif

struct p4tc_u_internal_operand {
	struct p4tc_u_operand op;
	char *path;
	char *extra_path;
	void *immedv_large;
	char *print_prefix;
};

struct p4tc_cmds_v {
	struct p4tc_u_internal_operand opnds[P4TC_CMD_OPERS_MAX];
	struct p4tc_u_operate ins;
	char *label1;
	char *label2;
};

static struct p4tc_cmds_v INS[P4TC_CMDS_LIST_MAX];

static int parse_set_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_act_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_brn_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_print_operands(struct action_util *a, int *argc_p,
				char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_tblapp_operands(struct action_util *a, int *argc_p,
				   char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_sndportegr_operands(struct action_util *a, int *argc_p,
				     char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_binarith_operands(struct action_util *a, int *argc_p,
				   char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_concat_operands(struct action_util *a, int *argc_p,
				 char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_jump_operands(struct action_util *a, int *argc_p,
			       char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_label_operands(struct action_util *a, int *argc_p,
			       char ***argv_p, struct p4tc_cmds_v *ins);
static int parse_ret_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins);

struct op_type_s {
        int id;
        const char *name;
	int (*parse_operands)(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins);
	void (*print_op)(struct p4tc_u_operand *oper,
			 void *oppath, FILE *f);
};

static struct op_type_s op_types [] = {
	{P4TC_CMD_OP_SET, "set", parse_set_operands, NULL},
	{P4TC_CMD_OP_ACT, "act", parse_act_operands, NULL},
	{P4TC_CMD_OP_BEQ, "beq", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BNE, "bne", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BNE, "bne", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BGT, "bgt", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BLT, "blt", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BGE, "bge", parse_brn_operands, NULL},
	{P4TC_CMD_OP_BLE, "ble", parse_brn_operands, NULL},
	{P4TC_CMD_OP_PRINT, "print", parse_print_operands, NULL},
	{P4TC_CMD_OP_TBLAPP, "tableapply", parse_tblapp_operands, NULL},
	{P4TC_CMD_OP_SNDPORTEGR, "send_port_egress", parse_sndportegr_operands,
		NULL},
	{P4TC_CMD_OP_MIRPORTEGR, "mirror_port_egress", parse_sndportegr_operands,
		NULL},
	{P4TC_CMD_OP_PLUS, "plus", parse_binarith_operands, NULL },
	{P4TC_CMD_OP_SUB, "sub", parse_binarith_operands, NULL },
	{P4TC_CMD_OP_CONCAT, "concat", parse_concat_operands, NULL },
	{P4TC_CMD_OP_BAND, "band", parse_binarith_operands, NULL },
	{P4TC_CMD_OP_BOR, "bor", parse_binarith_operands, NULL },
	{P4TC_CMD_OP_BXOR, "bxor", parse_binarith_operands, NULL },
	{P4TC_CMD_OP_JUMP, "jump", parse_jump_operands, NULL },
	{P4TC_CMD_OP_LABEL, "label", parse_label_operands, NULL },
	{P4TC_CMD_OP_RET, "return", parse_ret_operands, NULL },
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
	int (*get_opertype)(struct action_util *a, const char *op_components[],
			    struct p4tc_u_internal_operand *intern_op);
	void (*print_opertype)(struct p4tc_u_operand *oper, char **p4tcpath,
			       void *oppath, void *immedv_large, void *prefix,
			       FILE *f);
};

int get_metadata_type(struct action_util *a, const char *op_components[],
		      struct p4tc_u_internal_operand *intern_op);
int get_key_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op);
int get_const_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op);
int get_act_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op);
int get_table_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op);
int get_res_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op);
int get_hdrfield_type(struct action_util *a, const char *op_components[],
		      struct p4tc_u_internal_operand *intern_op);
int get_act_param_type(struct action_util *a, const char *op_components[],
		       struct p4tc_u_internal_operand *intern_op);
int get_dev_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op);
int get_register_type(struct action_util *a, const char *op_components[],
		      struct p4tc_u_internal_operand *intern_op);
int get_label_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op);
static void print_constant_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_metadata_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_act_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_key_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_table_type(struct p4tc_u_operand *oper, char **p4tcpath,
			     void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_res_type(struct p4tc_u_operand *oper, char **p4tcpath,
			    void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_hdrfield_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_dev_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_act_param_type(struct p4tc_u_operand *oper, char **p4tcpath,
				 void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_register_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_label_type(struct p4tc_u_operand *oper, char **p4tcpath,
			     void *oppath, void *immedv_large, void *prefix, FILE *f);
static void print_ret_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f);

static struct opnd_type_s opnd_types [] = {
	{P4TC_OPER_META, P4T_PATH, "metadata", get_metadata_type,
	 print_metadata_type},
	{P4TC_OPER_HDRFIELD, P4T_PATH, "hdrfield", get_hdrfield_type,
	 print_hdrfield_type},
	{P4TC_OPER_KEY, P4T_PATH, "key", get_key_type, print_key_type },
	{P4TC_OPER_CONST, P4T_UNSPEC, "constant", get_const_type,
	 print_constant_type},
	{P4TC_OPER_ACTID, P4T_U32, "act", get_act_type,
	 print_act_type},
	{P4TC_OPER_TBL, P4T_PATH, "table", get_table_type, print_table_type },
	{P4TC_OPER_RES, P4T_PATH, "results", get_res_type, print_res_type },
	{P4TC_OPER_PARAM, P4T_PATH, "param", get_act_param_type,
	 print_act_param_type},
	{P4TC_OPER_DEV, P4T_PATH, "dev", get_dev_type, print_dev_type},
	{P4TC_OPER_REG, P4T_PATH, "register", get_register_type,
	 print_register_type},
	{P4TC_OPER_LABEL, P4T_PATH, "label", get_label_type,
	 print_label_type},
	{P4TC_OPER_RET, P4T_PATH, "return", NULL, print_ret_type},
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

int get_act_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op)
{
	const char *pname = op_components[0];
	struct p4tc_u_operand *op = &intern_op->op;
	const char *key_id = op_components[2];
	char *act_name = (char *)op_components[1];
	struct action_util *au;
	__u32 actionindex;
	int result;

	if (strcmp("kernel", pname) == 0)
		op->oper_flags |= DATA_USES_ROOT_PIPE;

	if (!action_a2n(act_name, &result, true)) {
		act_name = "gact";
	}

	if (op->oper_flags & DATA_USES_ROOT_PIPE) {
		au = get_action_kind(act_name);
		if (au)
			op->immedv = au->aid;
	}

	if (key_id) {
		if (get_u32(&actionindex, key_id, 0)) {
			fprintf(stderr, "Invalid action index %s:%s\n",
				act_name, key_id);
			return -1;
		}

		op->immedv2 = actionindex;
	}

	intern_op->path = calloc(1, strnlen(act_name, ACTNAMSIZ) + 1);
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, act_name, ACTNAMSIZ);

	return 0;
}

int get_const_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op)
{
	const char *f1 = op_components[1], *f2 = op_components[2];
	struct p4tc_u_operand *op = &intern_op->op;
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

	op->oper_flags |= DATA_HAS_TYPE_INFO;

	val.bitsz = bitsz;
	if (t->bitsz > 32) {
		intern_op->immedv_large = calloc(1, t->bitsz >> 3);
		if (!intern_op->immedv_large) {
			fprintf(stderr, "Unable to allocate path\n");
			return -1;
		}
		val.value = intern_op->immedv_large;
		rc = t->parse_p4t(&val, f2, 0);
	} else {
		val.value = &op->immedv;
		rc = t->parse_p4t(&val, f2, 0);
		op->oper_flags |= DATA_IS_IMMEDIATE;
	}
	if (rc) {
		fprintf(stderr, "Invalid operand Value %s\n", f2);
		return -1;
	}

	return 0;
}

int get_metadata_type(struct action_util *a, const char *op_components[],
		      struct p4tc_u_internal_operand *intern_op)
{
	const char *pname = op_components[1], *f2 = op_components[2];
	struct p4tc_u_operand *op = &intern_op->op;
	int rc = 0, l=0, r=0;
	bool isslice = false;
	char *pr = NULL;
	size_t meta_str_len;

	if (!f2) {
		fprintf(stderr, "Must specify metadata name\n");
		return -1;
	}

	rc = sscanf(f2, "%m[a-z0-9_/.%][%d-%d]", &pr, &l, &r);
	if (rc == 3 && l>=0 && r>=0)
		isslice = true;

	if (!pname) {
		fprintf(stderr, "Must specify pipeline name\n");
		return -1;
	}

	if (strcmp(pname, "kernel") == 0)
		op->oper_flags |= DATA_USES_ROOT_PIPE;

	if (isslice) {
		op->oper_startbit = l;
		op->oper_endbit = r;
		op->oper_flags |= DATA_IS_SLICE;
	}

	meta_str_len = strnlen(pr, METANAMSIZ);
	intern_op->path = calloc(1, meta_str_len + 1);
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, pr, METANAMSIZ);

	free(pr);

	return 0;
}

int get_table_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op)
{
	const char *tblname = op_components[2];

	intern_op->path = calloc(1, strnlen(tblname, TABLENAMSIZ) + 1);
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, tblname, TABLENAMSIZ);

	return 0;
}

static int get_jump_type(struct action_util *a, int argc, char **argv,
			 char *op_components[],
			 struct p4tc_u_internal_operand *intern_op)
{
	const char *f0 = op_components[0];

	intern_op->op.oper_type = P4TC_OPER_LABEL;

	if (isdigit(*f0)) {
		int jmp_cnt;

		jmp_cnt = atoi(f0);
		if (jmp_cnt <= 0) {
			fprintf(stderr, "Backward jumps are not allowed\n");
			return -1;
		}

		return parse_action_control(&argc, &argv,
					    (int *)&intern_op->op.immedv, false);
	}

	intern_op->path = calloc(1, strnlen(f0, LABELNAMSIZ) + 1);
	if (!intern_op->path) {
		fprintf(stderr, "Unable to allocate jump path");
		return -1;
	}

	strlcpy(intern_op->path, f0, LABELNAMSIZ);

	return 0;
}

static int get_ret_type(int *argc, char ***argv, struct p4tc_u_operand *A)
{
	if (parse_action_control(argc, argv, (int *)&A->immedv, false)) {
		fprintf(stderr, "Unable to parse gact return value %s\n",
			**argv);
		return -1;
	}

	return 0;
}

int get_label_type(struct action_util *a, const char *op_components[],
		   struct p4tc_u_internal_operand *intern_op)
{
	const char *f0 = op_components[0];

	intern_op->path = calloc(1, strnlen(f0, LABELNAMSIZ) + 1);
	if (!intern_op->path) {
		fprintf(stderr, "Unable to allocate label path");
		return -1;
	}

	intern_op->op.oper_type = P4TC_OPER_LABEL;

	strlcpy(intern_op->path, f0, LABELNAMSIZ);

	return 0;
}

int get_hdrfield_type(struct action_util *a, const char *op_components[],
		      struct p4tc_u_internal_operand *intern_op)
{
	const char *parsername = op_components[2], *hdrname = op_components[3];
	const char *fieldname = op_components[4];
	size_t full_hdr_name_len, parser_name_len;

	parser_name_len = strnlen(parsername, PARSERNAMSIZ);
	intern_op->path = calloc(1, parser_name_len + 1);
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, parsername, parser_name_len + 1);

	full_hdr_name_len = strnlen(hdrname, HDRFIELDNAMSIZ) + strnlen(fieldname, HDRFIELDNAMSIZ);
	intern_op->extra_path = calloc(1, full_hdr_name_len + 1);
	if (!intern_op->extra_path)
		return -1;

	snprintf(intern_op->extra_path, HDRFIELDNAMSIZ, "%s/%s", hdrname,
		 fieldname);

	return 0;
}

int get_act_param_type(struct action_util *a, const char *op_components[],
		       struct p4tc_u_internal_operand *intern_op)
{
	const char *param_name = op_components[1];

	intern_op->path = calloc(1, strnlen(param_name, TEMPLATENAMSZ));
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, param_name, TEMPLATENAMSZ);

	return 0;
}

int get_dev_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op)
{
	struct p4tc_u_operand *op = &intern_op->op;
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

int get_key_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op)
{
	const char *tblname = op_components[2];

	intern_op->path = calloc(1, strnlen(tblname, TABLENAMSIZ) + 1);
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, tblname, TABLENAMSIZ);

	return 0;
}

int get_register_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op)
{
	const char *f2 = op_components[1];
	const char *f3 = op_components[2];
	struct p4tc_u_operand *op = &intern_op->op;
	char *pr = NULL;
	int idx = 0;
	int rc;

	rc = sscanf(f3, "%m[a-z0-9_/.%][%d]", &pr, &idx);
	if (rc != 2 && idx >= 0) {
		fprintf(stderr, "Invalid register name %s\n", f2);
		return -1;
	}

	op->immedv2 = idx;
	intern_op->path = calloc(1, strnlen(pr, REGISTERNAMSIZ));
	if (!intern_op->path)
		return -1;

	strlcpy(intern_op->path, pr, REGISTERNAMSIZ);

	return 0;
}

int get_res_type(struct action_util *a, const char *op_components[],
		 struct p4tc_u_internal_operand *intern_op)
{
	struct p4tc_u_operand *op = &intern_op->op;
	const char *f1 = op_components[1];
	struct p4_type_s *type;

	if (strcmp(f1, "hit") == 0) {
		op->immedv = P4TC_CMDS_RESULTS_HIT;
	} else if (strcmp(f1, "miss") == 0) {
		op->immedv = P4TC_CMDS_RESULTS_MISS;
	} else {
		fprintf(stderr, "Unknown results field %s\n", f1);
		return -1;
	}

	type = get_p4type_byname("bool");
	op->oper_datatype = type->containid;
	op->oper_startbit = type->startbit;
	op->oper_endbit = type->endbit;
	op->oper_cbitsize = type->bitsz;

	return 0;
}

static void print_operation(struct p4tc_u_operate *ins, FILE *f)
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

static void print_constant_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix,
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
			val.value = immedv_large;
			t->print_p4t("value: ", "value", &val, f);
		} else {
			val.value = &oper->immedv;
			t->print_p4t("value: ", "value", &val, f);
		}
	}
}


static void print_key_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f)
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

static void print_table_type(struct p4tc_u_operand *oper, char **p4tcpath,
			     void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s", "table");
}

static void print_hdrfield_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f)
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

static void print_dev_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	int ifindex = oper->immedv;
	const char *ifname = ll_index_to_name(ifindex);

	print_string(PRINT_ANY, "type", " type %s\n", "dev");
	print_string(PRINT_ANY, "dev", "\t    dev %s", ifname);
}

static void print_res_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s\n", "result");
	if (oper->immedv == P4TC_CMDS_RESULTS_HIT)
		print_string(PRINT_ANY, "result", "\t    results.%s", "hit");
	else
		print_string(PRINT_ANY, "result", "\t    results.%s", "miss");
}

static void print_act_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	discover_actions();

	print_string(PRINT_ANY, "type", " type %s\n", "action");
	if (oper->pipeid) {
		print_uint(PRINT_ANY, "pipeid", "\t    pipeline id %u\n",
			   oper->pipeid);
		print_uint(PRINT_ANY, "id", "\t    action id %u", oper->immedv);
	} else {
		struct action_util *a;

		a = get_action_byid(oper->immedv);

		print_string(PRINT_ANY, "pname", "\t    pipeline name %s\n",
			     "kernel");
		if (a)
			print_string(PRINT_ANY, "id", "\t    action id %s",
				     a->id);
	}
}

static void print_act_param_type(struct p4tc_u_operand *oper,
				 char **p4tcpath, void *oppath, void *immedv_large,
				 void *prefix, FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s\n", "param");

	print_uint(PRINT_ANY, "pipeid", "\t    pipeid %u\n", oper->pipeid);
	print_uint(PRINT_ANY, "actid", "\t    actid %u\n", oper->immedv);
	print_uint(PRINT_ANY, "paramid", "\t    param id %u", oper->immedv2);
}

static void print_metadata_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	struct p4_type_s *p4_type = get_p4type_byid(oper->oper_datatype);
	char *pname = p4tcpath[0];
	__u32 metaid;

	print_string(PRINT_ANY, "type", " type %s:", "metadata");

	metaid = oper->immedv;
	if (oper->pipeid)
		print_string(PRINT_ANY, "pname", " %s/", pname);
	else
		print_string(PRINT_ANY, "pname", " %s/", "kernel");
	print_string(PRINT_ANY, "name", "%s", oppath);

	print_uint(PRINT_ANY, "id", "(id %u)\n", metaid);

	print_string(PRINT_ANY, "container", "\t    container %s",
		     p4_type->name);
	print_uint(PRINT_ANY, "startbit", " startbit %u", oper->oper_startbit);
	print_uint(PRINT_ANY, "endbit", " endbit %u\n", oper->oper_endbit);

	if (prefix)
		print_string(PRINT_ANY, "prefix", "\t    prefix %s", prefix);

}

static void print_register_type(struct p4tc_u_operand *oper, char **p4tcpath,
				void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	struct p4_type_s *p4_type = get_p4type_byid(oper->oper_datatype);
	char *pname = p4tcpath[0];

	print_string(PRINT_ANY, "type", " type %s\n", "register");

	print_uint(PRINT_ANY, "pid", "\t    pipeline id %u\n", oper->pipeid);
	print_string(PRINT_ANY, "pname", "\t    pipeline name %s\n",
		     pname);

	print_string(PRINT_ANY, "container", "\t    container %s",
		     p4_type->name);
	print_uint(PRINT_ANY, "startbit", " startbit %u", oper->oper_startbit);
	print_uint(PRINT_ANY, "endbit", " endbit %u\n", oper->oper_endbit);
	print_uint(PRINT_ANY, "idx", "\t    register index %u\n",
		   oper->immedv2);

	print_string(PRINT_ANY, "regname", "\t    register name %s\n",
		     oppath);
	print_uint(PRINT_ANY, "regid", "\t    register id %u\n", oper->immedv);
}

static void print_label_type(struct p4tc_u_operand *oper, char **p4tcpath,
			     void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s\n", "label");
	print_string(PRINT_ANY, "label", " label %s\n", oppath);
}

static void print_ret_type(struct p4tc_u_operand *oper, char **p4tcpath,
			   void *oppath, void *immedv_large, void *prefix, FILE *f)
{
	print_string(PRINT_ANY, "type", " type %s", "return");
	print_action_control(f, "action ", oper->immedv, "\n");
}

static void print_operand_content(const char *ABC, struct action_util *au,
				  struct p4tc_u_operand *oper, void *oppath,
				  void *immedv_large, void *prefix, FILE *f)
{
	struct opnd_type_s *o;
	char *p4tcpath[2];

	if (!oper)
		return;

	print_string(PRINT_FP, NULL, "\t   operand %s", ABC);
	o = get_optype_byid(oper->oper_type);
	if (!o) {
		fprintf(f, "UNKNOWN opnd type: ??%d??\n", oper->oper_type);
		return;
	}

	parse_path(au->id, p4tcpath, "/");

	o->print_opertype(oper, p4tcpath, oppath, immedv_large, prefix, f);

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

static int populate_oper_path(struct action_util *a, char *fields[],
			      struct p4tc_u_internal_operand *intern_op)
{
	struct opnd_type_s *o;

	o = get_optype_byname(fields[0]);
	if (!o) {
		fprintf(stderr, "Invalid operand datatype %s\n",
			fields[0]);
		return -1;
	}

	intern_op->op.oper_type = o->id;

	if (o->get_opertype(a, (const char **)fields, intern_op)) {
		fprintf(stderr, "Invalid operand datatype %s.%s\n",
			fields[1], fields[2]);
		return -1;
	}

	return 0;
}

static int extract_jump_label(int *argc_p, char ***argv_p, int *result,
			      char **label)
{
	char **argv = *argv_p;
	int argc = *argc_p;

	if (action_a2n(*argv, result, false) < 0) {
		fprintf(stderr, "Bad action type %s\n",
			*argv);
		return -1;
	}

	if (*result == TC_ACT_JUMP) {
		if (NEXT_ARG_OK()) {
			NEXT_ARG_FWD();
			if (isalpha(**argv)) {
				*label = calloc(1, strnlen(*argv, LABELNAMSIZ));
				if (!*label) {
					fprintf(stderr, "Unable to alloc label\n");
					return -1;
				}
				strlcpy(*label, *argv, LABELNAMSIZ);
				NEXT_ARG_FWD();
				goto out;
			}

			PREV_ARG();
		}
	}

	if (parse_action_control(&argc, &argv, result, false) < 0)
		return -1;

out:
	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_cmd_control(int *argc_p, char ***argv_p,
			     struct p4tc_u_operate *op, char **label1,
			     char **label2)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ret;

	if (strcmp(*argv, "control") == 0) {
		if (!NEXT_ARG_OK()) {
			fprintf(stderr, "control needs an argument\n");
			return -1;
		}
		NEXT_ARG();

		ret = extract_jump_label(&argc, &argv,
					 (int *)&op->op_ctl1, label1);
		if (ret < 0)
			return ret;

		if (argc) {
			if (NEXT_ARG_OK() && strcmp(*argv, "/") == 0) {
				NEXT_ARG();
				ret = extract_jump_label(&argc, &argv,
							 (int *)&op->op_ctl2,
							 label2);
				if (ret < 0)
					return ret;
			}
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
			      char ***argv_p, struct p4tc_cmds_v *ins)
{
	struct p4tc_u_operand *A = &ins->opnds[P4TC_CMD_OPER_A].op;
	char *Af[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	int i = 1;
	struct opnd_type_s *o;
	char *argsA;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Af);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	o = get_optype_byid(P4TC_OPER_ACTID);
	if (!o) {
		fprintf(stderr, "Invalid action datatype %s\n",
			Af[0]);
		return -1;
	}

	A->oper_type = o->id;
	if (o->get_opertype(a, (const char **)Af, &ins->opnds[P4TC_CMD_OPER_A])) {
		fprintf(stderr, "Invalid operand datatype %s.%s\n",
			Af[1], Af[2]);
		return -1;
	}

	NEXT_ARG_FWD();

	while (argc && strcmp(*argv, "control") && strcmp(*argv, "cmd") &&
	       strcmp(*argv, "param")) {
		char *components[MAX_PATH_COMPONENTS] = {};
		struct p4tc_u_internal_operand *op;
		int num_components;
		char *args;
		int rc;

		if (i == P4TC_CMD_OPERS_MAX) {
			fprintf(stderr,
				"Concat can have at most %u operands\n",
				P4TC_CMD_OPERS_MAX);
			return -1;
		}

		op = &ins->opnds[i];

		args = strdupa(*argv);

		num_components = parse_operand_path(args, components);
		if (!args || num_components < 2) {
			fprintf(stderr, "Invalid operand\n");
			return -1;
		}

		rc = populate_oper_path(a, components, op);
		if (rc < 0) {
			fprintf(stderr, "XXX: Invalid operand %s\n",
				components[0]);
			return -1;
		}

		NEXT_ARG_FWD();

		i++;
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct p4tc_u_operate *op = &ins->ins;
		int rc;

		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid act \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_set_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins)
{
	int num_Acomponents = 0, num_Bcomponents = 0, num_Ccomponents = 0;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char *Bcomponents[MAX_PATH_COMPONENTS] = { };
	char *Ccomponents[MAX_PATH_COMPONENTS] = { };
	struct p4tc_u_internal_operand *A_intern, *B_intern;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA, *argsB, *argsC;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	NEXT_ARG();
	argsB = strdupa(*argv);

	num_Bcomponents = parse_operand_path(argsB, Bcomponents);
	if (num_Bcomponents < 2)
		return -1;

	if (NEXT_ARG_OK()) {
		NEXT_ARG();

		argsC = strdupa(*argv);

		num_Ccomponents = parse_operand_path(argsC, Ccomponents);
		if (!argsC || num_Ccomponents < 3) {
			PREV_ARG();
		} else {
			fprintf(stderr, "Set operand mustn't have opC\n");
			return -1;
		}
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct p4tc_u_operate *op = &ins->ins;
		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	A_intern = &ins->opnds[P4TC_CMD_OPER_A];
	rc = populate_oper_path(a, Acomponents, A_intern);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	if (A_intern->op.oper_type == P4TC_OPER_CONST) {
		fprintf(stderr, "Invalid SET const operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	B_intern = &ins->opnds[P4TC_CMD_OPER_B];
	rc = populate_oper_path(a, Bcomponents, B_intern);
	if (rc < 0) {
		fprintf(stderr, "...Invalid operand B %s\n",
			Bcomponents[0]);
		return -1;
	}
	if (B_intern->op.oper_type == P4TC_OPER_KEY) {
		fprintf(stderr, "Invalid SET const operand B %s\n",
			Bcomponents[0]);
		return -1;
	}

	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_brn_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins)
{
	int num_Acomponents = 0, num_Bcomponents = 0;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char *Bcomponents[MAX_PATH_COMPONENTS] = { };
	struct p4tc_u_operate *op = &ins->ins;
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

	NEXT_ARG();
	argsB = strdupa(*argv);

	num_Bcomponents = parse_operand_path(argsB, Bcomponents);
	if (num_Bcomponents < 3) {
		fprintf(stderr, "Invalid operand B %s\n", *argv);
		return -1;
	}

	NEXT_ARG_FWD();
	if (strcmp(*argv, "control") == 0) {
		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return rc;
		}
	} else {
		fprintf(stderr, "Invalid branch construct. Needs \"control\"\n");
		return -1;
	}

	rc = populate_oper_path(a, Acomponents, &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	rc = populate_oper_path(a, Bcomponents, &ins->opnds[P4TC_CMD_OPER_B]);
	if (rc < 0) {
		fprintf(stderr, "...Invalid operand B %s\n",
			Bcomponents[0]);
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_print_operands(struct action_util *a, int *argc_p,
				char ***argv_p, struct p4tc_cmds_v *ins)
{
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	char prefix[P4TC_CMD_MAX_OPER_PATH_LEN];
	int num_Acomponents = 0;
	bool set_prefix = false;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA;
	int rc;

	if (strcmp(*argv, "prefix") == 0) {
		NEXT_ARG();
		set_prefix = true;
		strlcpy(prefix, *argv, P4TC_CMD_MAX_OPER_PATH_LEN);
		NEXT_ARG();
	}

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct p4tc_u_operate *op = &ins->ins;

		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid set \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	rc = populate_oper_path(a, Acomponents, &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	if (set_prefix) {
		struct p4tc_u_internal_operand *intern_op;
		intern_op = &ins->opnds[P4TC_CMD_OPER_A];

		intern_op->print_prefix = calloc(P4TC_CMD_MAX_OPER_PATH_LEN,
						 sizeof(char));
		if (!intern_op->print_prefix) {
			fprintf(stderr, "Unable to allocate path\n");
			return -1;
		}
		strncpy(intern_op->print_prefix, prefix,
			P4TC_CMD_MAX_OPER_PATH_LEN);
	}

	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_tblapp_operands(struct action_util *a, int *argc_p,
				 char ***argv_p, struct p4tc_cmds_v *ins)
{
	struct p4tc_u_operand *A = &ins->opnds[P4TC_CMD_OPER_A].op;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	__u32 keyid = 0;
	char *argsA;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 2) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	NEXT_ARG_FWD();

	if (*argv && strcmp(*argv, "keyid") == 0) {
		NEXT_ARG();
		if (get_u32(&keyid, *argv, 10) < 0) {
			fprintf(stderr, "Invalid table id\n");
			return -1;
		}
	}

	rc = populate_oper_path(a, Acomponents, &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	if (A->oper_type != P4TC_OPER_TBL) {
		fprintf(stderr, "Table apply operand must be a table\n");
		return -1;
	}
	A->oper_startbit = 0;
	A->oper_endbit = 0;
	A->oper_datatype = P4TC_OPER_TBL;

	A->immedv2 = keyid;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_jump_operands(struct action_util *a, int *argc_p,
			       char ***argv_p, struct p4tc_cmds_v *ins)
{
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	char *argsA;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 1) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	PREV_ARG();
	rc = get_jump_type(a, argc, argv, Acomponents,
			   &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}
	NEXT_ARG_FWD();
	NEXT_ARG_FWD();

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_label_operands(struct action_util *a, int *argc_p,
			       char ***argv_p, struct p4tc_cmds_v *ins)
{
	struct p4tc_u_operand *A = &ins->opnds[P4TC_CMD_OPER_A].op;
	char *Acomponents[MAX_PATH_COMPONENTS] = { };
	int num_Acomponents = 0;
	char **argv = *argv_p;
	int argc = *argc_p;
	struct opnd_type_s *o;
	char *argsA;
	int rc;

	argsA = strdupa(*argv);

	num_Acomponents = parse_operand_path(argsA, Acomponents);
	if (num_Acomponents < 1) {
		fprintf(stderr, "Invalid operand A %s\n", *argv);
		return -1;
	}

	o = get_optype_byid(P4TC_OPER_LABEL);
	if (!o) {
		fprintf(stderr, "Invalid action datatype label\n");
		return -1;
	}
	A->oper_type = o->id;

	rc = o->get_opertype(a, (const char **)Acomponents,
			     &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	NEXT_ARG_FWD();

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_ret_operands(struct action_util *a, int *argc_p,
			      char ***argv_p, struct p4tc_cmds_v *ins)
{
	struct p4tc_u_operand *A = &ins->opnds[P4TC_CMD_OPER_A].op;
	char **argv = *argv_p;
	int argc = *argc_p;

	A->oper_type = P4TC_OPER_RET;
	A->oper_datatype = P4T_U32;
	A->oper_startbit = 0;
	A->oper_endbit = 31;
	if (get_ret_type(&argc, &argv, A) < 0) {
		fprintf(stderr, "Unable to parse gact return value %s\n",
			*argv);
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_sndportegr_operands(struct action_util *a, int *argc_p,
				     char ***argv_p, struct p4tc_cmds_v *ins)
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

	NEXT_ARG_FWD();

	rc = populate_oper_path(a, Acomponents, &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n", Acomponents[0]);
		return -1;
	}

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int parse_binarith_operands(struct action_util *a, int *argc_p,
				   char ***argv_p, struct p4tc_cmds_v *ins)
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

	NEXT_ARG();
	argsB = strdupa(*argv);

	num_Bcomponents = parse_operand_path(argsB, Bcomponents);
	if (num_Bcomponents < 2) {
		fprintf(stderr, "Invalid operand B %s\n", *argv);
		return -1;
	}

	if (NEXT_ARG_OK()) {
		NEXT_ARG();

		argsC = strdupa(*argv);

		num_Ccomponents = parse_operand_path(argsC, Ccomponents);
		if (!argsC || num_Ccomponents < 3) {
			fprintf(stderr,
				"Must specify 3 arguments for arithmetic command");
			return -1;
		}
	}

	NEXT_ARG_FWD();
	if (*argv && strcmp(*argv, "control") == 0) {
		struct p4tc_u_operate *op = &ins->ins;

		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid binarith \"control\"\n");
			return -1;
		}
	}
	PREV_ARG();

	rc = populate_oper_path(a, Acomponents, &ins->opnds[P4TC_CMD_OPER_A]);
	if (rc < 0) {
		fprintf(stderr, "XXX: Invalid operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	if (ins->opnds[P4TC_CMD_OPER_A].op.oper_type == P4TC_OPER_CONST) {
		fprintf(stderr, "Invalid arithmetic const operand A %s\n",
			Acomponents[0]);
		return -1;
	}

	rc = populate_oper_path(a, Bcomponents, &ins->opnds[P4TC_CMD_OPER_B]);
	if (rc < 0) {
		fprintf(stderr, "...Invalid operand B %s\n",
			Bcomponents[0]);
		return -1;
	}

	rc = populate_oper_path(a, Ccomponents, &ins->opnds[P4TC_CMD_OPER_C]);
	if (rc < 0) {
		fprintf(stderr, "...Invalid operand C %s\n",
			Ccomponents[0]);
		return -1;
	}

	NEXT_ARG_FWD();
	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

static int parse_concat_operands(struct action_util *a, int *argc_p,
				 char ***argv_p, struct p4tc_cmds_v *ins)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int i = 0;
	int rc;

	while (argc && strcmp(*argv, "control") && strcmp(*argv, "cmd") &&
	       strcmp(*argv, "param")) {
		char *components[MAX_PATH_COMPONENTS] = {};
		struct p4tc_u_internal_operand *op;
		int num_components;
		char *args;

		if (i == P4TC_CMD_OPERS_MAX) {
			fprintf(stderr,
				"Concat can have at most %u operands\n",
				P4TC_CMD_OPERS_MAX );
			return -1;
		}

		op = &ins->opnds[i];

		args = strdupa(*argv);

		num_components = parse_operand_path(args, components);
		if (!args || num_components < 2) {
			fprintf(stderr, "Invalid operand\n");
			return -1;
		}

		rc = populate_oper_path(a, components, op);
		if (rc < 0) {
			fprintf(stderr, "XXX: Invalid operand %s\n",
				components[0]);
			return -1;
		}

		NEXT_ARG_FWD();

		i++;
	}

	if (*argv && strcmp(*argv, "control") == 0) {
		struct p4tc_u_operate *op = &ins->ins;

		rc = parse_cmd_control(&argc, &argv, op, &ins->label1,
				       &ins->label2);
		if (rc) {
			fprintf(stderr, "Invalid binarith \"control\"\n");
			return -1;
		}
	}

	*argc_p = argc;
	*argv_p = argv;

	return 0;
}

int p4tc_parse_cmds(struct action_util *a, int *argc_p, char ***argv_p)
{
	char **argv = *argv_p;
	int argc = *argc_p;
	int ins_cnt = -1;
	int ret = 0;
	struct p4tc_cmds_v *ins = NULL;
	struct op_type_s *op = NULL;

	while (argc > 0) {

		if (strcmp(*argv, "cmd") == 0) {
                        NEXT_ARG();
			ins_cnt++;
			if (ins_cnt > P4TC_CMDS_LIST_MAX) {
				fprintf(stderr, "p4tc_cmds too many ins: %d>%d\n",
					ins_cnt, P4TC_CMDS_LIST_MAX);
				return -1;
			}
			ins = &INS[ins_cnt];
			ins->ins.op_ctl1 = ins->ins.op_ctl2 = TC_ACT_PIPE;
			continue;

		} else if (strcmp(*argv, "set") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_SET;
			op = get_op_byname("set");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <set>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "act") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_ACT;
			op = get_op_byname("act");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}

			discover_actions();
			//print_known_actions();
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <act>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "beq") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BEQ;
			op = get_op_byname("beq");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <beq>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "bne") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BNE;
			op = get_op_byname("bne");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <bne>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bgt") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BGT;
			op = get_op_byname("bgt");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <bgt>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "blt") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BLT;
			op = get_op_byname("blt");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <blt>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bge") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BGE;
			op = get_op_byname("bge");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <bge>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "ble") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BLE;
			op = get_op_byname("ble");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <ble>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "print") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_PRINT;
			op = get_op_byname("print");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <print>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "tableapply") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_TBLAPP;
			op = get_op_byname("tableapply");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <tableapply>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "send_port_egress") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_SNDPORTEGR;
			op = get_op_byname("send_port_egress");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <send_port_egress>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "mirror_port_egress") == 0) {
                        NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_MIRPORTEGR;
			op = get_op_byname("mirror_port_egress");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <mirror_port_egress>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "plus") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_PLUS;
			op = get_op_byname("plus");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "p4tc_cmds bad <plus>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "sub") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_SUB;
			op = get_op_byname("sub");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad <sub>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "concat") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_CONCAT;
			op = get_op_byname("concat");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <concat>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "band") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BAND;
			op = get_op_byname("band");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
		argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <band>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bor") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BOR;
			op = get_op_byname("bor");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
		argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <bor>: %d:<%s>\n",
		argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "bxor") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_BXOR;
			op = get_op_byname("bxor");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
		argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <bxor>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "jump") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_JUMP;
			op = get_op_byname("jump");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <jump>: %d:<%s>\n",
					argc, *argv);
			}
			continue;
		} else if (strcmp(*argv, "label") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_LABEL;
			op = get_op_byname("label");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <label>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;
		} else if (strcmp(*argv, "return") == 0) {
			NEXT_ARG();
			ins->ins.op_type = P4TC_CMD_OP_RET;
			op = get_op_byname("return");
			if (!op) {
				fprintf(stderr, "p4tc_cmds unknown cmd: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			ret = op->parse_operands(a, &argc, &argv, ins);
			if (ret != 0) {
				fprintf(stderr, "bad p4tc_cmd <return>: %d:<%s>\n",
					argc, *argv);
				return -1;
			}
			continue;

		} else if (strcmp(*argv, "index") == 0) {
			break;
		} else if (strcmp(*argv, "defact") == 0) {
			break;
		} else if (strcmp(*argv, "param") == 0) {
			break;
		} else {
			fprintf(stderr, "p4tc_cmds: bad command %d:<%s>\n",
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

int p4tc_add_cmds(struct nlmsghdr *n, int ins_cnt, int tca_id)
{
	struct p4tc_cmds_v *ins = NULL;
	struct rtattr *tailinsl, *tailins;
	int i;

	if (!ins_cnt) {
		return 0;
	}

	tailinsl = addattr_nest(n, MAX_MSG, tca_id | NLA_F_NESTED);
	for (i = 0; i < ins_cnt; i++) {
		struct rtattr *tailoper;
		int j;

		tailins = addattr_nest(n, MAX_MSG, (i + 1) | NLA_F_NESTED);


		ins = &INS[i];

		addattr_l(n, MAX_MSG, P4TC_CMD_OPERATION, &ins->ins,
			  sizeof(struct p4tc_u_operate));

		if (ins->label1)
			addattrstrz(n, MAX_MSG, P4TC_CMD_OPER_LABEL1,
				    ins->label1);
		if (ins->label2)
			addattrstrz(n, MAX_MSG, P4TC_CMD_OPER_LABEL2,
				    ins->label2);

		tailoper = addattr_nest(n, MAX_MSG,
					     P4TC_CMD_OPER_LIST | NLA_F_NESTED);
		for (j = 0; j < P4TC_CMD_OPERS_MAX; j++) {
			struct p4tc_u_internal_operand *op;
			struct rtattr *count;

			op = &ins->opnds[j];

			if (op->op.oper_type == P4TC_OPER_UNSPEC)
				break;

			count = addattr_nest(n, MAX_MSG, (j + 1) | NLA_F_NESTED);
			if (op->path) {
				addattrstrz(n, MAX_MSG, P4TC_CMD_OPND_PATH,
					    op->path);
			}
			if (op->extra_path) {
				addattrstrz(n, MAX_MSG, P4TC_CMD_OPND_PATH_EXTRA,
					    op->extra_path);
			}
			if (op->immedv_large) {
				addattrstrz(n, MAX_MSG,
					    P4TC_CMD_OPND_LARGE_CONSTANT,
					    op->immedv_large);
			}
			if (op->print_prefix) {
				addattrstrz(n, MAX_MSG,
					    P4TC_CMD_OPND_PREFIX,
					    op->print_prefix);
			}
			addattr_l(n, MAX_MSG, P4TC_CMD_OPND_INFO, &op->op,
				  sizeof(struct p4tc_u_operand));
			addattr_nest_end(n, count);
		}
		addattr_nest_end(n, tailoper);

		addattr_nest_end(n, tailins);
	}
	addattr_nest_end(n, tailinsl);

	return 0;
}

int p4tc_cmds_print_operand(const char *ABC, struct action_util *au,
			    struct rtattr *op_attr, FILE *f)
{
	void *immedv_large = NULL;
	void *prefix = NULL;
	void *path = NULL;
	struct rtattr *tb[P4TC_CMD_OPND_MAX + 1];
	struct p4tc_u_operand *opnd;

	if (!op_attr)
		return 0;

	parse_rtattr_nested(tb, P4TC_CMD_OPND_MAX, op_attr);

	if (tb[P4TC_CMD_OPND_PATH])
		path = RTA_DATA(tb[P4TC_CMD_OPND_PATH]);

	if (tb[P4TC_CMD_OPND_PREFIX])
		prefix = RTA_DATA(tb[P4TC_CMD_OPND_PREFIX]);

	if (tb[P4TC_CMD_OPND_LARGE_CONSTANT])
		immedv_large = RTA_DATA(tb[P4TC_CMD_OPND_LARGE_CONSTANT]);

	if (!tb[P4TC_CMD_OPND_INFO]) {
		fprintf(stderr, "Missing p4tc_cmds operand information\n");
		return -1;
	}

	opnd = RTA_DATA(tb[P4TC_CMD_OPND_INFO]);
	print_operand_content(ABC, au, opnd, path, immedv_large, prefix,
			      stdout);

	return 0;
}

static int p4tc_cmds_print_operands(struct action_util *au,
				    struct rtattr *op_attr, FILE *f)
{
	struct rtattr *tb[P4TC_CMD_OPERS_MAX + 1];
	char ABC[] = { 'O', 'P', 'A' };
	int i;

	if (!op_attr)
		return 0;

	parse_rtattr_nested(tb, P4TC_CMD_OPERS_MAX, op_attr);

	for (i = 1; i < P4TC_CMD_OPERS_MAX + 1 && tb[i]; i++) {
		open_json_object(ABC);
		p4tc_cmds_print_operand(&ABC[2], au, tb[i], f);
		close_json_object();

		ABC[2] = ABC[2] + 1;
	}

	return 0;
}

static int p4tc_cmds_print_ops(int i, struct action_util *au,
			       struct rtattr *op_attr, FILE *f)
{
	struct rtattr *tb[P4TC_CMD_OPER_MAX + 1];
	struct p4tc_u_operate *op_entry;
	int err;

	parse_rtattr_nested(tb, P4TC_CMD_OPER_MAX, op_attr);

	if (!tb[P4TC_CMD_OPERATION]) {
		fprintf(stderr, "Missing p4tc_cmds operation\n");
		return -1;
	}

	op_entry = RTA_DATA(tb[P4TC_CMD_OPERATION]);

	print_operation(op_entry, f);

	open_json_object("operands");

	err = p4tc_cmds_print_operands(au, tb[P4TC_CMD_OPER_LIST], f);
        if (err < 0)
                return err;

	close_json_object();

	return 0;
}

int p4tc_print_cmds(FILE *f, struct action_util *au, struct rtattr *arg)
{
	struct rtattr *oplist_attr[P4TC_CMDS_LIST_MAX + 1];
	int err, i;

	parse_rtattr_nested(oplist_attr, P4TC_CMDS_LIST_MAX, arg);

	open_json_array(PRINT_JSON, "operations");
	for (i = 1; i <= P4TC_CMDS_LIST_MAX && oplist_attr[i]; i++) {
		open_json_object(NULL);
		err = p4tc_cmds_print_ops(i, au, oplist_attr[i], f);
		if (err) {
			unregister_kernel_metadata();
			return err;
		}
		close_json_object();
	}
	close_json_array(PRINT_JSON, NULL);

	print_nl();

	return 0;
}
