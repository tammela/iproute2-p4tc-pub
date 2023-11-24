/*
 * p4tc_filter.c		P4 TC Filter
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022-2024, Mojatatu Networks
 * Copyright (c) 2022-2024, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "utils.h"
#include "rt_names.h"
#include "tc_common.h"
#include "names.h"
#include "p4_types.h"
#include "p4tc_filter.h"

static struct typedexpr typed_error = {
	.t = ET_ERR,
};

#define err_type_fmt(fmt, args...) ({ \
	if (snprintf(typed_error.errmsg_fmt, P4TC_EXPR_FMTMSG_LEN, \
		     "%s" fmt "%s", "", ##args, "") >=  \
		      P4TC_EXPR_FMTMSG_LEN) \
		fprintf(stderr, "Error message was trucated\n"); \
	typed_error.errmsg = typed_error.errmsg_fmt; \
	&typed_error;  })

#define err_type(msg) ({ \
	typed_error.errmsg = msg; \
	&typed_error; })

static int equalable_types(struct p4_type_s *a, struct p4_type_s *b)
{
	if (p4type_numeric(a))
		return(p4type_numeric(b));
	if (p4type_numeric(b))
		return false;

	return a->containid == b->containid;
}

static bool comparable_types(struct p4_type_s *a, struct p4_type_s *b)
{
	if (p4type_numeric(a))
		return p4type_numeric(b);
	if (p4type_numeric(b))
		return false;
	if (a->containid == P4TC_T_STRING)
		return b->containid == P4TC_T_STRING;

	return false;
}

#define MAX_PREFIXED_EXP_COMPONENTS 7

enum p4tc_filter_name_expr_type {
	P4TC_NAME_EXPR_KEYFIELD,
	P4TC_NAME_EXPR_ACT_PARAM,
	P4TC_NAME_EXPR_DEV,
	P4TC_NAME_EXPR_IPV4,
	P4TC_NAME_EXPR_IPV6,
	P4TC_NAME_EXPR_MAC,
	P4TC_NAME_EXPR_CUSTOM,
};

struct p4tc_table_keyfield {
	char name[P4TC_NAME_LEN];
	struct p4_type_s *key_type;
	int bitoff;
	__u32 tbl_keysz;
	__u32 bitsz;
};

#define KNOWN_UNPREFIXED_NAME_STRING_MAX 32

struct known_unprefixed_name {
	char name[KNOWN_UNPREFIXED_NAME_STRING_MAX];
	struct p4_type_s *type;
	__u32 uapi_attr;
};

union p4tc_filter_name_expr {
	enum p4tc_filter_name_expr_type type;
	struct {
		enum p4tc_filter_name_expr_type type;
		struct p4tc_table_keyfield *data;
	} keyfield;
	struct {
		enum p4tc_filter_name_expr_type type;
		struct p4tc_act_param *data;
		char fullactname[ACTNAMSIZ];
	} act_param;
	struct {
		enum p4tc_filter_name_expr_type type;
		__u32 ifindex;
	} dev;
	struct {
		enum p4tc_filter_name_expr_type type;
		struct known_unprefixed_name *known_unprefixed_name;
	} custom;
};

static int get_prefixed_tbl_keyfield(struct p4tc_table_keyfield *keyfield,
				     const char **p4tcpath)
{
	struct p4tc_json_key_fields_list *key;
	const char *pname = p4tcpath[1];
	struct p4tc_json_pipeline *p;
	struct p4tc_json_table *t;
	int ret = 0;

	key = introspect_key_field_byname(&p, &t, pname, p4tcpath,
					  p4tcpath[4]);

	if (!key)
		return -1;

	keyfield->key_type = get_p4type_byarg(key->type, &keyfield->bitsz);
	if (!keyfield->key_type) {
		fprintf(stderr, "Unable to find type %s\n", key->type);
		ret = -1;
		goto free_json_pipeline;
	}
	keyfield->bitoff = key->bitoff;
	strcpy(keyfield->name, key->name);
	keyfield->tbl_keysz = t->ksize;

free_json_pipeline:
	p4tc_json_free_pipeline(p);
	return ret;
}

static int get_prefixed_act_param_type(struct p4tc_act_param *param,
				       const char **p4tcpath)
{
	struct p4tc_json_actions_list *act;
	struct p4tc_json_pipeline *pipe;
	int ret;

	act = introspect_action_byname(&pipe, &p4tcpath[2]);
	if (!act)
		return -1;

	ret = p4tc_act_param_build(act, param, p4tcpath[5], true);
	if (ret < 0)
		return -1;

	return 0;
}

/* Options:
 * - param.act.pname.cbname.actname.paramname
 * - key.pname.cbname.tblname.keyfield
 */
static int parse_prefixed_exp(struct typedexpr *t, struct parsedexpr *e,
			      const char *prefix_exp)
{
	union p4tc_filter_name_expr *filter_name_expr;
	char *p4tcpath[MAX_PREFIXED_EXP_COMPONENTS];
	char *prefix_exp_copy = strdup(prefix_exp);
	int num_components;
	int ret = 0;

	num_components = parse_path(prefix_exp_copy, p4tcpath, ".");
	if (num_components < 0) {
		free(prefix_exp_copy);
		return -1;
	}

	if (strcmp(p4tcpath[0], "param") == 0) {
		struct p4tc_act_param *param;

		if (num_components != 5 && num_components != 6) {
			err_type_fmt("Invalid param operand %s",
				     prefix_exp_copy);
			free(prefix_exp_copy);
			return -1;
		}

		filter_name_expr = calloc(1, sizeof(*filter_name_expr));
		if (!filter_name_expr) {
			free(prefix_exp_copy);
			err_type("Out of memory");
			return -ENOMEM;
		}
		filter_name_expr->type = P4TC_NAME_EXPR_ACT_PARAM;

		param = calloc(1, sizeof(*param));
		if (!param) {
			free(filter_name_expr);
			free(prefix_exp_copy);
			err_type("Out of memory");
			return -ENOMEM;
		}

		ret = get_prefixed_act_param_type(param,
						  (const char **)p4tcpath);
		if (ret < 0) {
			free(param);
			free(filter_name_expr);
			free(prefix_exp_copy);
			return ret;
		}
		/* - param.act.pname.cbname.actname.paramname */
		if (num_components == 6)
			snprintf(filter_name_expr->act_param.fullactname,
				 ACTNAMSIZ, "%s/%s/%s", p4tcpath[2],
				 p4tcpath[3], p4tcpath[4]);
		else
			snprintf(filter_name_expr->act_param.fullactname,
				 ACTNAMSIZ, "%s/%s", p4tcpath[2],
				 p4tcpath[3]);

		filter_name_expr->act_param.data = param;
		t->name.name = e->name.name;
		t->name.data = filter_name_expr;
		t->name.typ = param->type;
	} else if (strcmp(p4tcpath[0], "key") == 0) {
		struct p4tc_table_keyfield *keyfield;

		filter_name_expr = calloc(1, sizeof(*filter_name_expr));
		if (!filter_name_expr) {
			free(prefix_exp_copy);
			err_type("Out of memory");
			return -ENOMEM;
		}
		filter_name_expr->type = P4TC_NAME_EXPR_KEYFIELD;

		keyfield = calloc(1, sizeof(*keyfield));
		if (!keyfield) {
			free(filter_name_expr);
			free(prefix_exp_copy);
			err_type("Out of memory");
			return -ENOMEM;
		}

		ret = get_prefixed_tbl_keyfield(keyfield,
						(const char **)p4tcpath);
		if (ret < 0) {
			free(keyfield);
			free(filter_name_expr);
			free(prefix_exp_copy);
			return ret;
		}
		filter_name_expr->keyfield.data = keyfield;
		t->name.name = e->name.name;
		t->name.data = filter_name_expr;
		t->name.typ = keyfield->key_type;
	} else {
		err_type_fmt("Unknown token %s", prefix_exp);
	}

	free(prefix_exp_copy);

	return ret;
}

static void free_typedexpr_name_prefix(struct typedexpr *t)
{
	union p4tc_filter_name_expr *filter_name_expr = t->name.data;

	if (filter_name_expr) {
		switch (filter_name_expr->type) {
		case P4TC_NAME_EXPR_KEYFIELD:
			free(filter_name_expr->keyfield.data);
			break;
		case P4TC_NAME_EXPR_ACT_PARAM:
			free(filter_name_expr->act_param.data);
			break;
		default:
			/* Will never happen */
			break;
		}

		free(filter_name_expr);
	}
}

void free_typedexpr(struct typedexpr *t)
{
	switch (t->t) {
	case ET_NAME:
		free_typedexpr_name_prefix(t);
		break;
	case ET_UNARY:
		free_typedexpr(t->unary.arg);
		break;
	case ET_BINARY:
		free_typedexpr(t->binary.lhs);
		free_typedexpr(t->binary.rhs);
		break;
	default:
		break;
	}

	free(t);
}

/* Will search JSON to try and retrieve type */
/* Returns -EINVAL on failure */
static struct typedexpr *type_prefixed_name_exp(struct parsedexpr *e)
{
	char *prefixed_exp = e->name.name;
	struct typedexpr *typed_prefix;
	int ret;

	typed_prefix = calloc(1, sizeof(*typed_prefix));
	if (!typed_prefix)
		return err_type("Out of memory");

	ret = parse_prefixed_exp(typed_prefix, e, prefixed_exp);
	if (ret < 0) {
		free(typed_prefix);
		return &typed_error;
	}

	typed_prefix->t = ET_NAME;

	return typed_prefix;
}

static struct p4_type_s *
get_filter_name_expr_type(union p4tc_filter_name_expr *filter_name_expr)
{
	switch (filter_name_expr->type) {
	case P4TC_NAME_EXPR_KEYFIELD: {
		struct p4tc_table_keyfield *keyfield;

		keyfield = filter_name_expr->keyfield.data;
		return keyfield->key_type;
	}
	case P4TC_NAME_EXPR_ACT_PARAM: {
		struct p4tc_act_param *act_param;

		act_param = filter_name_expr->act_param.data;
		return act_param->type;
	}
	case P4TC_NAME_EXPR_DEV:
		return get_p4type_byid(P4TC_T_DEV);
	case P4TC_NAME_EXPR_IPV4:
		return get_p4type_byid(P4TC_T_IPV4ADDR);
	case P4TC_NAME_EXPR_IPV6:
		return get_p4type_byid(P4TC_T_U128);
	case P4TC_NAME_EXPR_MAC:
		return get_p4type_byid(P4TC_T_MACADDR);
	case P4TC_NAME_EXPR_CUSTOM: {
		struct known_unprefixed_name *known_unprefixed_name;

		known_unprefixed_name =
			filter_name_expr->custom.known_unprefixed_name;

		return known_unprefixed_name->type;
	}
	default:
		/* Should never happen */
		return NULL;
	}
}

static struct p4_type_s *typedexpr_extract_type(struct typedexpr *t)
{
	int containid;

	switch (t->t) {
	case ET_BOOL:
		containid = P4TC_T_BOOL;
		break;
	case ET_INTEGER:
		return t->integer.typ;
	case ET_STRING:
		containid = P4TC_T_STRING;
		break;
	case ET_IPv4:
		containid = P4TC_T_IPV4ADDR;
		break;
	case ET_IPv6:
		containid = P4TC_T_U128;
		break;
	case ET_MAC:
		containid = P4TC_T_MACADDR;
		break;
	case ET_NAME: {
		union p4tc_filter_name_expr *filter_name_expr;
		struct p4_type_s *type;

		filter_name_expr = t->name.data;
		type = get_filter_name_expr_type(filter_name_expr);
		return type;
	}
	default:
		return NULL;
	}

	return get_p4type_byid(containid);
}

static bool expr_is_constant(struct parsedexpr *e)
{
	switch (e->t) {
	case ET_BOOL:
	case ET_INTEGER:
	case ET_STRING:
		return true;
	default:
		return false;
	}
}

static bool op_is_cmp(enum binary_op op)
{
	switch (op) {
	case B_LT:
	case B_GT:
	case B_LE:
	case B_GE:
		return true;
	default:
		return false;
	}
}

#define KNOW_UNPREFIXED_NAMES_MAX 16

static struct
known_unprefixed_name known_unprefixed_names_map[KNOW_UNPREFIXED_NAMES_MAX] = {};
static int num_known_unprefixed_names;

static int register_known_unprefixed_name(const char *name, int containid,
					  __u32 uapi_attr)
{
	struct known_unprefixed_name known_unprefixed_name = {0};

	if (num_known_unprefixed_names == KNOW_UNPREFIXED_NAMES_MAX) {
		fprintf(stderr, "Exceeded known unprefixed names limit\n");
		return -1;
	}

	if (strnlen(name, KNOWN_UNPREFIXED_NAME_STRING_MAX) ==
	    KNOWN_UNPREFIXED_NAME_STRING_MAX) {
		fprintf(stderr, "Exceeded known unprefixed names too big %s\n",
			name);
		return -1;
	}

	strcpy(known_unprefixed_name.name, name);
	known_unprefixed_name.type = get_p4type_byid(containid);
	if (!known_unprefixed_name.type)
		return -1;
	known_unprefixed_name.uapi_attr = uapi_attr;

	known_unprefixed_names_map[num_known_unprefixed_names] =
		known_unprefixed_name;

	num_known_unprefixed_names++;

	return 0;
}

int register_known_unprefixed_names(void)
{
	int ret;

	ret = register_known_unprefixed_name("prio", P4TC_T_U32,
					     P4TC_FILTER_OPND_ENTRY_PRIO);
	if (ret < 0) {
		fprintf(stderr, "Unable to unprefixed name prio\n");
		return ret;
	}

	ret = register_known_unprefixed_name("msecs_since", P4TC_T_U32,
					     P4TC_FILTER_OPND_ENTRY_TIME_DELTA);
	if (ret < 0) {
		fprintf(stderr, "Unable to unprefixed name prio\n");
		return ret;
	}

	return 0;
}

static struct known_unprefixed_name *
lookup_known_unprefixed_names(const char *name)
{
	int i;

	for (i = 0; i < num_known_unprefixed_names; i++) {
		struct known_unprefixed_name *known_unprefixed_name;

		known_unprefixed_name = &known_unprefixed_names_map[i];
		if (strcmp(name, known_unprefixed_name->name) == 0)
			return &known_unprefixed_names_map[i];
	}

	return NULL;
}

static struct typedexpr *type_unprefixed_name_expr(struct parsedexpr *name_expr,
						   struct p4_type_s *pair_type)
{
	struct known_unprefixed_name *known_unprefixed_name;
	union p4tc_filter_name_expr *filter_name_expr;
	struct typedexpr *typed_unprefixed;
	int ret;

	known_unprefixed_name =
		lookup_known_unprefixed_names(name_expr->name.name);
	if (known_unprefixed_name) {
		typed_unprefixed = calloc(1, sizeof(*typed_unprefixed));
		if (!typed_unprefixed)
			return err_type("Out of memory");

		filter_name_expr = calloc(1, sizeof(*filter_name_expr));
		if (!filter_name_expr) {
			free(typed_unprefixed);
			return err_type("Out of memory");
		}
		filter_name_expr->type = P4TC_NAME_EXPR_CUSTOM;
		filter_name_expr->custom.known_unprefixed_name =
			known_unprefixed_name;
		typed_unprefixed->name.name = name_expr->name.name;
		typed_unprefixed->t = ET_NAME;
		typed_unprefixed->name.data = filter_name_expr;

		return typed_unprefixed;
	}

	if (!pair_type)
		return err_type_fmt("Unknown unprefixed name %s",
				    name_expr->name.name);

	switch (pair_type->containid) {
	case P4TC_T_DEV: {
		struct p4_type_s *dev_type =
			get_p4type_byid(pair_type->containid);
		struct p4_type_value val = {0};

		typed_unprefixed = calloc(1, sizeof(*typed_unprefixed));
		if (!typed_unprefixed)
			return err_type("Out of memory");

		filter_name_expr = calloc(1, sizeof(*filter_name_expr));
		if (!filter_name_expr) {
			free(typed_unprefixed);
			return err_type("Out of memory");
		}

		val.value = &filter_name_expr->dev.ifindex;
		filter_name_expr->type = P4TC_NAME_EXPR_DEV;
		ret = dev_type->parse_p4t(&val, name_expr->name.name, 0);
		if (ret < 0) {
			free(filter_name_expr);
			return err_type("Out of memory");
		}
		typed_unprefixed->name.data = filter_name_expr;
		typed_unprefixed->name.name = name_expr->name.name;
		typed_unprefixed->t = ET_NAME;

		return typed_unprefixed;
	}
	default:
		return err_type_fmt("What is %s?\n", name_expr->name.name);
	}
}

static struct typedexpr *type_integer(struct parsedexpr *integer,
				      struct p4_type_s *pair_type)
{
	struct p4_type_value val = {0};
	struct typedexpr *t;
	int ret;

	val.value = &integer->integer.i;
	val.bitsz = pair_type->bitsz;
	ret = pair_type->parse_p4t(&val, integer->integer.s, 0);
	if (ret < 0)
		return err_type_fmt("Invalid %s integer %s\n",
				    pair_type->name, integer->integer.s);

	t = calloc(1, sizeof(*t));
	if (!t)
		return err_type("Out of memory");

	t->t = ET_INTEGER;
	t->integer.i = integer->integer.i;
	t->integer.typ = pair_type;

	return t;
}

#define COPY_PARSEDEXPR_CONSTANT(expr_const, typed_const, field) \
	memcpy(&(typed_const)->field, &(expr_const)->field, \
	       sizeof(expr_const->field))

static bool constant_string_requires_typing(struct p4_type_s *prefix_name_type)
{
	switch (prefix_name_type->containid) {
	case P4TC_T_IPV4ADDR:
	case P4TC_T_MACADDR:
	case P4TC_T_U128:
		return true;
	default:
		return false;
	}
}

static struct typedexpr *type_constant_string(struct parsedexpr *string,
					      struct p4_type_s *prefix_name_type)
{
	struct typedexpr *typed_constant;
	int ret;

	if (!constant_string_requires_typing(prefix_name_type)) {
		if (prefix_name_type->containid != P4TC_T_STRING)
			return err_type("rhs and lhs have incompatible types");

		typed_constant = calloc(1, sizeof(*typed_constant));
		if (!typed_constant)
			return err_type("Out of memory");

		COPY_PARSEDEXPR_CONSTANT(string, typed_constant, string);
		return typed_constant;
	}

	switch (prefix_name_type->containid) {
	case P4TC_T_IPV4ADDR: {
		struct p4_type_s *ipv4_type =
			get_p4type_byid(prefix_name_type->containid);
		struct p4_type_value val = {0};

		typed_constant = calloc(1, sizeof(*typed_constant));
		if (!typed_constant)
			return err_type("Out of memory");

		val.value = &typed_constant->ipv4.a;
		val.mask = &typed_constant->ipv4.mask;

		ret = ipv4_type->parse_p4t(&val,
					   (const char *)string->string.txt,
					   0);
		if (ret < 0)
			free(typed_constant);

		typed_constant->t = ET_IPv4;
		typed_constant->ipv4.a = *((__u32 *)val.value);

		return typed_constant;
	}
	case P4TC_T_U128: {
		struct p4_type_s *u128_type =
			get_p4type_byid(prefix_name_type->containid);
		struct p4_type_value val = {0};

		typed_constant = calloc(1, sizeof(*typed_constant));
		if (!typed_constant)
			return err_type("Out of memory");

		val.value = typed_constant->ipv6.a;
		val.mask = &typed_constant->ipv6.mask;

		ret = u128_type->parse_p4t(&val,
					   (const char *)string->string.txt,
					   0);
		if (ret < 0)
			free(typed_constant);

		typed_constant->t = ET_IPv6;
		memcpy(typed_constant->ipv6.a, val.value, 16);

		return typed_constant;
	}
	case P4TC_T_MACADDR: {
		struct p4_type_s *mac_type =
			get_p4type_byid(prefix_name_type->containid);
		struct p4_type_value val = {0};

		typed_constant = calloc(1, sizeof(*typed_constant));
		if (!typed_constant)
			return err_type("Out of memory");
		val.value = typed_constant->mac.a;
		ret = mac_type->parse_p4t(&val,
					  (const char *)string->string.txt,
					  0);
		if (ret < 0)
			free(typed_constant);

		typed_constant->t = ET_MAC;

		return typed_constant;
	}
	default:
		/* Will never happen */
		return err_type_fmt("Invalid type %u\n",
				    prefix_name_type->containid);
	}

	return typed_constant;
}

static struct typedexpr *type_constant(struct parsedexpr *constant,
				       struct p4_type_s *prefix_name_type)
{
	struct typedexpr *typed_constant;

	switch (constant->t) {
	case ET_INTEGER:
		if (p4type_numeric(prefix_name_type)) {
			typed_constant = type_integer(constant,
						      prefix_name_type);
			if (typed_constant->t == ET_ERR)
				return typed_constant;
		} else {
			return err_type("rhs and lhs have incompatible types");
		}
		return typed_constant;
	case ET_STRING:
		return type_constant_string(constant, prefix_name_type);
	case ET_BOOL:
		if (prefix_name_type->containid != P4TC_T_BOOL)
			return err_type("rhs and lhs have incompatible types");

		typed_constant = calloc(1, sizeof(*typed_constant));
		if (!typed_constant)
			return err_type("Out of memory");

		COPY_PARSEDEXPR_CONSTANT(constant, typed_constant, boolean);
		break;
	default:
		/* Should never happen */
		return err_type("Unknown constant type");
	}

	typed_constant->t = constant->t;

	return typed_constant;
}

static bool validate_constant_relational(struct parsedexpr *op1,
					 struct parsedexpr *op2)
{
	if (expr_is_constant(op1)) {
		if (op2->t != ET_NAME) {
			err_type("Constants may only be compared to names");
			return false;
		}
	}

	return true;
}

/* Basic rules:
 * OPND1 OP OPND2
 * OP := < "<", ">", "=", "<=", ">="
 * One operand is always a PREFIXED_NAME and the other must be a
 * NONPREFIXED_NAME or a constant
 * In case of an OPND being a constant integer, the code will use the type of
 * the other operand to validate and extract the integer constant.
 */
static struct typedexpr *type_binary_relational(struct parsedexpr *e)
{
	struct parsedexpr *lhs = e->binary.lhs;
	struct parsedexpr *rhs = e->binary.rhs;
	struct typedexpr *typed_lhs = NULL;
	struct typedexpr *typed_rhs = NULL;
	struct p4_type_s *type_lhs = NULL;
	struct p4_type_s *type_rhs = NULL;
	enum binary_op op = e->binary.op;
	struct typedexpr *typed_binary;

	if (!validate_constant_relational(lhs, rhs) ||
	    !validate_constant_relational(rhs, lhs))
		return &typed_error;

	if (lhs->t == ET_NAME) {
		if (strchr(lhs->name.name, '.')) {
			typed_lhs = type_prefixed_name_exp(lhs);
			if (typed_lhs->t == ET_ERR)
				return typed_lhs;
			type_lhs = typedexpr_extract_type(typed_lhs);
		}
	} else {
		err_type("Left hand side must be a prefixed name operand");
		goto free_typed_ops;
	}

	if (rhs->t == ET_NAME) {
		if (strchr(rhs->name.name, '.')) {
			err_type("Right hand side can't be a prefiexed name operand");
			goto free_typed_ops;
		}
	}

	if (typed_lhs) {
		if (expr_is_constant(rhs)) {
			typed_rhs = type_constant(rhs, type_lhs);
			if (typed_rhs->t == ET_ERR)
				goto free_typed_ops;
		} else {
			typed_rhs = type_unprefixed_name_expr(rhs, type_lhs);
			if (typed_rhs->t == ET_ERR)
				goto free_typed_ops;
		}
		type_rhs = typedexpr_extract_type(typed_rhs);
	} else if (lhs->t == ET_NAME) {
		union p4tc_filter_name_expr *filter_name_expr;

		typed_lhs = type_unprefixed_name_expr(lhs, type_rhs);
		if (typed_lhs->t == ET_ERR)
			goto free_typed_ops;

		filter_name_expr = typed_lhs->name.data;
		if (filter_name_expr->type != P4TC_NAME_EXPR_CUSTOM) {
			err_type("Left hand side must a prefixed or a custom name");
			goto free_typed_ops;
		}

		type_lhs = typedexpr_extract_type(typed_lhs);

		if (expr_is_constant(rhs)) {
			typed_rhs = type_constant(rhs, type_lhs);
			if (typed_rhs->t == ET_ERR)
				goto free_typed_ops;
		} else {
			err_type("rhs of binary op must be a constant");
			goto free_typed_ops;
		}

		type_rhs = typedexpr_extract_type(typed_rhs);
	} else if (rhs->t == ET_NAME) {
		typed_rhs = type_unprefixed_name_expr(rhs, type_lhs);
		if (typed_rhs->t == ET_ERR)
			goto free_typed_ops;

		type_rhs = typedexpr_extract_type(typed_rhs);

		if (expr_is_constant(lhs)) {
			typed_rhs = type_constant(lhs, type_rhs);
			if (typed_rhs->t == ET_ERR)
				goto free_typed_ops;
		} else {
			err_type("rhs of binary op must be a constant");
			goto free_typed_ops;
		}

		type_lhs = typedexpr_extract_type(typed_lhs);
	} else {
		err_type("Invalid operands for binary op");
		goto free_typed_ops;
	}

	if (op_is_cmp(op)) {
		if (!comparable_types(type_lhs, type_rhs)) {
			err_type_fmt("Types %s and %s are not comparable",
				     type_lhs->name, type_rhs->name);
			goto free_typed_ops;
		}
	} else {
		if (!equalable_types(type_lhs, type_rhs)) {
			err_type_fmt("Types %s and %s are not equalable",
				     type_lhs->name, type_rhs->name);
			goto free_typed_ops;
		}
	}

	typed_binary = calloc(1, sizeof(*typed_binary));
	if (!typed_binary)
		goto free_typed_ops;

	typed_binary->binary.rhs = typed_rhs;
	typed_binary->binary.lhs = typed_lhs;
	typed_binary->binary.op = op;
	typed_binary->t = ET_BINARY;

	return typed_binary;

free_typed_ops:
	if (typed_rhs)
		free_typedexpr(typed_rhs);
	if (typed_lhs)
		free_typedexpr(typed_lhs);

	return &typed_error;
}

static struct typedexpr *type_unary(struct parsedexpr *e)
{
	struct typedexpr *typed_arg = &typed_error;
	struct typedexpr *typed_unary;

	switch (e->unary.op) {
	case U_MINUS:
		break;
	case U_LOGNOT:
		typed_arg = type_expr(e->unary.arg);
		break;
	default:
		break;
	}

	if (typed_arg == &typed_error)
		return typed_arg;

	typed_unary = calloc(1, sizeof(*typed_unary));
	typed_unary->unary.arg = typed_arg;
	typed_unary->unary.op = e->unary.op;
	typed_unary->t = ET_UNARY;

	return typed_unary;
}

static struct typedexpr *type_binary(struct parsedexpr *e)
{
	struct typedexpr *typed_binary;
	struct typedexpr *typed_lhs;
	struct typedexpr *typed_rhs;

	switch (e->binary.op) {
	case B_EQ:
	case B_NE:
	case B_LT:
	case B_GT:
	case B_LE:
	case B_GE:
		return type_binary_relational(e);
	case B_LOGAND:
	case B_LOGOR:
	case B_LOGXOR:
	default:
		break;
	}

	typed_lhs = type_expr(e->binary.lhs);
	if (typed_lhs->t == ET_ERR)
		return typed_lhs;
	typed_rhs = type_expr(e->binary.rhs);
	if (typed_rhs->t == ET_ERR)
		return typed_rhs;

	typed_binary = calloc(1, sizeof(*typed_binary));
	typed_binary->binary.lhs = typed_lhs;
	typed_binary->binary.rhs = typed_rhs;
	typed_binary->binary.op = e->binary.op;
	typed_binary->t = e->t;

	return typed_binary;
}

struct typedexpr *type_expr(struct parsedexpr *e)
{
	switch (e->t) {
	case ET_BINARY:
		return type_binary(e);
	case ET_UNARY:
		return type_unary(e);
	default:
		/* Will never happen */
		return err_type_fmt("Unknown expression type %u", e->t);
	}
}

#define ULL(X) X##ULL
#define UL(X) X##UL

#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BITS_PER_BYTE		8
#define BITS_PER_LONG 64

#define BUILD_BUG_ON_ZERO(e) (0)

#define GENMASK_INPUT_CHECK(h, l) \
		(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
				   __is_constexpr((l) > (h)), (l) > (h), 0)))

#define __GENMASK(h, l) \
		(((~UL(0)) - (UL(1) << (l)) + 1) & \
			 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))

#define GENMASK(h, l) \
		(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BITS_TO_BYTES(n) __KERNEL_DIV_ROUND_UP(n, sizeof(char) * 8)

static void shift_values(__u8 *blob, __u8 shift, __u32 sz,
			 __u32 offset)
{
	__u8 remainder = 0;
	int i;

	for (i = 0; i < sz; i++) {
		__u8 *ptr = &blob[i];
		__u8 ptr_before = *ptr;

		*ptr >>= shift;
		*ptr |= remainder;

		remainder = ptr_before << (8 - shift);
	}

	blob[sz] |= remainder;
	memmove(blob + offset, blob, sz + 1);
	memset(blob, 0, offset);
}

static void extract_relational_val(void *value, void *mask, struct typedexpr *val,
				   bool *extracted_mask)
{
	switch (val->t) {
	case ET_BOOL: {
		bool *b = value;

		*b = val->boolean.v;
		break;
	}
	case ET_INTEGER: {
		int *i = value;

		*i = val->integer.i;
		break;
	}
	case ET_STRING:
		memcpy(value, val->string.txt, val->string.len);
		break;
	case ET_IPv4:
		memcpy(value, &val->ipv4.a, 4);
		break;
	case ET_IPv6:
		memcpy(value, val->ipv6.a, 16);
		break;
	case ET_MAC:
		memcpy(value, val->mac.a, 6);
		break;
	case ET_NAME: {
		union p4tc_filter_name_expr *name_expr;

		name_expr = val->name.data;
		switch (name_expr->type) {
		case P4TC_NAME_EXPR_DEV: {
			__u32 *ifindex = value;

			*ifindex = name_expr->dev.ifindex;
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		break;
	}
}

static void add_binary_relation(struct nlmsghdr *n, struct typedexpr *name,
				struct typedexpr *val, __u32 rel_attr)
{
	union p4tc_filter_name_expr *filter_name_expr = name->name.data;
	bool extracted_mask = false;
	struct rtattr *oper1_nest;
	struct rtattr *oper1_leaf;
	struct rtattr *entry_nest;

	addattr16(n, MAX_MSG, P4TC_FILTER_OP_KIND, P4TC_FILTER_OP_KIND_REL);
	addattr16(n, MAX_MSG, P4TC_FILTER_OP_VALUE, rel_attr);

	oper1_nest = addattr_nest(n, MAX_MSG,
				  P4TC_FILTER_OP_NODE1 | NLA_F_NESTED);
	oper1_leaf = addattr_nest(n, MAX_MSG,
				  P4TC_FILTER_OP_NODE_LEAF | NLA_F_NESTED);
	entry_nest = addattr_nest(n, MAX_MSG,
				  P4TC_FILTER_OPND_ENTRY | NLA_F_NESTED);
	switch (filter_name_expr->type) {
	case P4TC_NAME_EXPR_KEYFIELD: {
		struct p4tc_table_keyfield *keyfield;
		__u8 mask[P4TC_MAX_KEYSZ] = {0};
		__u8 key[P4TC_MAX_KEYSZ] = {0};
		__u32 key_bytesoff_down;
		__u32 keysz_bytes;
		__u8 shift;

		extract_relational_val(key, mask, val, &extracted_mask);
		keyfield = filter_name_expr->keyfield.data;

		key_bytesoff_down = keyfield->bitoff >> 3;
		keysz_bytes = BITS_TO_BYTES(keyfield->bitsz);

		shift = (keyfield->bitoff - (key_bytesoff_down * 8));
		shift_values(key, shift, keysz_bytes, key_bytesoff_down);

		addattr_l(n, MAX_MSG, P4TC_FILTER_OPND_ENTRY_KEY_BLOB,
			  key, BITS_TO_BYTES(keyfield->tbl_keysz));
		if (!extracted_mask) {
			__u8 _shift = keyfield->bitsz - (keysz_bytes << 3);

			memset(mask, 0xFF, keysz_bytes);
			mask[keysz_bytes - 1] <<= _shift;
		}

		shift_values(mask, shift, keysz_bytes, key_bytesoff_down);

		addattr_l(n, MAX_MSG, P4TC_FILTER_OPND_ENTRY_MASK_BLOB,
			  mask, BITS_TO_BYTES(keyfield->tbl_keysz));
		break;
	}
	case P4TC_NAME_EXPR_ACT_PARAM: {
		struct p4tc_act_param *act_param;
		__u8 value[P4TC_MAX_KEYSZ] = {0};
		__u8 mask[P4TC_MAX_KEYSZ] = {0};
		struct rtattr *act_param_nest;
		struct rtattr *act_nest;

		act_nest = addattr_nest(n, MAX_MSG,
					P4TC_FILTER_OPND_ENTRY_ACT | NLA_F_NESTED);
		act_param_nest = addattr_nest(n, MAX_MSG,
					      P4TC_FILTER_OPND_ENTRY_ACT_PARAMS | NLA_F_NESTED);
		act_param = filter_name_expr->act_param.data;
		extract_relational_val(value, mask, val, &extracted_mask);
		dyna_add_param(act_param, value, true, n, false);
		addattr_nest_end(n, act_param_nest);
		addattrstrz(n, MAX_MSG, P4TC_FILTER_OPND_ENTRY_ACT_NAME,
			    filter_name_expr->act_param.fullactname);
		addattr_nest_end(n, act_nest);
		break;
	}
	case P4TC_NAME_EXPR_CUSTOM: {
		struct known_unprefixed_name *known_unprefixed_name;

		known_unprefixed_name =
			filter_name_expr->custom.known_unprefixed_name;

		switch (known_unprefixed_name->uapi_attr) {
		case P4TC_FILTER_OPND_ENTRY_PRIO:
		case P4TC_FILTER_OPND_ENTRY_TIME_DELTA: {
			__u32 value, mask;

			extract_relational_val(&value, &mask, val,
					       &extracted_mask);
			addattr32(n, MAX_MSG, known_unprefixed_name->uapi_attr,
				  value);
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		break;
	}

	addattr_nest_end(n, entry_nest);
	addattr_nest_end(n, oper1_leaf);
	addattr_nest_end(n, oper1_nest);
}

void add_typed_expr(struct nlmsghdr *n, struct typedexpr *t);

static void add_logical_op(struct nlmsghdr *n, struct typedexpr *t,
			   __u16 uapi_op)
{
	struct rtattr *oper_parent;
	struct rtattr *oper_nest;

	addattr16(n, MAX_MSG, P4TC_FILTER_OP_KIND, P4TC_FILTER_OP_KIND_LOGICAL);
	addattr16(n, MAX_MSG, P4TC_FILTER_OP_VALUE, uapi_op);
	oper_nest = addattr_nest(n, MAX_MSG,
				 P4TC_FILTER_OP_NODE1 | NLA_F_NESTED);
	oper_parent = addattr_nest(n, MAX_MSG,
				   P4TC_FILTER_OP_NODE_PARENT | NLA_F_NESTED);
	if (t->t == ET_BINARY) {
		add_typed_expr(n, t->binary.lhs);
		addattr_nest_end(n, oper_nest);
		addattr_nest_end(n, oper_parent);

		oper_nest = addattr_nest(n, MAX_MSG,
					 P4TC_FILTER_OP_NODE2 | NLA_F_NESTED);
		oper_parent = addattr_nest(n, MAX_MSG,
					   P4TC_FILTER_OP_NODE_PARENT | NLA_F_NESTED);
		add_typed_expr(n, t->binary.rhs);
	} else {
		add_typed_expr(n, t->unary.arg);
	}
	addattr_nest_end(n, oper_nest);
	addattr_nest_end(n, oper_parent);
}

static void add_typed_binary_relational(struct nlmsghdr *n, struct typedexpr *t,
					__u16 uapi_attr)
{
	struct typedexpr *name_op, *val_op;

	if (t->binary.rhs->t == ET_NAME) {
		union p4tc_filter_name_expr *name_expr;
		struct typedexpr *rhs = t->binary.rhs;

		name_expr = rhs->name.data;
		if (name_expr->type == P4TC_NAME_EXPR_DEV) {
			name_op = t->binary.lhs;
			val_op = rhs;
		} else {
			name_op = rhs;
			val_op = t->binary.lhs;
		}
	} else {
		union p4tc_filter_name_expr *name_expr;
		struct typedexpr *lhs = t->binary.lhs;

		name_expr = lhs->name.data;
		if (name_expr->type == P4TC_NAME_EXPR_DEV) {
			name_op = t->binary.rhs;
			val_op = lhs;
		} else {
			name_op = lhs;
			val_op = t->binary.rhs;
		}
	}
	add_binary_relation(n, name_op, val_op, uapi_attr);
}

static void add_typed_unary(struct nlmsghdr *n, struct typedexpr *t)
{
	add_logical_op(n, t, P4TC_FILTER_OP_KIND_LOGICAL_NOT);
}

static void add_typed_binary(struct nlmsghdr *n, struct typedexpr *t)
{
	switch (t->binary.op) {
	case B_EQ:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_EQ);
		break;
	case B_NE:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_NEQ);
		break;
	case B_LT:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_LT);
		break;
	case B_GT:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_GT);
		break;
	case B_LE:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_LE);
		break;
	case B_GE:
		add_typed_binary_relational(n, t, P4TC_FILTER_OP_KIND_REL_GE);
		break;
	case B_LOGAND:
		add_logical_op(n, t, P4TC_FILTER_OP_KIND_LOGICAL_AND);
		break;
	case B_LOGOR:
		add_logical_op(n, t, P4TC_FILTER_OP_KIND_LOGICAL_OR);
		break;
	case B_LOGXOR:
		add_logical_op(n, t, P4TC_FILTER_OP_KIND_LOGICAL_XOR);
		break;
	default:
		fprintf(stderr, "Not implemented\n");
		break;
	}
}

void add_typed_expr(struct nlmsghdr *n, struct typedexpr *t)
{
	switch (t->t) {
	case ET_ERR:
		fprintf(stderr, "t->errmsg %s\n", t->errmsg);
		break;
	case ET_BINARY:
		add_typed_binary(n, t);
		break;
	case ET_UNARY:
		add_typed_unary(n, t);
		break;
	default:
		fprintf(stderr, "Unknown expression type %u\n",
			t->t);
	}
}

static void
print_filter_name_expr_type(union p4tc_filter_name_expr *filter_name_expr)
{
	switch (filter_name_expr->type) {
	case P4TC_NAME_EXPR_KEYFIELD: {
		struct p4tc_table_keyfield *keyfield;

		keyfield = filter_name_expr->keyfield.data;

		printf("KEYFIELD: { NAME: %s TYPE: %s }\n",
		       keyfield->name, keyfield->key_type->name);
		break;
	}
	case P4TC_NAME_EXPR_ACT_PARAM: {
		struct p4tc_act_param *act_param;

		act_param = filter_name_expr->act_param.data;
		printf("ACT PARAM: { NAME: %s TYPE: %s }\n",
		       act_param->name, act_param->type->name);
		break;
	}
	case P4TC_NAME_EXPR_DEV: {
		struct p4_type_s *dev_type = get_p4type_byid(P4TC_T_DEV);
		struct p4_type_value val = {0};

		val.value = &filter_name_expr->dev.ifindex;
		dev_type->print_p4t("DEV PARAM: ", NULL, &val, stdout);
		printf("\n");
		break;
	}
	default:
		/* Should never happen */
		break;
	}
}

void dump_typed_expr(struct typedexpr *t, int indent);

static void dump_typed_binary(struct typedexpr *t, int indent)
{
	switch (t->binary.op) {
#define OP(op)\
	case B_##op:				\
		   printf("B_" #op "\n");			\
		   dump_typed_expr(t->binary.lhs, indent + 2);	\
		   dump_typed_expr(t->binary.rhs, indent + 2);	\
		   break;
	OP(EQ)
	OP(NE)
	OP(LT)
	OP(GT)
	OP(LE)
	OP(GE)
	OP(LOGAND)
	OP(LOGOR)
	OP(LOGXOR)
	default:
		printf("?binary(%d)", (int)t->binary.op);
		dump_typed_expr(t->binary.lhs, indent + 2);
		dump_typed_expr(t->binary.rhs, indent + 2);
		break;
#undef OP
	}
}

void dump_typed_expr(struct typedexpr *t, int indent)
{
	printf("%*s", indent, "");

	switch (t->t) {
	case  ET_BOOL:
		printf("bool = %s\n", t->boolean.v ? "true" : "false");
		break;
	case ET_INTEGER:
		printf("integer = %llu\n", t->integer.i);
		break;
	case ET_STRING:
		printf("string = %.*s\n", t->string.len, t->string.txt);
		break;
	case ET_IPv4: {
		struct p4_type_s *ipv4_type =
			get_p4type_byid(P4TC_T_IPV4ADDR);
		struct p4_type_value val = {0};

		val.value = &t->ipv4.a;
		val.mask = &t->ipv4.mask;
		ipv4_type->print_p4t("ipv4", NULL, &val, stdout);
		break;
	}
	case ET_IPv6: {
		printf("IPv6 = %x:%x:%x:%x:%x:%x:%x:%x",
		       (t->ipv6.a[0] * 256) + t->ipv6.a[1],
		       (t->ipv6.a[2] * 256) + t->ipv6.a[3],
		       (t->ipv6.a[4] * 256) + t->ipv6.a[5],
		       (t->ipv6.a[6] * 256) + t->ipv6.a[7],
		       (t->ipv6.a[8] * 256) + t->ipv6.a[9],
		       (t->ipv6.a[10] * 256) + t->ipv6.a[11],
		       (t->ipv6.a[12] * 256) + t->ipv6.a[13],
		       (t->ipv6.a[14] * 256) + t->ipv6.a[15]);
		if (t->ipv6.mask >= 0)
			printf("/%d",t->ipv6.mask);
		printf("\n");
		break;
	}
	case ET_MAC: {
		struct p4_type_s *mac_type =
			get_p4type_byid(P4TC_T_MACADDR);
		struct p4_type_value val = {0};

		val.value = &t->mac.a;
		mac_type->print_p4t("mac", NULL, &val, stdout);
		printf("\n");
		break;
	}
	case ET_NAME:
		print_filter_name_expr_type(t->name.data);
		break;
	case ET_UNARY:
		switch (t->unary.op) {
#define OP(op)\
		case U_##op:				\
			printf("U_" #op "\n");			\
			dump_typed_expr(t->unary.arg, indent + 2);	\
			break;
		OP(MINUS)
		OP(LOGNOT)
		default:
			printf("?unary(%d)", (int)t->unary.op);
			dump_typed_expr(t->unary.arg, indent + 2);
			break;
		}
		break;
	#undef OP
	case ET_BINARY:
		dump_typed_binary(t, indent);
		break;
	default:
		/* Will never happen */
		fprintf(stderr, "Unknown expression type %u\n", t->t);
	}
}
