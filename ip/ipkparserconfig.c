// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/* Copyright (c) 2022, SiPanda Inc.
 *
 * ipkparserconfig.c - ip parser(kParser) CLI static configuration
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * Author:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <errno.h>
#include "utils.h"
#include "kparser_common.h"

static inline void dump_inline_expanded_cli_cmd(int argc, const char **argv)
{
	int i;

	printf("\nDumping inline CLI cmd expansion: {parser ");
	for (i = 0; i < argc; i++)
		printf("%s ", argv[i]);
	printf("}\n");
}

static int check_key(int argc, const char **argv, const char *key)
{
	int i;

	for (i = 0; i < argc; i += 2)
		if (!strcmp(argv[i], key))
			return i;

	return -1;
}

static int check_key_idx(int argc, int start, const char **argv,
		const char *key)
{
	int i;

	if (start >= argc)
		return -1;

	for (i = start; i < argc; i += 2)
		if (!strcmp(argv[i], key))
			return i;

	return -1;
}

static inline int count_consecutive_bits(unsigned int *mem, size_t len,
		bool *shiftneeded)
{
	int cnt = 0, i;

	for (i = 0; i < len * BITS_IN_BYTE; i++) {
		if (kparsertestbit(mem, i)) {
			cnt++;
			continue;
		}
		if (i == 0)
			*shiftneeded = true;
	}
	return cnt;
}

#define KPARSER_ARG_S(bits, key, member, min, max, def, msg, ...)	\
	{								\
		.type = KPARSER_ARG_VAL_S##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_U(bits, key, member, min, max, def, msg, ...)	\
	{								\
		.type = KPARSER_ARG_VAL_U##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_U_HEX(bits, key, member, min, max, def, msg, ...)	\
	{								\
		.type = KPARSER_ARG_VAL_U##bits,			\
		.key_name = key,					\
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U##bits,		\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.print_id = KPARSER_PRINT_HEX,				\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.incompatible_keys = { __VA_ARGS__ },			\
	}

#define KPARSER_ARG_HKEY_NAME(key, member, msg, ...)			\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_name,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.name),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.name),				\
		.help_msg = "object's name",				\
		.incompatible_keys = { __VA_ARGS__ },			\
		.id = true,						\
	}

#define KPARSER_ARG_HKEY_ID(key, member, msg, ...)			\
	{								\
		.key_name = key,					\
		.default_template_token = &hkey_id,			\
		.other_mandatory_idx = -1,				\
		.w_offset = offsetof(struct kparser_conf_cmd,		\
				member.id),				\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member.id),				\
		.help_msg = "object's id",				\
		.incompatible_keys = { __VA_ARGS__ },			\
		.id = true,						\
	}

#define KPARSER_ARG_HKEY(keyname, idname, member, msg, ...)		\
	KPARSER_ARG_HKEY_NAME(keyname, member, msg, __VA_ARGS__),	\
	KPARSER_ARG_HKEY_ID(idname, member, msg, __VA_ARGS__)

#define KPARSER_ARG_H_K_N(key, member, def, msg)			\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_NAME,			\
		.key_name = key,					\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.str_arg_len_max = KPARSER_MAX_NAME,			\
		.help_msg = msg,					\
		.dontreport = true,					\
	}

#define KPARSER_ARG_H_K_I(key, member, min, max, def, msg)		\
	{								\
		.type = KPARSER_ARG_VAL_HYB_KEY_ID,			\
		.key_name = key,					\
		.min_value = min,					\
		.def_value = def,					\
		.max_value = max,					\
		.print_id = KPARSER_PRINT_HEX,				\
		.w_offset = offsetof(struct kparser_conf_cmd, member),	\
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->	\
				member),				\
		.help_msg = msg,					\
		.dontreport = true,					\
	}

#define KPARSER_ARG_BOOL(key_name_arg, member, def_value, msg, ...)	\
{									\
	.type = KPARSER_ARG_VAL_SET,					\
	.key_name = key_name_arg,					\
	.value_set_len = ARRAY_SIZE(bool_types),			\
	.value_set = bool_types,					\
	.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,			\
	.def_value_enum = def_value,					\
	.w_offset = offsetof(struct kparser_conf_cmd, member),		\
	.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->member),	\
	.help_msg = msg,						\
	.incompatible_keys = { __VA_ARGS__ },				\
}

static const struct kparser_arg_set bool_types[] = {
	{
		.set_value_str = "true",
		.set_value_enum = true,
	},
	{
		.set_value_str = "false",
		.set_value_enum = false,
	},
};

static const struct kparser_arg_key_val_token hkey_name = {
		.type = KPARSER_ARG_VAL_STR,
		.key_name = "name",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.str_arg_len_max = KPARSER_MAX_NAME,
		.help_msg = "string name of hash key",
		.id = true,
};

static const struct kparser_arg_key_val_token hkey_id = {
		.type = KPARSER_ARG_VAL_U16,
		.key_name = "id",
		.semi_optional = true,
		.other_mandatory_idx = -1,
		.str_arg_len_max = KPARSER_MAX_STR_LEN_U16,
		.min_value = KPARSER_USER_ID_MIN,
		.def_value = KPARSER_INVALID_ID,
		.max_value = KPARSER_USER_ID_MAX,
		.print_id = KPARSER_PRINT_HEX,
		.help_msg = "unsigned 16 bit hash key id",
		.id = true,
};

static const struct kparser_arg_set expr_types[] = {
	{
		.set_value_str = "equal",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_EQUAL,
	},
	{
		.set_value_str = "notequal",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_NOTEQUAL,
	},
	{
		.set_value_str = "lessthan",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_LT,
	},
	{
		.set_value_str = "lessthanequal",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_LTE,
	},
	{
		.set_value_str = "greaterthan",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_GT,
	},
	{
		.set_value_str = "greaterthanequal",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_GTE,
	},
};

static const struct kparser_arg_key_val_token cond_exprs_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = ARRAY_SIZE(expr_types),
		.value_set = expr_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_CONDEXPR_TYPE_EQUAL,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cond_conf.config.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cond_conf.config.type),
		.help_msg = "conditional expression type",
	},
	KPARSER_ARG_U(16, "src.field-off", cond_conf.config.src_off, 0, 0xffff,
			0,
			"Start offset in the packet data relative "
			"the current protocol header. The derived bytes will "
			"be evaluated."),
	KPARSER_ARG_U(8, "src.field-len", cond_conf.config.length, 0, 0xff, 0,
			"Length of the field which will be evaluated."),
	KPARSER_ARG_U_HEX(32, "mask", cond_conf.config.mask, 0,
			KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"Mask to extract the packet data field"),
	KPARSER_ARG_U(32, "value", cond_conf.config.value, 0,
			0xffffffff, 0,
			"Constant value to be compared with the derived packet "
			"data using the given `type` expression."),
};

static const struct kparser_arg_set default_fail_types[] = {
	{
		.set_value_str = "OKAY",
		.set_value_enum = KPARSER_OKAY,
	},
	{
		.set_value_str = "RET_OKAY",
		.set_value_enum = KPARSER_RET_OKAY,
	},
	{
		.set_value_str = "STOP_OKAY",
		.set_value_enum = KPARSER_STOP_OKAY,
	},
	{
		.set_value_str = "STOP_FAIL",
		.set_value_enum = KPARSER_STOP_FAIL,
	},
	{
		.set_value_str = "STOP_FAIL_CMP",
		.set_value_enum = KPARSER_STOP_FAIL_CMP,
	},
	{
		.set_value_str = "STOP_COMPARE",
		.set_value_enum = KPARSER_STOP_COMPARE,
	},
};

static const struct kparser_arg_set table_expr_types[] = {
	{
		.set_value_str = "or",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_OR,
	},
	{
		.set_value_str = "and",
		.set_value_enum = KPARSER_CONDEXPR_TYPE_AND,
	},
};

static const struct kparser_arg_key_val_token cond_exprs_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "defaultfail",
		.value_set_len = sizeof(default_fail_types) /
			sizeof(default_fail_types[0]),
		.value_set = default_fail_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_STOP_OKAY,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.optional_value1),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.optional_value1),
		.help_msg = "kparser return code to use as default failure",
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = sizeof(table_expr_types) /
			sizeof(table_expr_types[0]),
		.value_set = table_expr_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_CONDEXPR_TYPE_OR,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.optional_value2),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.optional_value2),
		.help_msg = "conditional expression table type",
	},
	KPARSER_ARG_H_K_N("table", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX,
			"hybrid key name for the associated conditional "
			"expression table"),
	KPARSER_ARG_H_K_I("table", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID,
			"hybrid key id for the associated conditional "
			"expression table"),
	KPARSER_ARG_HKEY("condexprs",
			"condexprs-id", table_conf.elem_key,
			"associated conditional expression entry's name or id",
			NULL, NULL),
};

static const struct kparser_arg_key_val_token cond_exprs_tables_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_N("condexprstable",
			table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX,
			"hybrid key name for the associated table of "
			"conditional expression table"),
	KPARSER_ARG_H_K_I("condexprstable-id",
			table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID,
			"hybrid key id for the associated table of "
			"conditional expression table"),
	KPARSER_ARG_HKEY("condexprslist",
			"condexprslist-id", table_conf.elem_key,
			"associated table of conditional expression's "
			"name or id"),
};

static const struct kparser_arg_key_val_token counter_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cntr_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cntr_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				cntr_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				cntr_conf.key.id),
	},
	KPARSER_ARG_U(32, "maxvalue", cntr_conf.conf.max_value,
			0, 0xffffffff, 0, "max value of this counter"),
	KPARSER_ARG_U(32, "arraylimit", cntr_conf.conf.array_limit,
			0, 0xffffffff, 0,
			"size of the array field in metadata"),
	KPARSER_ARG_U(64, "arrayelementsize", cntr_conf.conf.el_size, 0,
			0xffffffff, 0, "metadata array field's element size"),
	KPARSER_ARG_BOOL("resetonencap", cntr_conf.conf.reset_on_encap, true,
			"Unset if counter value not to be reset upon "
			"encapsulation encounter"),
	KPARSER_ARG_BOOL("overwritelast", cntr_conf.conf.overwrite_last, false,
			"Set if counter value to be overwritten upon max "
			"value overflow"),
	KPARSER_ARG_BOOL("erroronexceeded", cntr_conf.conf.error_on_exceeded,
			 true,
			"Unset if does not want to return an error "
			"upon counter max value overflow"),
};

static const struct kparser_arg_set md_types[] = {
	{
		.set_value_str = "hdrdata",
		.set_value_enum = KPARSER_METADATA_HDRDATA,
	},
	{
		.set_value_str = "hdrlen",
		.set_value_enum = KPARSER_METADATA_HDRLEN,
	},
	{
		.set_value_str = "constant_byte",
		.set_value_enum = KPARSER_METADATA_CONSTANT_BYTE,
	},
	{
		.set_value_str = "constant_halfword",
		.set_value_enum = KPARSER_METADATA_CONSTANT_HALFWORD,
	},
	{
		.set_value_str = "offset",
		.set_value_enum = KPARSER_METADATA_OFFSET,
	},
	{
		.set_value_str = "bit_offset",
		.set_value_enum = KPARSER_METADATA_BIT_OFFSET,
	},
	{
		.set_value_str = "numencaps",
		.set_value_enum = KPARSER_METADATA_NUMENCAPS,
	},
	{
		.set_value_str = "numnodes",
		.set_value_enum = KPARSER_METADATA_NUMNODES,
	},
	{
		.set_value_str = "timestamp",
		.set_value_enum = KPARSER_METADATA_TIMESTAMP,
	},
	{
		.set_value_str = "return_code",
		.set_value_enum = KPARSER_METADATA_RETURN_CODE,
	},
	{
		.set_value_str = "counter_mode",
		.set_value_enum = KPARSER_METADATA_COUNTER,
	},
	{
		.set_value_str = "noop",
		.set_value_enum = KPARSER_METADATA_NOOP,
	},
};

static const struct kparser_arg_set counter_op_types[] = {
	{
		.set_value_str = "noop",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_NOOP,
	},
	{
		.set_value_str = "incr",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_INCR,
	},
	{
		.set_value_str = "reset",
		.set_value_enum = KPARSER_METADATA_COUNTEROP_RST,
	},
};

static const struct kparser_arg_key_val_token md_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				md_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = ARRAY_SIZE(md_types),
		.value_set = md_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_METADATA_HDRDATA,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.type),
		.help_msg = "metadata type",
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "counterop",
		.value_set_len = sizeof(counter_op_types) /
			sizeof(counter_op_types[0]),
		.value_set = counter_op_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_METADATA_COUNTEROP_NOOP,
		.w_offset = offsetof(struct kparser_conf_cmd, md_conf.cntr_op),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				md_conf.cntr_op),
		.help_msg = "associated counter operation type",
	},
	KPARSER_ARG_BOOL("isframe", md_conf.frame, false,
			"Set if frame of the user metadata to be used to store, "
			"else metametadata will be used to store"),
	KPARSER_ARG_BOOL("isendianneeded", md_conf.e_bit, false,
			"Set if host byte order conversion is needed before "
			"writing to user data"),
	KPARSER_ARG_U(8, "counterid", md_conf.cntr, 0, 0xff, 0,
			"associated counter id"),
	KPARSER_ARG_U(8, "counterdata", md_conf.cntr_data, 0, 0xff, 0,
			"associated counter data"),
	KPARSER_ARG_U(8, "constantvalue", md_conf.constant_value, 0, 0xff, 0,
			"associated constant value"),
	KPARSER_ARG_U(64, "hdr-src-off", md_conf.soff, 0, 0xffffffff, 0,
			"start offset"),
	KPARSER_ARG_U(64, "md-off", md_conf.doff, 0, 0xffffffff, 0,
			"destination metadata/metametadata offset", NULL, NULL),
	KPARSER_ARG_U(64, "length", md_conf.len, 0, 0xffffffff, 2,
			"length in bytes"),
	KPARSER_ARG_U(64, "addoff", md_conf.add_off,
			KPARSER_METADATA_OFFSET_MIN,
			KPARSER_METADATA_OFFSET_MAX, 0,
			"add any additional constant offset value if needed",
			"soff"),
	KPARSER_ARG_HKEY("counteridx", "counteridx-id",
			md_conf.counterkey,
			"associated counter indexed object's key"),
};

static const struct kparser_arg_key_val_token mdl_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				mdl_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd, mdl_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				mdl_conf.key.id),
	},
	[2] {
		.type = KPARSER_ARG_VAL_ARRAY,
		.elem_type = KPARSER_ARG_VAL_U16,
		.default_template_token = &hkey_id,
		.elem_counter = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys_count),
		.elem_size = sizeof(struct kparser_hkey),
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys),
		.w_len = sizeof(((struct kparser_hkey *) NULL)->id),
		.key_name = "md.rule-id",
		.help_msg = "associated metadata object's id",
	},
	[3] {
		.type = KPARSER_ARG_VAL_ARRAY,
		.elem_type = KPARSER_ARG_VAL_STR,
		.default_template_token = &hkey_name,
		.elem_counter = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys_count),
		.elem_size = sizeof(struct kparser_hkey),
		.w_offset = offsetof(struct kparser_conf_cmd,
				mdl_conf.metadata_keys),
		.w_len = sizeof(((struct kparser_hkey *) NULL)->name),
		.key_name = "md.rule",
		.offset_adjust = sizeof(((struct kparser_hkey *) NULL)->id),
		.help_msg = "associated metadata object's name",
	},
};

static const struct kparser_arg_set node_types[] = {
	{
		.set_value_str = "PLAIN",
		.set_value_enum = KPARSER_NODE_TYPE_PLAIN,
	},
	{
		.set_value_str = "TLV",
		.set_value_enum = KPARSER_NODE_TYPE_TLVS,
	},
	{
		.set_value_str = "FLAGFIELDS",
		.set_value_enum = KPARSER_NODE_TYPE_FLAG_FIELDS,
	},
};

static const struct kparser_arg_set disp_limit_types[] = {
	{
		.set_value_str = "LOOP_DISP_STOP_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_NODE_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_NODE_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_SUB_NODE_OKAY",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_SUB_NODE_OKAY,
	},
	{
		.set_value_str = "LOOP_DISP_STOP_FAIL",
		.set_value_enum = KPARSER_LOOP_DISP_STOP_FAIL,
	},

};

#define PLAIN_NODE node_conf.plain_parse_node
#define TLVS_NODE node_conf.tlvs_parse_node
#define FLAGS_NODE node_conf.flag_fields_parse_node

static const struct kparser_arg_key_val_token parse_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.key.id),
	},
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "type",
		.value_set_len = ARRAY_SIZE(node_types),
		.value_set = node_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_NODE_TYPE_PLAIN,
		.w_offset = offsetof(struct kparser_conf_cmd, node_conf.type),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				node_conf.type),
		.help_msg = "parse node type, default is `plain`, or FLAGs/TLVs "
			"depending upon associated keys are configured",
	},
	KPARSER_ARG_S(32, "unknownret", PLAIN_NODE.unknown_ret,
			0, 0xffffffff, -12,
			"Code to return for a miss on the protocol table and "
			"the wildcard node is not set"),
	KPARSER_ARG_HKEY("md.ruleset", "md.ruleset-id",
			PLAIN_NODE.metadata_table_key,
			"Table of parameterized metadata operations"),

	// params for plain parse node
	KPARSER_ARG_BOOL("overlay", PLAIN_NODE.proto_node.overlay, false,
			"Set to indicates this is an overlay parsing"),
	KPARSER_ARG_U(64, "min-hdr-length", PLAIN_NODE.proto_node.min_len,
			0, 0xffff, 0, "Minimum length of the protocol header"),

#define HDR_LEN_FIELD_OFF_KEY "hdr.len.field-off"
	KPARSER_ARG_U(16, HDR_LEN_FIELD_OFF_KEY,
			PLAIN_NODE.proto_node.ops.pflen.src_off,
			0, 0xffff, 0,
			"relative start offset of this protocol header after "
			"the previous header ends"),

#define HDR_LEN_FIELD_LEN_KEY "hdr.len.field-len"
	KPARSER_ARG_U(8, HDR_LEN_FIELD_LEN_KEY,
			PLAIN_NODE.proto_node.ops.pflen.size,
			0, 4, 0, "this protocol header's length field's "
			"size in bytes"),
	KPARSER_ARG_BOOL("hdr.len.endian",
			PLAIN_NODE.proto_node.ops.pflen.endian, false,
			"Set this field if host byte order conversion is needed "
			"to calculate the header length"),

#define HDR_LEN_MASK_KEY "hdr.len.mask"
	KPARSER_ARG_U_HEX(32, HDR_LEN_MASK_KEY,
			PLAIN_NODE.proto_node.ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the header length value"),

#define HDR_LEN_RSHIFT_KEY "hdr.len.rightshift"
	KPARSER_ARG_U(8, HDR_LEN_RSHIFT_KEY,
			PLAIN_NODE.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract "
			"the header length value"),
	KPARSER_ARG_U(8, "hdr.len.multiplier",
			PLAIN_NODE.proto_node.ops.pflen.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final "
			"header length in bytes"),
#define HDR_LEN_ADDVAL_KEY "hdr.len.addvalue"
	KPARSER_ARG_U(8, HDR_LEN_ADDVAL_KEY,
			PLAIN_NODE.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "constant value to be added with extracted "
			"header length to calculate final length"),

	// paramdds for plain parse node ends
	KPARSER_ARG_HKEY("nxt.table", "nxt.table-id",
			PLAIN_NODE.proto_table_key,
			"associated protocol table's name or id"),
	KPARSER_ARG_HKEY("nxt.wildcardparsenode", "nxt.wildcardparsenode-id",
			PLAIN_NODE.wildcard_parse_node_key,
			"Node use for a miss on next protocol lookup"),
	// paramdds for plain parse node
	KPARSER_ARG_BOOL("nxt.encap", PLAIN_NODE.proto_node.encap, false,
			"Set to indicate next protocol after this will start "
			"in a separate encapsulation layer"),

	KPARSER_ARG_U(16, "nxt.field-off",
			PLAIN_NODE.proto_node.ops.pfnext_proto.src_off,
			0, 0xffff, 0, "relative offset to identify the start "
			"of the next protocol number identifier"),
	KPARSER_ARG_U(8, "nxt.field-len",
			PLAIN_NODE.proto_node.ops.pfnext_proto.size,
			0, 0xff, 0,
			"size of the next protocol identifier field"),
	KPARSER_ARG_U_HEX(16, "nxt.mask",
			PLAIN_NODE.proto_node.ops.pfnext_proto.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"mask to extract the next protocol identifier"),
	KPARSER_ARG_U(8, "nxt.rightshift",
			PLAIN_NODE.proto_node.ops.pfnext_proto.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract "
			"the next protocol id field"),

	KPARSER_ARG_HKEY("condexprstable", "condexprstable-id",
			PLAIN_NODE.proto_node.ops.cond_exprs_table,
			"table of conditional expressions table"),

	// params for tlvs parse node
	KPARSER_ARG_U(64, "tlvs.startoff.constantoff",
			TLVS_NODE.proto_node.start_offset,
			0, 0xffffffff, 0, "When there TLVs start relative the "
			"enapsulating protocol"),
	KPARSER_ARG_U(16, "tlvs.startoff.dynamicoff.field-off",
			TLVS_NODE.proto_node.ops.pfstart_offset.src_off,
			0, 0xffff, 0,
			"relative start offset of this tlv header after "
			"the previous header ends"),
	KPARSER_ARG_U(8, "tlvs.startoff.dynamicoff.field-len",
			TLVS_NODE.proto_node.ops.pfstart_offset.size,
			0, 0xff, 0, "this tlv header's length field's "
			"size in bytes"),
	KPARSER_ARG_BOOL("tlvs.startoff.dynamicoff.endian",
			TLVS_NODE.proto_node.ops.pfstart_offset.endian, false,
			"Set this field if host byte order conversion is "
			"needed to calculate the header length"),
	KPARSER_ARG_U_HEX(32, "tlvs.startoff.dynamicoff.mask",
			TLVS_NODE.proto_node.ops.pfstart_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the header length value", NULL, NULL),
	KPARSER_ARG_U(8, "tlvs.startoff.dynamicoff.rightshift",
			TLVS_NODE.proto_node.ops.pfstart_offset.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract "
			"this tlv header length value"),
	KPARSER_ARG_U(8, "tlvs.startoff.dynamicoff.multiplier",
			TLVS_NODE.proto_node.ops.pfstart_offset.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final "
			"header length in bytes"),
	KPARSER_ARG_U(8, "tlvs.startoff.dynamicoff.addvalue",
			TLVS_NODE.proto_node.ops.pfstart_offset.add_value,
			0, 0xff, 0, "constant value to be added with extracted "
			"header length to calculate final length"),

	KPARSER_ARG_U(16, "tlvs.len.field-off",
			TLVS_NODE.proto_node.ops.pflen.src_off,
			0, 0xffff, 1,
			"relative start offset of this tlv header's len field"),
	KPARSER_ARG_U(8, "tlvs.len.field-len",
			TLVS_NODE.proto_node.ops.pflen.size,
			0, 0xff, 1, "this tlv length field's size in bytes"),
	KPARSER_ARG_BOOL("tlvs.len.endian",
			TLVS_NODE.proto_node.ops.pflen.endian, false,
			"Set this field if host byte order conversion is "
			"needed to calculate the tlv length"),
	KPARSER_ARG_U_HEX(32, "tlvs.len.mask",
			TLVS_NODE.proto_node.ops.pflen.mask,
			0, KPARSER_DEFAULT_U32_MASK, 0xff,
			"mask to extract the tlv length value"),
	KPARSER_ARG_U(8, "tlvs.len.rightshift",
			TLVS_NODE.proto_node.ops.pflen.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract "
			"this tlv length field's value "),
	KPARSER_ARG_U(8, "tlvs.len.multiplier",
			TLVS_NODE.proto_node.ops.pflen.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final "
			"tlv length in bytes"),
	KPARSER_ARG_U(8, "tlvs.hdr.len.addvalue",
			TLVS_NODE.proto_node.ops.pflen.add_value,
			0, 0xff, 0, "constant value to be added with extracted "
			"tlv length to calculate final length "),

	KPARSER_ARG_U(16, "tlvs.type.field-off",
			TLVS_NODE.proto_node.ops.pftype.src_off, 0, 0xffff, 0,
			"relative offset to identify the start of the next "
			"tlv type field"),
	KPARSER_ARG_U(8, "tlvs.type.field-len",
			TLVS_NODE.proto_node.ops.pftype.size, 0, 0xff, 1,
			"size of the next tlv type field"),
	KPARSER_ARG_U_HEX(16, "tlvs.type.mask",
			TLVS_NODE.proto_node.ops.pftype.mask, 0,
			KPARSER_DEFAULT_U16_MASK, 0xff,
			"mask to extract the next tlv type"),
	KPARSER_ARG_U(8, "tlvs.type.rightshift",
			TLVS_NODE.proto_node.ops.pftype.right_shift, 0, 0xff, 0,
			"number of bits to shift right to extract the next tlv "
			"type field"),
	KPARSER_ARG_U(8, "tlvs.pad1",
			TLVS_NODE.proto_node.pad1_val,
			0, 0xff, 0, "Type value indicating one byte of TLV "
			"padding"),
	KPARSER_ARG_U(8, "tlvs.padn", TLVS_NODE.proto_node.padn_val, 0,
			0xff, 0, "Type value indicating n byte of TLV"),
	KPARSER_ARG_U(8, "tlvs.eol", TLVS_NODE.proto_node.eol_val, 0,
			0xff, 0, "Type value that indicates end of TLV list"),
	KPARSER_ARG_BOOL("tlvs.stndfmt",
			TLVS_NODE.proto_node.tlvsstdfmt, true,
			"Standard TLV format is applicable"),
	KPARSER_ARG_U(64, "tlvs.min-hdr-length", TLVS_NODE.proto_node.min_len,
			0, 0xffffffff, 2, "Minimal length of a TLV option"),

	KPARSER_ARG_S(32, "tlvs.unknowntyperet",
			TLVS_NODE.unknown_tlv_type_ret,
			0, 0xffffffff, -12, "kParser error code to return on a "
			"TLV table lookup miss and tlv_wildcard_node is NULL"),
	KPARSER_ARG_HKEY("tlvs.table", "tlvs.table-id",
			TLVS_NODE.tlv_proto_table_key,
			"Lookup TLV table using TLV type"),
	KPARSER_ARG_HKEY("tlvs.wildcardnode", "tlvs.wildcardnode-id",
			TLVS_NODE.tlv_wildcard_node_key, "Node to use on a TLV "
			"type lookup miss"),

	KPARSER_ARG_U(16, "tlvs.maxloop", TLVS_NODE.config.max_loop,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_LOOP,
			"Maximum number of TLVs to process"),
	KPARSER_ARG_U(16, "tlvs.maxnon", TLVS_NODE.config.max_non,
			0, 0xffff, KPARSER_DEFAULT_TLV_MAX_NON_PADDING,
			"Maximum number of non-padding TLVs to process"),
	KPARSER_ARG_U(8, "tlvs.maxplen", TLVS_NODE.config.max_plen,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_BYTES,
			"Maximum consecutive padding bytes"),
	KPARSER_ARG_U(8, "tlvs.maxcpad", TLVS_NODE.config.max_c_pad,
			0, 0xff, KPARSER_DEFAULT_TLV_MAX_CONSEC_PAD_OPTS,
			"Maximum number of consecutive padding options"),
	{
		.type = KPARSER_ARG_VAL_SET,
		.key_name = "tlvs.displimitexceed",
		.value_set_len = sizeof(disp_limit_types) /
			sizeof(disp_limit_types[0]),
		.value_set = disp_limit_types,
		.str_arg_len_max = KPARSER_SET_VAL_LEN_MAX,
		.def_value_enum = KPARSER_DEFAULT_TLV_DISP_LIMIT_EXCEED,
		.w_offset = offsetof(struct kparser_conf_cmd,
				TLVS_NODE.config.disp_limit_exceed),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				TLVS_NODE.config.disp_limit_exceed),
		.help_msg = "Disposition when a TLV parsing limit is exceeded",
	},
	KPARSER_ARG_BOOL("tlvs.exceedloopcntiserr",
			TLVS_NODE.config.exceed_loop_cnt_is_err,
			KPARSER_DEFAULT_TLV_EXCEED_LOOP_CNT_ERR,
			"Set if exceeding maximum number of TLVS is an error"),

	// params for flag fields parse node
	KPARSER_ARG_U(16, "flags.off",
			FLAGS_NODE.proto_node.ops.pfget_flags.src_off,
			0, 0xffff, 0, "relative start offset of the flag "
			"in the current protocol header"),
	KPARSER_ARG_U_HEX(32, "flags.mask",
			FLAGS_NODE.proto_node.ops.pfget_flags.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract flag from the given offset in "
			"the current protocol header"),
	KPARSER_ARG_U(8, "flags.len",
			FLAGS_NODE.proto_node.ops.pfget_flags.size,
			0, 0xff, 0, "length of the flag"),

	KPARSER_ARG_U(16, "flags.fieldhdrlen",
			FLAGS_NODE.proto_node.ops.hdr_length,
			0, 0xffff, 0, "header length of the flag field's "
			"protocol header"),
	KPARSER_ARG_U(16, "flags.fieldoff",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.src_off,
			0, 0xffff, 0, "relative start offset in the flag field "
			"to extract from the current protocol header"),
	KPARSER_ARG_U(8, "flags.fieldlen",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.size,
			0, 0xff, 0, "length of the flag field in bytes"),
	KPARSER_ARG_BOOL("flags.fieldendian",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.endian,
			false, "Set if host byte order conversion needed while "
			"parsing the flag field"),
	KPARSER_ARG_U_HEX(32, "flags.fieldmask",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.mask,
			0, KPARSER_DEFAULT_U32_MASK, KPARSER_DEFAULT_U32_MASK,
			"mask to extract the flag field value"),
	KPARSER_ARG_U(8, "flags.fieldrightshift",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.right_shift,
			0, 0xff, 0, "number of bits to shift right to extract "
			"the flag field"),
	KPARSER_ARG_U(8, "flags.fieldmultiplier",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.multiplier,
			0, 0xff, 1, "constant multiplier to calculate final "
			"flag field"),
	KPARSER_ARG_U(8, "flags.fieldaddvalue",
			FLAGS_NODE.proto_node.ops.pfstart_fields_offset.add_value,
			0, 0xff, 0, "constant value to be added with extracted "
			"flag field"),

	KPARSER_ARG_HKEY("flags.fields.table", "flags.fields.table-id",
			FLAGS_NODE.proto_node.flag_fields_table_hkey,
			"table of flag fields"),
	KPARSER_ARG_HKEY("flags.fieldsprototable",
			"flags.fieldsprototable-id",
			FLAGS_NODE.flag_fields_proto_table_key,
			"flag fields protocol table"),
};

static const struct kparser_arg_key_val_token proto_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_U_HEX(32, "key", table_conf.optional_value1,
			0, 0xffffffff, 0,
			"<TODO>"),
	KPARSER_ARG_BOOL("encap", table_conf.optional_value2, false,
			"Set if this protocol is starting of a new "
			"encapsulation layer"),
	KPARSER_ARG_H_K_N("table", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table-id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("node", "node-id", table_conf.elem_key,
			NULL, NULL,
			"<TODO>"),
};

static const struct kparser_arg_key_val_token tlv_parse_node_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				tlv_node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				tlv_node_conf.key.id),
	},
	KPARSER_ARG_U(64, "min-hdr-length", tlv_node_conf.node_proto.min_len,
			0, 0xffffffff, 0,
			"<TODO>"),
	KPARSER_ARG_U(64, "maxlen", tlv_node_conf.node_proto.max_len, 0,
			0xffffffff, 0xffffffff,
			"<TODO>"),
	KPARSER_ARG_BOOL("is_padding", tlv_node_conf.node_proto.is_padding,
			false,
			"<TODO>"),
	KPARSER_ARG_U(16, "overlay.type.field.off",
			tlv_node_conf.node_proto.ops.pfoverlay_type.src_off,
			0, 0xffff, 0,
			"<TODO>"),
	KPARSER_ARG_U(8, "overlay.type.field.len",
			tlv_node_conf.node_proto.ops.pfoverlay_type.size,
			0, 0xff, 0,
			"<TODO>"),
	KPARSER_ARG_U_HEX(16, "overlay.type.mask",
			tlv_node_conf.node_proto.ops.pfoverlay_type.mask,
			0, KPARSER_DEFAULT_U16_MASK, KPARSER_DEFAULT_U16_MASK,
			"<TODO>"),
	KPARSER_ARG_U(8, "overlay.type.field.rightshift",
			tlv_node_conf.node_proto.ops.
			pfoverlay_type.right_shift,
			0, 0xff, 0,
			"<TODO>"),
	KPARSER_ARG_HKEY("condexprstable", "condexprstable-id",
			tlv_node_conf.node_proto.ops.cond_exprs_table,
			"<TODO>"),

	KPARSER_ARG_S(32, "unknown_ret", tlv_node_conf.unknown_ret,
			0, 0xffffffff, -12,
			"<TODO>"),
	KPARSER_ARG_HKEY("overlay_proto_tlvs_table_key",
			"overlay_proto_tlvs_table_key-id",
			tlv_node_conf.overlay_proto_tlvs_table_key,
			"<TODO>"),
	KPARSER_ARG_HKEY("overlay_wildcard_parse_node",
			"overlay_wildcard_parse_node-id",
			tlv_node_conf.overlay_wildcard_parse_node_key,
			"<TODO>"),
	KPARSER_ARG_HKEY("md.ruleset", "md.ruleset-id",
			tlv_node_conf.metadata_table_key,
			"<TODO>"),
};

static const struct kparser_arg_key_val_token tlv_proto_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_U(32, "tlvtype", table_conf.optional_value1,
			0, 0xffffffff, 0,
			"<TODO>"),
	KPARSER_ARG_H_K_N("table", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table-id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_HKEY("tlvnode", "tlvnode-id", table_conf.elem_key,
			"<TODO>"),
};

static const struct kparser_arg_key_val_token flag_field_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_conf.key.id),
	},
	KPARSER_ARG_U(32, "flag", flag_field_conf.conf.flag,
			0, 0xffffffff, 0,
			"flag value expected in packet field"),
	KPARSER_ARG_U_HEX(32, "mask", flag_field_conf.conf.mask,
			0, KPARSER_DEFAULT_U32_MASK, 0,
			"mask to extract the packet data field"),
	KPARSER_ARG_U(64, "size", flag_field_conf.conf.size, 0,
			0xffffffff, 0,
			"flag field's size in bytes"),
};

static const struct kparser_arg_key_val_token flag_field_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_N("table", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "hybrid key name for the "
			"associated flag field table"),
	KPARSER_ARG_H_K_I("table-id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "hybrid id for the associated "
			"flag field table"),
	KPARSER_ARG_U(32, "key", table_conf.optional_value1,
			0, 0xffffffff, 0,
			"index as key of this flag field"),
	KPARSER_ARG_HKEY("flag", "flag-id",
			table_conf.elem_key,
			"associated flag entry's name or id"),
};

static const struct kparser_arg_key_val_token
flag_field_node_parse_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_node_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_node_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				flag_field_node_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				flag_field_node_conf.key.id),
	},

	KPARSER_ARG_HKEY("md.ruleset", "md.ruleset-id",
			flag_field_node_conf.metadata_table_key,
			"Table of parameterized metadata operations"),
	KPARSER_ARG_HKEY("condexprstable", "condexprstable-id",
			flag_field_node_conf.ops.cond_exprs_table_key,
			"name or id of table of conditional expressions table"),
};

static const struct kparser_arg_key_val_token
flag_field_proto_table_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.w_offset = offsetof(struct kparser_conf_cmd,
				table_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				table_conf.key.id),
	},
	KPARSER_ARG_H_K_N("table", table_conf.key.name,
			KPARSER_DEF_NAME_PREFIX, "<TODO>"),
	KPARSER_ARG_H_K_I("table-id", table_conf.key.id,
			KPARSER_USER_ID_MIN, KPARSER_USER_ID_MAX,
			KPARSER_INVALID_ID, "<TODO>"),
	KPARSER_ARG_U(32, "flagid", table_conf.optional_value1,
			0, 0xffffffff, 0,
			"associated flag value"),
	KPARSER_ARG_HKEY("flagsnode", "flagsnode-id",
			table_conf.elem_key,
			"<TODO>"),
};

static const struct kparser_arg_key_val_token parser_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				parser_conf.key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				parser_conf.key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				parser_conf.key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				parser_conf.key.id),
	},
	KPARSER_ARG_U(16, "flags", parser_conf.config.flags, 0, 0xffff,
			0,
			"<TODO>"),
	KPARSER_ARG_U(16, "maxnodes", parser_conf.config.max_nodes,
			0, 0xffff, KPARSER_MAX_NODES,
			"<TODO>"),
	KPARSER_ARG_U(16, "maxencaps", parser_conf.config.max_encaps,
			0, 0xffff, KPARSER_MAX_ENCAPS,
			"<TODO>"),
	KPARSER_ARG_U(16, "maxframes", parser_conf.config.max_frames,
			0, 0xffff, KPARSER_MAX_FRAMES,
			"<TODO>"),
	KPARSER_ARG_U(64, "metametasize", parser_conf.config.metameta_size, 0,
			0xffffffff, 0,
			"<TODO>"),
	KPARSER_ARG_U(64, "framesize", parser_conf.config.frame_size, 0,
			0xffffffff, 0,
			"<TODO>"),
	KPARSER_ARG_HKEY("rootnode", "rootnode-id",
			parser_conf.root_node_key,
			"<TODO>"),
	KPARSER_ARG_HKEY("oknode", "oknode-id",
			parser_conf.ok_node_key,
			"<TODO>"),
	KPARSER_ARG_HKEY("failnode", "failnode-id",
			parser_conf.fail_node_key,
			"<TODO>"),
	KPARSER_ARG_HKEY("atencapnode", "atencapnode-id",
			parser_conf.atencap_node_key,
			"<TODO>"),
};

static const struct kparser_arg_key_val_token parser_lock_unlock_key_vals[] = {
	[0] {
		.default_template_token = &hkey_name,
		.semi_optional = true,
		.other_mandatory_idx = 1,
		.w_offset = offsetof(struct kparser_conf_cmd,
				obj_key.name),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				obj_key.name),
	},
	[1] {
		.default_template_token = &hkey_id,
		.semi_optional = true,
		.other_mandatory_idx = 0,
		.w_offset = offsetof(struct kparser_conf_cmd,
				obj_key.id),
		.w_len = sizeof(((struct kparser_conf_cmd *) NULL)->
				obj_key.id),
	},
};

#define DEFINE_NAMESPACE_MEMBERS(id, namestr, token_name, desc,		\
		pre, post, keynamealiases)				\
	.name_space_id = id,						\
	.name = namestr,						\
	.alias = #id,							\
	.arg_tokens_count = ARRAY_SIZE(token_name),			\
	.arg_tokens = token_name,					\
	.create_attr_id = KPARSER_ATTR_CREATE_##id,			\
	.update_attr_id = KPARSER_ATTR_UPDATE_##id,			\
	.read_attr_id = KPARSER_ATTR_READ_##id,				\
	.delete_attr_id = KPARSER_ATTR_DELETE_##id,			\
	.rsp_attr_id = KPARSER_ATTR_RSP_##id,				\
	.description = desc,						\
	.custom_do_cli = pre,						\
	.post_process_handler = post,					\
	.aliases = keynamealiases

static inline int key_to_index(const char *key,
		const struct kparser_global_namespaces *ns)
{
	const char *key_name;
	int i = -1;

	for (i = 0; i < ns->arg_tokens_count; i++) {
		key_name = ns->arg_tokens[i].key_name;
		if (!key_name && ns->arg_tokens[i].default_template_token)
			key_name = ns->arg_tokens[i].default_template_token->
				key_name;
		if (!strcmp(key_name, key))
			break;
	}

	return i;
}

#define K2IDX(key, ret)							\
do {									\
	ret = key_to_index(key, ns);					\
	if (ret == -1) {						\
		fprintf(stderr, "{%s:%d} Invalid key:%s\n",		\
				__func__, __LINE__, key);		\
		return -EINVAL;						\
	}								\
} while (0)


static inline int cond_exprs_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_condexpr *conf = &cmd_arg->cond_conf;
	const struct kparser_global_namespaces *ns = namespace;
	int kidx;

	K2IDX("mask", kidx);
	if (!kparsertestbit(ns_keys_bvs, kidx)) {
		// convert mask to host byte order if needed
		if (conf->config.mask > 0xff && conf->config.mask <= 0xffff)
			conf->config.mask = ntohs(conf->config.mask);
		else if (conf->config.mask > 0xffff)
			conf->config.mask = ntohl(conf->config.mask);
	}

	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS,
			"condexprs",
			cond_exprs_vals,
			"conditional expressions object",
			NULL, cond_exprs_post_handler, NULL),
};

static inline int cond_table_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLE,
			"condexprslist",
			cond_exprs_table_key_vals,
			"conditional expressions table object(s)",
			NULL, cond_table_post_handler, NULL),
};

static inline int cond_tables_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_cond_exprs_tables = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_CONDEXPRS_TABLES,
			"condexprstable",
			cond_exprs_tables_key_vals,
			"table of conditional expressions table object(s)",
			NULL, cond_tables_post_handler, NULL),
};

static inline int counter_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_cntr *conf = &cmd_arg->cntr_conf;

	conf->conf.valid_entry = true;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_counter = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_COUNTER,
			"counter",
			counter_key_vals,
			"counter object", NULL, counter_post_handler, NULL),
};

static const struct kparser_cmd_args_ns_aliases md_aliases = {
	.nsid = KPARSER_NS_METADATA,
	// 0th index is special for namespace name map
	.keyaliases[0] = {
		.keyname = "metadata-rule",
		.aliases[0] = "md-rule"
	},
	.keyaliases[1] = {
		.keyname = "md-off",
		.aliases[0] = "doff"
	},
};

static const struct kparser_global_namespaces kparser_arg_namespace_metadata = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METADATA, "metadata-rule",
			md_key_vals,
			"metadata object", NULL, NULL, &md_aliases),
};

static const struct kparser_cmd_args_ns_aliases mdl_aliases = {
	.nsid = KPARSER_NS_METALIST,
	// 0th index is special for namespace name map
	.keyaliases[0] = {
		.keyname = "metadata-ruleset",
		.aliases[0] = "metalist"
	},
	.keyaliases[1] = {
		.keyname = "md.rule",
		.aliases[0] = "md-rule",
		.aliases[1] = "metadata"
	},
// nxt.field-off
// nxt.field-len
};

static const struct kparser_global_namespaces kparser_arg_namespace_metalist = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_METALIST,
			"metadata-ruleset", mdl_key_vals,
			"list of metadata object(s)", NULL, NULL, &mdl_aliases),
};

static inline int node_do_cli_metalist(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid, char *autogenname);

static inline int node_do_cli_table(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid, char *autogenname);

static inline int node_do_cli(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid)
{
	const char *newargv[KPARSER_CONFIG_MAX_KEYS] = {};
	char autogenname[KPARSER_MAX_NAME] = {};
	bool undesired_arg_enforce = true;
	int currargidx, i = 0, rc;

	for (i = 0; i < argc; i++)
		newargv[i] = strdupa(argv[i]);

	if (op != op_create)
		goto skip_inline_do_clis;

	rc = node_do_cli_metalist(nsid, op, argc, argidx,
			(const char **) &newargv,
			hybrid_token, tbn, tbid, autogenname);
	if (rc != 0) {
		fprintf(stderr, "node_do_cli_metalist() failed, rc:%d\n", rc);
		return rc;
	}

	if (strlen(autogenname) != 0) {
		undesired_arg_enforce = false;
		newargv[argc++] = strdupa("md.ruleset");
		newargv[argc++] = strdupa(autogenname);
	}

	autogenname[0] = '\0';
	rc = node_do_cli_table(nsid, op, argc, argidx,
			(const char **) &newargv,
			hybrid_token, tbn, tbid, autogenname);
	if (rc != 0) {
		fprintf(stderr, "node_do_cli_table() failed, rc:%d\n", rc);
		return rc;
	}
	if (strlen(autogenname) != 0) {
		undesired_arg_enforce = false;
		newargv[argc++] = strdupa("nxt.table");
		newargv[argc++] = strdupa(autogenname);
	}

	currargidx = check_key(argc, newargv, "flagstable");
	if (currargidx != -1) {
		undesired_arg_enforce = false;
		newargv[currargidx] = strdupa("flagsfieldstable");
		snprintf(autogenname, sizeof(autogenname), "flagstable.%s",
				newargv[currargidx + 1]);
		newargv[argc++] = strdupa("flagsfieldsprototable");
		newargv[argc++] = strdupa(autogenname);

		dump_inline_expanded_cli_cmd(argc, newargv);
	}

skip_inline_do_clis:
	return do_cli(nsid, op, argc, argidx, (const char **) &newargv,
				hybrid_token, true, undesired_arg_enforce);
}

static inline int node_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_node *conf = &cmd_arg->node_conf;
	bool tlvsset = false, flagsset = false, isset = false;
	const struct kparser_global_namespaces *ns = namespace;
	int i, kidx, kidxstart, kidxend, cnt;
	bool rightshiftneeded = false;

	K2IDX("type", kidx);
	if (!kparsertestbit(ns_keys_bvs, kidx)) {
		if (conf->type == KPARSER_NODE_TYPE_TLVS)
			tlvsset = true;
		else if (conf->type == KPARSER_NODE_TYPE_FLAG_FIELDS)
			flagsset = true;
	}

	K2IDX(HDR_LEN_FIELD_OFF_KEY, kidxstart);
	K2IDX(HDR_LEN_ADDVAL_KEY, kidxend);
	for (i = kidxstart; i <= kidxend; i++)
		if (!kparsertestbit(ns_keys_bvs, i)) {
			conf->plain_parse_node.proto_node.ops.
				len_parameterized = true;
			break;
		}

	/* If HDR_LEN_MASK_KEY is set and HDR_LEN_FIELD_LEN_KEY is not set,
	 * auto calculate the HDR_LEN_FIELD_LEN_KEY from HDR_LEN_MASK_KEY value
	 */
	if (conf->plain_parse_node.proto_node.ops.len_parameterized) {
		K2IDX(HDR_LEN_FIELD_LEN_KEY, kidx);
		if (kparsertestbit(ns_keys_bvs, kidx)) {
			K2IDX(HDR_LEN_MASK_KEY, kidx);
			if (kparsertestbit(ns_keys_bvs, kidx)) {
				// config error
				fprintf(stderr, "Either specify key "
						"`%s` or key `%s`\n",
						HDR_LEN_FIELD_LEN_KEY,
						HDR_LEN_MASK_KEY);
				return -EINVAL;
			} else {
				/* calculate HDR_LEN_FIELD_LEN_KEY from
				 * HDR_LEN_MASK_KEY
				 * Max: 4 bytes
				 */
				if (conf->plain_parse_node.proto_node.ops.
						pflen.mask <= 0xff)
					conf->plain_parse_node.proto_node.ops.
						pflen.size = 1;
				else if (conf->plain_parse_node.proto_node.ops.
						pflen.mask > 0xff &&
					conf->plain_parse_node.proto_node.ops.
					pflen.mask <= 0xffff)
					conf->plain_parse_node.proto_node.ops.
						pflen.size = 2;
				else if (conf->plain_parse_node.proto_node.ops.
						pflen.mask > 0xffff &&
					conf->plain_parse_node.proto_node.ops.
					pflen.mask <= 0xffffff)
					conf->plain_parse_node.proto_node.ops.
						pflen.size = 3;
				else
					conf->plain_parse_node.proto_node.ops.
						pflen.size = 4;
				// mention this field is set automatically
				K2IDX(HDR_LEN_FIELD_LEN_KEY, kidx);
				kparserclearbit(ns_keys_bvs, kidx);
			}
		}
	}

	/* If HDR_LEN_FIELD_LEN_KEY is set and HDR_LEN_MASK_KEY is set and
	 * HDR_LEN_RSHIFT_KEY is not set, the try to auto calculate it.
	 */
	K2IDX(HDR_LEN_FIELD_LEN_KEY, kidx);
	if (!kparsertestbit(ns_keys_bvs, kidx)) {
		K2IDX(HDR_LEN_MASK_KEY, kidx);
		if (conf->plain_parse_node.proto_node.ops.pflen.size >
				sizeof(conf->plain_parse_node.proto_node.ops.
					pflen.mask)) {
			fprintf(stderr, "%s: %u bytes, it can not be "
				"more than capacity of %s: %lu bytes\n",
				HDR_LEN_FIELD_LEN_KEY,
				conf->plain_parse_node.proto_node.ops.
				pflen.size, HDR_LEN_MASK_KEY,
				sizeof(conf->plain_parse_node.proto_node.ops.
				pflen.mask));
			return -EINVAL;
		}
		cnt = count_consecutive_bits(
				&conf->plain_parse_node.proto_node.
				ops.pflen.mask,
				conf->plain_parse_node.proto_node.ops.
				pflen.size, &rightshiftneeded);

		if (!kparsertestbit(ns_keys_bvs, kidx)) {
			K2IDX("HDR_LEN_RSHIFT_KEY", kidx);
			if (kparsertestbit(ns_keys_bvs, kidx) &&
					rightshiftneeded) {
				conf->plain_parse_node.proto_node.ops.
					pflen.right_shift = cnt;
			}
		}
	}

	K2IDX("tlvhdrlenoff", kidxstart);
	K2IDX("tlvsexceedloopcntiserr", kidxend);
	for (i = kidxstart; i <= kidxend; i++)
		if (!kparsertestbit(ns_keys_bvs, i)) {
			if (flagsset) {
				fprintf(stderr, "tlvs options and flags options "
						"are mutually exclusive,"
						"TLVs key `%s` can not be used "
						"here\n",
						parse_node_key_vals[i].
						key_name);
				return -EINVAL;
			}
			tlvsset = true;
			conf->type = KPARSER_NODE_TYPE_TLVS;
			break;
		}

	K2IDX("flagsoff", kidxstart);
	K2IDX("flagfieldsprototable-id", kidxend);
	for (i = kidxstart; i <= kidxend; i++)
		if (!kparsertestbit(ns_keys_bvs, i)) {
			if (tlvsset) {
				fprintf(stderr, "tlvs options and flags options "
						"are mutually exclusive,"
						"FLAGs key `%s` can not be used "
						"here\n",
						parse_node_key_vals[i].
						key_name);
				return -EINVAL;
			}
			conf->type = KPARSER_NODE_TYPE_FLAG_FIELDS;
			flagsset = true;
			break;
		}

	if (tlvsset) {
		K2IDX("tlvslenoff", kidxstart);
		K2IDX("tlvshdrlenaddvalue", kidxend);
		for (i = kidxstart; i <= kidxend; i++) {
			// any member of TLVS_NODE.proto_node.ops.pflen is set
			if (!kparsertestbit(ns_keys_bvs, i)) {
				conf->tlvs_parse_node.proto_node.ops.
					len_parameterized = true;
				break;
			}
		}

		K2IDX("tlvsstndfmt", kidx);
		if (kparsertestbit(ns_keys_bvs, kidx) ||
				(!kparsertestbit(ns_keys_bvs, kidx) &&
				conf->tlvs_parse_node.proto_node.tlvsstdfmt))  {
			/* if "tlvsstndfmt"is not set or set to true and then
			 * set tlvsminlen 2, tlvstypelen 1, tlvslenoff 1, and
			 * tlvslenlen 1
			 */
			// default of tlvsminlen is 2, so do nothing here
			// default of tlvstypelen is 1, so do nothing here
			// default of tlvslenoff is 1, so do nothing here
			// default of tlvslenlen is 1, so do nothing here
			// if tlvs_parse_node.proto_node.ops.len_parameterized
			// is  not set, set here.
			if (!conf->tlvs_parse_node.proto_node.ops.
					len_parameterized) {
				conf->tlvs_parse_node.proto_node.ops.
					len_parameterized = true;
			}
		}

		/* if start_offset is set, set fixed_start_offset
		 * if ops.pfstart_offset is not set and start_offset is also not
		 * set, then try to set the min-hdr-length to start_offset and
		 * set fixed_start_offset. In this case, if min-hdr-length is
		 * also not set, then throw an error
		 */
		K2IDX("tlvs.startoff", kidx);
		if (!kparsertestbit(ns_keys_bvs, kidx)) {
			conf->tlvs_parse_node.proto_node.fixed_start_offset =
			true;
		}

		if (!conf->tlvs_parse_node.proto_node.fixed_start_offset) {
			K2IDX("tlvhdrlenoff", kidxstart);
			K2IDX("tlvhdrlenaddvalue", kidxend);
			for (i = kidxstart; i <= kidxend; i++) {
				if (!kparsertestbit(ns_keys_bvs, i)) {
					isset = true;
					break;
				}
			}
			if (!isset) {
				K2IDX("min-hdr-length", kidx);
				if (kparsertestbit(ns_keys_bvs, kidx)) {
					// but min-hdr-length is also not set
					fprintf(stderr,
						"if keys from `tlvhdrlenoff` "
						"to `tlvhdrlenaddvalue` are "
						"not set,then `min-hdr-length` "
						"must be set");
					return -EINVAL;
				}
				conf->tlvs_parse_node.proto_node.start_offset =
					conf->plain_parse_node.proto_node.
					min_len;
				conf->tlvs_parse_node.proto_node.
					fixed_start_offset = true;
			}
		}

		K2IDX("tlvspad1", kidx);
		if (!kparsertestbit(ns_keys_bvs, kidx))
			conf->tlvs_parse_node.proto_node.pad1_enable = true;

		K2IDX("tlvspadn", kidx);
		if (!kparsertestbit(ns_keys_bvs, kidx))
			conf->tlvs_parse_node.proto_node.padn_enable = true;

		K2IDX("tlvseol", kidx);
		if (!kparsertestbit(ns_keys_bvs, kidx))
			conf->tlvs_parse_node.proto_node.eol_enable = true;
	}

	if (flagsset) {
		K2IDX("flagsfieldoff", kidxstart);
		K2IDX("flagsfieldaddvalue", kidxend);
		for (i = kidxstart; i <= kidxend; i++) {
			// any member of pfstart_fields_offset is set
			if (!kparsertestbit(ns_keys_bvs, i)) {
				conf->flag_fields_parse_node.proto_node.ops.
					start_fields_offset_parameterized =
					true;
				break;
			}
		}

		K2IDX("flagsfieldhdrlen", kidx);
		if (kparsertestbit(ns_keys_bvs, kidx)) {
			// key flagsfieldhdrlen is not set
			if (!conf->flag_fields_parse_node.proto_node.
					ops.start_fields_offset_parameterized) {
				/* key flagsfieldhdrlen is not set
				 * and no member of pfstart_fields_offset is
				 * set. So set ops.hdr_length to min-hdr-length
				 * If min-hdr-length is not provided, then
				 * EINVAL
				 */
				K2IDX("min-hdr-length", kidx);
				if (kparsertestbit(ns_keys_bvs, kidx)) {
					// but min-hdr-length is also not set
					fprintf(stderr, "key `flagsfieldhdrlen` "
							"must be set in case "
							"key `min-hdr-length` "
						"is not set\n");
					return -EINVAL;
				}
				conf->flag_fields_parse_node.proto_node.ops.
					flag_fields_len = true;
				conf->flag_fields_parse_node.proto_node.ops.
					hdr_length = conf->plain_parse_node.
					proto_node.min_len;
			}
		} else  {
			/* if "flagsfieldhdrlen"is set
			 * Note: it overrides any config from
			 * pfstart_fields_offset
			 */
			conf->flag_fields_parse_node.proto_node.ops.
				flag_fields_len = true;
		}

		K2IDX("flagsoff", kidxstart);
		K2IDX("flagslen", kidxend);
		for (i = kidxstart; i <= kidxend; i++) {
			// any member of pfget_flags is set
			if (!kparsertestbit(ns_keys_bvs, i)) {
				conf->flag_fields_parse_node.proto_node.ops.
					get_flags_parameterized = true;
				break;
			}
		}
	}

	return 0;
}

static const struct kparser_cmd_args_ns_aliases node_aliases = {
	.nsid = KPARSER_NS_NODE_PARSE,
	// 0th index is special for namespace name map
	.keyaliases[0] = {
		.keyname = "node",
		.aliases[0] = "parse-node"
	},
	.keyaliases[1] = {
		.keyname = "min-hdr-length",
		.aliases[0] = "hdr.minlen",
	},
	.keyaliases[2] = {
		.keyname = "nxt.field-off",
		.aliases[0] = "nxt.offset",
	},
	.keyaliases[3] = {
		.keyname = "nxt.field-len",
		.aliases[0] = "nxt.length",
	},
	.keyaliases[4] = {
		.keyname = "hdr.len.field-off",
		.aliases[0] = "hdr.lenoff",
	},
	.keyaliases[5] = {
		.keyname = "hdr.len.field-len",
		.aliases[0] = "hdr.lenlen",
	},
	.keyaliases[6] = {
		.keyname = "hdr.len.mask",
		.aliases[0] = "hdr.lenmask",
	},
	.keyaliases[7] = {
		.keyname = "hdr.len.multiplier",
		.aliases[0] = "hdr.lenmultiplier",
	},
	.keyaliases[8] = {
		.keyname = "md.ruleset",
		.aliases[0] = "metalist",
	},
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_NODE_PARSE, "node",
			parse_node_key_vals,
			"plain parse node object",
			node_do_cli, node_post_handler, &node_aliases),
};

static inline int proto_table_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PROTO_TABLE, "table",
			proto_table_key_vals,
			"table of parse node object(s)",
			NULL, proto_table_post_handler, NULL),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_parse_node = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_NODE_PARSE, "tlvnode",
			tlv_parse_node_key_vals,
			"tlv (type-length-value) parse node object",
			NULL, NULL, NULL),
};

static inline int tlv_table_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_tlv_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_TLV_PROTO_TABLE, "tlvtable",
			tlv_proto_table_key_vals,
			"table of tlv parse node object(s)",
			NULL, tlv_table_post_handler, NULL),
};

static inline int flag_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_flag_field *conf = &cmd_arg->flag_field_conf;

	conf->conf.endian = true;

	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD, "flags",
			flag_field_key_vals,
			"flag object", NULL, flag_post_handler, NULL),
};

static inline int flagfields_do_cli(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid);

static inline int flagfields_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_TABLE,
			"flagfields",
			flag_field_table_key_vals,
			"table of flag object(s)",
			flagfields_do_cli, flagfields_post_handler, NULL),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_node_parse = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_NODE_PARSE,
			"flagsnode",
			flag_field_node_parse_key_vals,
			"flag field parse node object", NULL, NULL, NULL),
};

static inline int flags_proto_table_post_handler(const void *namespace,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		__u32 *ns_keys_bvs, struct kparser_conf_cmd *cmd_arg)
{
	struct kparser_conf_table *conf = &cmd_arg->table_conf;

	conf->add_entry = hybrid_token ? true : false;
	return 0;
}

static const struct kparser_global_namespaces
kparser_arg_namespace_flag_field_proto_table = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_FLAG_FIELD_PROTO_TABLE,
			"flagstable",
			flag_field_proto_table_key_vals,
			"table of flag field parse node object(s)",
			NULL, flags_proto_table_post_handler, NULL),
};

static const struct kparser_global_namespaces kparser_arg_namespace_parser = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_PARSER, "parser", parser_key_vals,
			"parser objects", NULL, NULL, NULL),
};

static const struct kparser_global_namespaces
kparser_arg_namespace_parser_lock_unlock = {
	DEFINE_NAMESPACE_MEMBERS(KPARSER_NS_OP_PARSER_LOCK_UNLOCK,
			"parserlockunlock", parser_lock_unlock_key_vals,
			"lock/unlock a parser object using key", NULL, NULL,
			NULL),
};

const struct kparser_global_namespaces *g_namespaces[] = {
	[KPARSER_NS_INVALID] = NULL,

	[KPARSER_NS_CONDEXPRS] = &kparser_arg_namespace_cond_exprs,
	[KPARSER_NS_CONDEXPRS_TABLE] =
		&kparser_arg_namespace_cond_exprs_table,
	[KPARSER_NS_CONDEXPRS_TABLES] =
		&kparser_arg_namespace_cond_exprs_tables,

	[KPARSER_NS_COUNTER] = &kparser_arg_namespace_counter,
	[KPARSER_NS_COUNTER_TABLE] = NULL,

	[KPARSER_NS_METADATA] = &kparser_arg_namespace_metadata,
	[KPARSER_NS_METALIST] = &kparser_arg_namespace_metalist,

	[KPARSER_NS_NODE_PARSE] = &kparser_arg_namespace_parse_node,
	[KPARSER_NS_PROTO_TABLE] = &kparser_arg_namespace_proto_table,

	[KPARSER_NS_TLV_NODE_PARSE] = &kparser_arg_namespace_tlv_parse_node,
	[KPARSER_NS_TLV_PROTO_TABLE] = &kparser_arg_namespace_tlv_proto_table,

	[KPARSER_NS_FLAG_FIELD] = &kparser_arg_namespace_flag_field,
	[KPARSER_NS_FLAG_FIELD_TABLE] =
		&kparser_arg_namespace_flag_field_table,
	[KPARSER_NS_FLAG_FIELD_NODE_PARSE] =
		&kparser_arg_namespace_flag_field_node_parse,
	[KPARSER_NS_FLAG_FIELD_PROTO_TABLE] =
		&kparser_arg_namespace_flag_field_proto_table,

	[KPARSER_NS_PARSER] = &kparser_arg_namespace_parser,

	[KPARSER_NS_OP_PARSER_LOCK_UNLOCK] =
		&kparser_arg_namespace_parser_lock_unlock,

	[KPARSER_NS_MAX] = NULL,
};

static inline int node_do_cli_table(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid, char *autogenname)
{
	const char *newargv[KPARSER_CONFIG_MAX_KEYS] = {};
	int currargidx, i, rc, j;
	const char *tk;
	char tname[KPARSER_MAX_NAME];

	if (op != op_create)
		return 0;

	currargidx = check_key(argc, argv, "nxt.tableent");
	if (currargidx == -1)
		return 0;

	if (check_key(argc, argv, "nxt.table") != -1) {
		/* in case inline nxt.tableent is configured, nxt.table can
		 * not be specified here.
		 */
		fprintf(stderr, "key `nxt.tableent` can not be used "
			"with key `nxt.table` for parse node config cmd.\n");
		return -EINVAL;
	}

	// create an empty proto table with autogen name first
	// i.e. table.auto.<objname>
	currargidx = check_key(argc, argv, "name");
	sprintf(autogenname, "__table.auto.%s", argv[currargidx+1]);

	i = 0;
	newargv[i++] = strdupa(argv[0]);
	newargv[i++] = strdupa(g_namespaces[KPARSER_NS_PROTO_TABLE]->name);
	newargv[i++] = strdupa("name");
	newargv[i++] = strdupa(autogenname);

	dump_inline_expanded_cli_cmd(i, newargv);

	rc = do_cli(KPARSER_NS_PROTO_TABLE, op, i, argidx,
			(const char **) &newargv, NULL, true, true);
	if (rc != 0) {
		fprintf(stderr, "do_cli() inline table failed, rc:%d\n", rc);
		return rc;
	}

	j = 0;
	while (1) {
		currargidx = check_key_idx(argc, j, argv, "nxt.tableent");
		if (currargidx == -1)
			break;
		j = currargidx + 2;
		i = 0;
		newargv[i++] = strdupa(argv[0]);
		sprintf(tname, "%s/%s",
				g_namespaces[KPARSER_NS_PROTO_TABLE]->name,
				autogenname);
		newargv[i++] = strdupa(tname);
		tk = strchr(argv[currargidx+1], ':');
		tk--;
		newargv[i++] = strdupa("key");
		newargv[i++] = strndupa(argv[currargidx+1],
				tk - argv[currargidx+1] + 1);
		tk += 2;
		newargv[i++] = strdupa("node");
		newargv[i++] = strndupa(tk, strlen(tk));

		dump_inline_expanded_cli_cmd(i, newargv);

		rc = do_cli(KPARSER_NS_PROTO_TABLE, op, i, argidx,
				(const char **) &newargv, newargv[1],
				true, true);
		if (rc != 0)
			break;
	}

	return rc;
}

static inline int node_do_cli_metalist(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid, char *autogenname)
{
	const char *newargv[KPARSER_CONFIG_MAX_KEYS] = {};
	int currargidx, i = 0, rc;

	if (op != op_create)
		return 0;

	currargidx = check_key(argc, argv, "md.rule");
	if (currargidx == -1) {
		currargidx = check_key(argc, argv, "md.rule-id");
		if (currargidx == -1)
			return 0;
	}

	if ((check_key(argc, argv, "md.ruleset") != -1) || (check_key(argc,
					argv, "md.ruleset-id") != -1)) {
		/* in case inline md.rule is configured, md.ruleset can not be
		 * specified here.
		 */
		fprintf(stderr, "key `md.ruleset`\\`md.ruleset-id` can not be "
			"used with key `md.rule` for parse node config cmd.\n");
		return -EINVAL;
	}
	// autogen md.ruleset name, i.e. mdl.auto.<objname>
	currargidx = check_key(argc, argv, "name");
	sprintf(autogenname, "mdl.auto.%s", argv[currargidx+1]);

	newargv[i++] = strdup(argv[0]);
	newargv[i++] = strdup(g_namespaces[KPARSER_NS_METALIST]->name);
	newargv[i++] = strdup("name");
	newargv[i++] = strdup(autogenname);

	for (; i < argc; i++)
		newargv[i] = strdup(argv[i]);

	dump_inline_expanded_cli_cmd(argc, newargv);

	rc = do_cli(KPARSER_NS_METALIST, op, argc, argidx,
			(const char **) &newargv, hybrid_token, true, false);

	for (i = 0; i < argc; i++)
		free((void *) newargv[i]);

	return rc;
}

static inline int flagfields_do_cli(int nsid,
		int op, int argc, int *argidx,
		const char **argv, const char *hybrid_token,
		const char *tbn, __u16 tbid)
{
	const char *flagname = NULL, *flagid = NULL, *flagsnodename = NULL;
	const char *newargv[KPARSER_CONFIG_MAX_KEYS] = {}, *newhybrid_token;
	char autoflagname[KPARSER_MAX_NAME];
	int newargc, currargidx, i, rc;
	bool compactcmd = false;

	/* check tbn/tbid to determine table create/add entry */
	if (((strlen(tbn) == 0) && (tbid == KPARSER_INVALID_ID)) ||
			(op != op_create))
		return do_cli(nsid, op, argc, argidx, argv,
				hybrid_token, true, true);

	currargidx = check_key(argc, argv, "flag");
	if (currargidx == -1) {
		fprintf(stderr, "Mandatory key `flag` is missing\n");
		return -EINVAL;
	}

	/* add entry,check key `flags.flag` to determine if this is compact cmd
	 * and need inline expansion
	 */
	currargidx = check_key(argc, argv, "flag");
	compactcmd = currargidx != -1;
	if (!compactcmd)
		return do_cli(nsid, op, argc, argidx, argv,
				hybrid_token, true, true);

	/* Now expect all the params needed to
	 *	1. create a flag
	 *	   e.g. create flags name flag.gre.seqno flag size 4
	 *	   check for flag.name or flag.id or both. If they don't exist ,
	 *	   autogen name by prepending "flags."to flagfields name.
	 */
	newargv[0] = strdup(argv[0]);
	newargv[1] = strdup(g_namespaces[KPARSER_NS_FLAG_FIELD]->name);
	for (i = 2; i < argc; i++)
		newargv[i+2] = strdup(argv[i]);
	newargc = argc + 2;

	currargidx = check_key(argc, argv, "flag");
	if (currargidx != -1)
		flagname = argv[currargidx+1];
	else {
		currargidx = check_key(argc, argv, "flag-id");
		if (currargidx != -1)
			flagid = argv[currargidx+1];
		else
			snprintf(autoflagname, sizeof(autoflagname),
					"flags.%s", tbn);
	}

	if (flagname) {
		newargv[2] = strdup("name");
		newargv[3] = strdup(flagname);
	} else if (flagid) {
		newargv[2] = strdup("id");
		newargv[3] = strdup(flagid);
	} else {
		newargv[2] = strdup("name");
		newargv[3] = strdup(autoflagname);
	}

	dump_inline_expanded_cli_cmd(newargc, newargv);

	rc = do_cli(KPARSER_NS_FLAG_FIELD, op, newargc, argidx,
			(const char **) &newargv, hybrid_token, true, false);
	if (rc != 0) {
		fprintf(stderr, "do_cli() NS_FLAG_FIELD rc:%d\n", rc);
		goto done;
	}

	for (i = 0; i < newargc; i++) {
		free((void *) newargv[i]);
		newargv[i] = NULL;
	}

	/* Now expect all the params needed to
	 *	2. create a flagsnode if md.ruleset/md.ruleset-id
		   or both/flagsnode.name/flagsnode.id is present.
	 *	   If flagsnode.name/flagsnode.id not present, autogen the name .
	 *         by prepending "flagsnode."to flagfields name.
	 *	   e.g. create flagsnode name flagsnode.gre md.ruleset
	 *		ml.gre.seqno
	 *	3. if above case is true, create a flagstable with that node
	 *	   e.g. create flagstable name flagstable.gre
	 *              create flagstable/flagstable.gre
	 *		flagid 0x1000 flagsnode.name flagsnode.gre
	 *              NOTE: flagid is same as flag
	 */
	flagname = NULL;
	flagid = NULL;
	currargidx = check_key(argc, argv, "md.ruleset");
	if (currargidx != -1)
		flagname = argv[currargidx+1];
	else {
		currargidx = check_key(argc, argv, "md.ruleset-id");
		if (currargidx != -1)
			flagid = argv[currargidx+1];
	}
	currargidx = check_key(argc, argv, "flagsnode");
	if ((currargidx == -1) && !flagname && !flagid)
		goto done; // no flagsnode and flagstable

	if (currargidx != -1)
		flagname = argv[currargidx+1];
	else {
		flagname = NULL;
		flagid = NULL;
		snprintf(autoflagname, sizeof(autoflagname),
				"flagsnode.%s", tbn);
	}

	newargv[0] = strdup(argv[0]);
	newargv[1] = strdup(g_namespaces[
			KPARSER_NS_FLAG_FIELD_NODE_PARSE]->name);
	for (i = 2; i < argc; i++)
		newargv[i+2] = strdup(argv[i]);
	newargc = argc + 2;

	if (flagname) {
		newargv[2] = strdup("name");
		newargv[3] = strdup(flagname);
	} else if (flagid) {
		newargv[2] = strdup("id");
		newargv[3] = strdup(flagid);
	} else {
		newargv[2] = strdup("name");
		newargv[3] = strdup(autoflagname);
	}

	flagsnodename = strdup(newargv[3]);

	dump_inline_expanded_cli_cmd(newargc, newargv);

	rc = do_cli(KPARSER_NS_FLAG_FIELD_NODE_PARSE, op, newargc, argidx,
			(const char **) &newargv, hybrid_token, true, false);
	if (rc != 0) {
		fprintf(stderr, "do_cli() NS_FLAG_FIELD rc:%d\n", rc);
		goto done;
	}

	for (i = 0; i < newargc; i++) {
		free((void *) newargv[i]);
		newargv[i] = NULL;
	}

	// create the flagstable

	flagname = NULL;
	flagid = NULL;
	currargidx = check_key(argc, argv, "flagstable");
	if (currargidx != -1)
		flagname = argv[currargidx+1];
	else
		snprintf(autoflagname, sizeof(autoflagname),
				"flagstable.%s", tbn);

	newargv[0] = strdup(argv[0]);
	newargv[1] = strdup(g_namespaces[
			KPARSER_NS_FLAG_FIELD_PROTO_TABLE]->name);
	newargv[2] = strdup("name");

	if (flagname)
		newargv[3] = strdup(flagname);
	else
		newargv[3] = strdup(autoflagname);

	newargc = 4;

	dump_inline_expanded_cli_cmd(newargc, newargv);

	rc = do_cli(KPARSER_NS_FLAG_FIELD_PROTO_TABLE, op, newargc, argidx,
			(const char **) &newargv, NULL, true, false);
	if (rc != 0) {
		fprintf(stderr, "do_cli() NS_FLAG_FIELD rc:%d\n", rc);
		goto done;
	}

	// create the flagstable entry with flagsnodename and key

	snprintf(autoflagname, sizeof(autoflagname), "flagstable/%s",
		newargv[3]);
	free((void *) newargv[3]);
	free((void *) newargv[2]);
	newargv[2] = strdup(autoflagname);
	newargv[3] = strdup("flagid");
	currargidx = check_key(argc, argv, "flag");
	newargv[4] = strdup(argv[currargidx+1]);
	newargv[5] = strdup("flagsnode");
	newargv[6] = strdup(flagsnodename);

	newargc = 7;
	newhybrid_token = newargv[2];

	dump_inline_expanded_cli_cmd(newargc, newargv);

	printf("newhybrid_token: %s\n", newhybrid_token);

	rc = do_cli(KPARSER_NS_FLAG_FIELD_PROTO_TABLE, op, newargc, argidx,
			(const char **) &newargv, newhybrid_token, true, false);
	if (rc != 0) {
		fprintf(stderr, "do_cli() NS_FLAG_FIELD rc:%d\n", rc);
		goto done;
	}

done:
	for (i = 0; i < ARRAY_SIZE(newargv); i++)
		if (newargv[i])
			free((void *) newargv[i]);
	if (flagsnodename)
		free((void *) flagsnodename);

	return do_cli(nsid, op, argc, argidx, argv, hybrid_token, true, false);
}
