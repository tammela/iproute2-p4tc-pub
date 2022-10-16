// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/* Copyright (c) 2022, SiPanda Inc.
 *
 * ipkparser.c - ip parser(kParser) CLI
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
 * Author:     Pratyush Kumar Khan <pratyush@sipanda.io>
 */

#include <ctype.h>
#include <errno.h>
#include <linux/genetlink.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"
#include "kparser_common.h"

struct kparser_cmd_args_key_alias_map {
	const char *key;
	const char *alias;
};

struct kparser_cmd_args_key_aliases {
	int count;
	struct kparser_cmd_args_key_alias_map
		key_alias_maps[KPARSER_CONFIG_MAX_KEYS];
};

static struct kparser_cmd_args_key_aliases op_alias_map[KPARSER_NS_MAX];

static inline int keymatches(const char *prefix, const char *string)
{
	if (!prefix || !string)
		return 0;

	return strcmp(prefix, string);
}


static inline void store_alias(int nsid, const char *key, const char *alias)
{
	struct kparser_cmd_args_key_aliases *ns_map;

	if (!key || !alias || nsid >= KPARSER_NS_MAX)
		return;

	ns_map = &op_alias_map[nsid];

	ns_map->key_alias_maps[ns_map->count].key = strdup(key);
	ns_map->key_alias_maps[ns_map->count++].alias = strdup(alias);
}

static inline const char *convert_to_alias(const char *key, int nsid)
{
	struct kparser_cmd_args_key_aliases *ns_map;
	int i;

	if (!key || nsid >= KPARSER_NS_MAX)
		return key;

	ns_map = &op_alias_map[nsid];

	for (i = 0; i < ns_map->count; i++)
		if (keymatches(ns_map->key_alias_maps[i].key, key) == 0)
			return ns_map->key_alias_maps[i].alias;
	return key;
}

static inline int keymatches_aliases(const char *prefix, const char *key,
		const void *aliases, int limit)
{
	const struct kparser_cmd_args_ns_aliases *ns_aliases = aliases;
	int i = 0, j;

	if (keymatches(prefix, key) == 0)
		return 0;

	if (!ns_aliases)
		return 1;

	if (limit == -1)
		limit = KPARSER_CONFIG_MAX_KEYS;

	while (i < limit) {
		if (ns_aliases->keyaliases[i].keyname == NULL)
			return 1;

		if (keymatches(key, ns_aliases->keyaliases[i].keyname) == 0)
			break;
		i++;
	}

	for (j = 0; j < KPARSER_CONFIG_MAX_ALIASES; j++) {
		if (ns_aliases->keyaliases[i].aliases[j] == NULL)
			break;
		if (keymatches(prefix, ns_aliases->keyaliases[i].aliases[j]) ==
				0) {
			store_alias(ns_aliases->nsid, key,
					ns_aliases->keyaliases[i].aliases[j]);
			return 0;
		}
	}


	return 1;
}

static const char *progname = "ip";

struct kparser_cliflags {
	const char *flagname;
	__u32 flagvalue;
	const char *help;
};

static int kmod_op_error;

static struct kparser_cliflags cliflags[] = {
	{
		.flagname = "-reportnoindent",
		.flagvalue = KPARSER_CLI_FLAG_DONT_REPORT_JSON_IDENTS,
		.help = "Set this flag to convert `.` based names to JSON "
			"indetnted objects for better readability.",
	},
	{
		.flagname = "-reportallparams",
		.flagvalue = KPARSER_CLI_FLAG_REPORT_ALL_PARAMS,
		.help = "Set this flag to report all the members of objects,"
			"even if they were not configured in CLI."

	},
	{
		.flagname = "-reportdeep",
		.flagvalue = KPARSER_CLI_FLAG_READ_DEEP_REPORT,
		.help = "Set this flag to report all the members of all the "
			"table/list objects in a read command, otherwise only "
			"their identifiers (name and id) will be dumped."
	},
	{
		.flagname = "-reportlinked",
		.flagvalue = KPARSER_CLI_FLAG_READ_REPORT_LINKED,
		.help = "Set this flag to report all the linked objects "
			"of the specified object during a read command."
	},
};

static __u32 cliflag;

extern const struct kparser_global_namespaces *g_namespaces[];

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define KPARSER_REQUEST(_req, _bufsiz, _cmd, _flags)			\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,			\
		     KPARSER_GENL_VERSION, _cmd, _flags)

#define KPARSER_NLM_MAX_LEN 8192

typedef void usage_handler(FILE *stream, bool intro, int argc, int *argidx,
		char **argv, bool dump_ops, bool dump_objects);

static usage_handler *usage;

struct stackobj {
	const char *tk;
	const char *key;
	int tklen;
};

struct keynamestack {
	int top;
	struct stackobj obj[KPARSER_CONFIG_MAX_KEYS];
};

static struct keynamestack knstack = {.top = -1};

static inline void keynamestack_pop(int level)
{
	int i, j = knstack.top;

	if ((knstack.top == -1) || (level > knstack.top))
		return;

	for (i = j; i >= level; i--) {
		if (knstack.top == -1)
			break;
		close_json_object();
		knstack.top--;
	}
}

static inline void keynamestack_push(const char *tkstart, const char *tkend,
		int level)
{
	int i, tklen = tkend - tkstart + 1;
	char kname[256];

	memcpy(kname, tkstart, tklen);
	kname[tklen] = '\0';

	if (knstack.top == -1) {
		// very first entry
		knstack.top++;
		knstack.obj[knstack.top].tk = tkstart;
		knstack.obj[knstack.top].tklen = tklen;
		open_json_object(kname);
		return;
	}

	// avoid inserting duplicate tokens
	for (i = 0; i <= knstack.top; i++) {
		if ((knstack.obj[i].tklen == tklen) &&
				(memcmp(knstack.obj[i].tk,
					tkstart, tklen) == 0)) {
			return; // already exists and opened, do nothing
		}
	}

	/* if the last token at the same level in stack does not match,
	 * json close from that level and remove those entries
	 */
	if (level <= knstack.top) {
		if (knstack.obj[level].tklen != tklen)
			keynamestack_pop(level);
		else if (memcmp(knstack.obj[level].tk, tkstart, tklen) != 0)
			keynamestack_pop(level);
	}

	// now insert it
	knstack.top++;
	knstack.obj[knstack.top].tk = tkstart;
	knstack.obj[knstack.top].tklen = tklen;
	open_json_object(kname);
}

static inline const char *json_indented_block_start(const char *key)
{
	const char *tkend, *tkstart;
	int i = -1;

	if (cliflag & KPARSER_CLI_FLAG_DONT_REPORT_JSON_IDENTS)
		return key;

	if (strchr(key, '.') == NULL) {
		/* current key does not have hierarchy, so close all the
		 * previous JSON hierarchies if any as well while processing
		 * current key.
		 */
		while (knstack.top != -1) {
			close_json_object();
			knstack.top--;
		}
		// nothing is there for JSON hierarchy indents, so return
		return NULL;
	}

	/* key has '.', so parse and store in stack but ensure no duplicate
	 * if duplicate
	 */
	tkstart = key;
	while (1) {
		tkend = strchr(tkstart, '.');
		if (tkend == NULL) {
			// last token, nothing to do
			keynamestack_pop(i+1);
			break;
		}
		i++;
		tkend--;
		// push this stoken into stack
		keynamestack_push(tkstart, tkend, i);
		// move to next token
		if (tkend + 2 > (key + strlen(key) + 1))
			break;
		tkend += 2;
		tkstart = tkend;
	}

	return tkstart;
}

static int objsreportedcount;

static void dump_an_obj(const struct kparser_global_namespaces *namespace,
		const struct kparser_conf_cmd *cmd_arg)
{
	size_t w_offset, w_len, elem_counter, elem_size, elems;
	const struct kparser_arg_key_val_token *curr_arg;
	enum kparser_print_id print_id;
	bool array_dumped = false;
	struct kparser_hkey *hks;
	const char *key, *kname;
	char objnamebuf[128];
	int type, i, j, k;

	sprintf(objnamebuf, "objidx:%d", objsreportedcount);

	open_json_object(NULL);
	open_json_object(objnamebuf);
	open_json_object(convert_to_alias(namespace->name,
				namespace->name_space_id));

	for (i = 0; i < namespace->arg_tokens_count; i++) {
		if (!(cliflag & KPARSER_CLI_FLAG_REPORT_ALL_PARAMS) &&
				kparsertestbit(
					cmd_arg->conf_keys_bv.ns_keys_bvs, i))
			continue;
		curr_arg = &namespace->arg_tokens[i];
		/*
		 * if (curr_arg->dontreport)
		 *	continue;
		 */
		kname = curr_arg->key_name;
		w_offset = curr_arg->w_offset;
		w_len = curr_arg->w_len;
		elem_size = curr_arg->elem_size;
		elem_counter = curr_arg->elem_counter;
		type = curr_arg->type;

		if (curr_arg->default_template_token)
			curr_arg = curr_arg->default_template_token;

		if (type != KPARSER_ARG_VAL_ARRAY)
			type = curr_arg->type;

		if (!kname)
			kname = curr_arg->key_name;

		if (objsreportedcount && !(cliflag &
					KPARSER_CLI_FLAG_READ_DEEP_REPORT)) {
#if 0
			/* for aux objects, dump only element id nodes, i.e.
			 * for `name ` and/or `id`
			 */
			if (!curr_arg->id || !strcmp(kname, "name") ||
					!strcmp(kname, "id"))
				continue;
#else
			/* for aux objects, dump only id nodes, i.e.
			 * for `name ` and/or `id`
			 */
			if (!curr_arg->id)
				continue;
#endif
		}

		print_id = curr_arg->print_id;

		kname = convert_to_alias(kname, namespace->name_space_id);

		key = json_indented_block_start(kname);

		if (!key)
			key = kname;

		switch (type) {
		case KPARSER_ARG_VAL_HYB_KEY_NAME:
		case KPARSER_ARG_VAL_STR:
			print_string(PRINT_ANY, key, "", (char *)
				(char *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_HYB_KEY_ID:
			print_hex(PRINT_ANY, key, "",
				*(__u16 *)(((void *) cmd_arg) + w_offset));
			break;
		case KPARSER_ARG_VAL_U8:
			if (print_id == KPARSER_PRINT_HEX)
				print_0xhex(PRINT_ANY, key, "",
						*(__u8 *)(((void *) cmd_arg) +
							w_offset));
			else
				print_hu(PRINT_ANY, key, "",
						*(__u8 *)(((void *) cmd_arg) +
							w_offset));
			break;
		case KPARSER_ARG_VAL_U16:
			if (print_id == KPARSER_PRINT_HEX)
				print_0xhex(PRINT_ANY, key, "",
						*(__u16 *)(((void *) cmd_arg) +
							w_offset));
			else
				print_hu(PRINT_ANY, key, "",
						*(__u16 *)(((void *) cmd_arg) +
							w_offset));
			break;
		case KPARSER_ARG_VAL_S32:
			if (print_id == KPARSER_PRINT_HEX)
				print_0xhex(PRINT_ANY, key, "",
						*(int *)(((void *) cmd_arg) +
							w_offset));
			else
				print_int(PRINT_ANY, key, "",
						*(int *)(((void *) cmd_arg) +
							w_offset));
			break;
		case KPARSER_ARG_VAL_U32:
			if (print_id == KPARSER_PRINT_HEX)
				print_0xhex(PRINT_ANY, key, "",
						*(__u32 *)(((void *) cmd_arg) +
							w_offset));
			else
				print_uint(PRINT_ANY, key, "",
						*(__u32 *)(((void *) cmd_arg) +
							w_offset));
			break;
		case KPARSER_ARG_VAL_U64:
			if (print_id == KPARSER_PRINT_HEX)
				print_0xhex(PRINT_ANY, key, "",
						*(__u32 *)(((void *) cmd_arg) +
							w_offset));
			else
				print_lluint(PRINT_ANY, key, "",
						*(__u64 *)(((void *) cmd_arg) +
							w_offset));
			break;
		case KPARSER_ARG_VAL_SET:
			for (j = 0; j < curr_arg->value_set_len; j++) {
				if (memcmp(((void *) cmd_arg) + w_offset,
					&curr_arg->value_set[j].set_value_enum,
					w_len))
					continue;
				print_string(PRINT_ANY, key, "", (char *)
					curr_arg->value_set[j].set_value_str);
			}
			break;
		case KPARSER_ARG_VAL_ARRAY:
			if (array_dumped) {
				// fprintf(stdout,
				//	"\t\tkey array already dumped\n");
				break;
			}
			if (elem_size != sizeof(*hks)) {
				fprintf(stdout,
					"array is only supported for hkeys\n");
				return;
			}
			array_dumped = true;
			elems = *(size_t *)
				(((void *) cmd_arg) + elem_counter);
			hks =  ((void *) cmd_arg) + w_offset;
			if (elems == 0)
				break;
			open_json_array(PRINT_JSON, "Array HKEYs");
			// fprintf(stdout, "\t\tarray len:%lu\n", elems);
			for (k = 0; k < elems; k++) {
				open_json_object(NULL);
				print_string(PRINT_ANY, "name", "",
						hks[k].name);
				print_hu(PRINT_ANY, "id", "", hks[k].id);
				close_json_object();
			}
			close_json_array(PRINT_JSON, NULL);
			break;
		default:
			printf("not supported type:%d\n", type);
			break;
		}
	}
	keynamestack_pop(-1);
	close_json_object();
	close_json_object();
	close_json_object();
	objsreportedcount++;
}

static bool dump_cmd_rsp_object(const struct kparser_cmd_rsp_hdr *rsp,
	size_t *cmd_rsp_size)
{
	const struct kparser_conf_cmd *rconf;
	int i;

	rconf = (const struct kparser_conf_cmd *)rsp->objects;
	for (i = 0; i < rsp->objects_len; i++) {
		if (*cmd_rsp_size < sizeof(struct kparser_conf_cmd)) {
			fprintf(stderr,
				"rsp:obj dump err, broken buffer,"
				"cmd_rsp_size:%lu expctd:%lu\n",
				*cmd_rsp_size,
				sizeof(struct kparser_conf_cmd));
			*cmd_rsp_size = 0;
			return false;
		}
		*cmd_rsp_size = (*cmd_rsp_size) - sizeof(*rconf);
		rconf = &rsp->objects[i];
		if ((rconf->namespace_id >= KPARSER_NS_MAX) ||
				(rconf->namespace_id <= KPARSER_NS_INVALID)) {
			fprintf(stderr, "invalid object ns id:%d\n",
					rconf->namespace_id);
			continue;
		}
		dump_an_obj(g_namespaces[rconf->namespace_id], rconf);
	}
	return true;
}

static void dump_cmd_rsp(const struct kparser_global_namespaces *namespace,
		const void *cmd_rsp, size_t *cmd_rsp_size)
{
	const struct kparser_cmd_rsp_hdr *rsp = cmd_rsp;
	int i;

	if (!cmd_rsp || !cmd_rsp_size || *cmd_rsp_size < sizeof(*rsp)) {
		fprintf(stderr, "size error, %lu instead of %lu=>%lu\n",
		*cmd_rsp_size, sizeof(*rsp), sizeof(struct kparser_conf_cmd));
		if (cmd_rsp_size)
			*cmd_rsp_size = 0;
		return;
	}

	if (!namespace) {
		if ((rsp->object.namespace_id >= KPARSER_NS_MAX) ||
				(rsp->object.namespace_id <=
				 KPARSER_NS_INVALID)) {
			fprintf(stderr, "Invalid object ns id:%d\n",
					rsp->object.namespace_id);
			*cmd_rsp_size = 0;
			return;
		}
		namespace = g_namespaces[rsp->object.namespace_id];
	}

	if (objsreportedcount == 0) {
		open_json_object(NULL);
		open_json_object("cliparams");
		open_json_array(PRINT_JSON, "flags");
		for (i = 0; i < ARRAY_SIZE(cliflags); i++)
			if (cliflag & cliflags[i].flagvalue)
				print_string(PRINT_JSON, NULL, "%s",
						cliflags[i].flagname);
		close_json_array(PRINT_JSON, NULL);
		close_json_object();
		close_json_object();
	}

	open_json_object(NULL);
	open_json_object("execsummary");
	print_0xhex(PRINT_ANY, "opretcode", "", rsp->op_ret_code);
	print_string(PRINT_ANY, "opdesc", "", (char *) rsp->err_str_buf);
	if (rsp->op_ret_code == 0)
		print_hex(PRINT_ANY, "objectscounttotal", "%d",
				rsp->objects_len + 1);
	else
		print_hex(PRINT_ANY, "objectscounttotal", "%d",
				rsp->objects_len);
	close_json_object();
	close_json_object();

	(*cmd_rsp_size) = (*cmd_rsp_size) - sizeof(*rsp);

	kmod_op_error = rsp->op_ret_code;
	if (rsp->op_ret_code == 0) {
		dump_an_obj(namespace, &rsp->object);
		if (rsp->objects_len) {
			open_json_object(NULL);
			open_json_array(PRINT_JSON, "ents");
			dump_cmd_rsp_object(rsp, cmd_rsp_size);
			close_json_array(PRINT_JSON, NULL);
			close_json_object();
		}
	}
	// fprintf(stdout, "rsp:obj dump ends\n");
}

static inline bool parse_cmd_line_key_val_str(int argc, int *argidx,
		const char *argv[], bool mandatory, const char *key,
		void *value, size_t value_len, bool *value_err,
		bool restart, const void *aliases)
{
	const char *str_arg_ptr;

	if (!key || !value || value_len == 0)
		return false;

	if (argc == 0 || !argv || !argidx) {
		if (mandatory)
			fprintf(stderr, "Key `%s` is missing!\n", key);
		return false;
	}

	if (*argidx > (argc - 1)) {
		if (restart)
			*argidx = 0;
		else {
			if (mandatory)
				fprintf(stderr, "Key `%s` is missing!\n", key);
			return false;
		}
	}

	if (keymatches_aliases(argv[*argidx], key, aliases, -1)) {
		// start scanning from beginning
		if (restart)
			*argidx = 0;
		while (*argidx <= argc - 1) {
			if (!argv[*argidx]) {
				if (mandatory)
					fprintf(stderr,
						"Expected Key `%s` missing!\n",
						key);
				return false;
			}
			if (keymatches_aliases(argv[*argidx], key, aliases, -1)
					== 0)
				break;
			(*argidx)++;
		}
	}

	if (*argidx > argc - 1) {
		// key not found
		if (mandatory)
			fprintf(stderr, "Expected Key `%s` notfound!\n", key);
		return false;
	}

	(*argidx)++;

	if (*argidx > (argc - 1) || !argv[*argidx]) {
		fprintf(stderr, "value for Key `%s` is missing!\n", key);
		*value_err = true;
		return false;
	}

	str_arg_ptr = argv[*argidx];
	if (!str_arg_ptr || *str_arg_ptr == '-') {
		fprintf(stderr,
			"Value `%s` of key `%s` starts with forbidden "
			"character `-`! Only flags can start with `-`.\n",
			str_arg_ptr, key);
		*value_err = true;
		return false;

	}

	if ((strlen(str_arg_ptr) + 1) > value_len) {
		fprintf(stderr,
			"Value `%s` of key `%s` exceeds max len %lu\n",
			str_arg_ptr, key, value_len);
		*value_err = true;
		return false;
	}
	memset(value, 0, value_len);
	(void) strncpy(value, str_arg_ptr, value_len);

	(*argidx)++;

	return true;
}

static inline bool parse_cmd_line_key_val_ints(int argc, int *argidx,
		const char *argv[], bool mandatory, const char *key,
		void *value, size_t value_len, int64_t min, int64_t max,
		bool *value_err, bool restart, bool ignore_min_max,
		const void *aliases)
{
	char arg_val[KPARSER_MAX_STR_LEN_U64];
	int errno_local;
	__u64 ret_digit;
	bool rc;

	if (!key || !value || value_len == 0 ||
			value_len > sizeof(ret_digit))
		return false;

	rc = parse_cmd_line_key_val_str(argc, argidx, argv, mandatory, key,
			arg_val, sizeof(arg_val), value_err, restart, aliases);
	if (!rc || *value_err)
		return false;

	ret_digit = strtoull(arg_val, NULL, 0);
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected digit for Key `%s`, val `%s`."
				"errno: %d in strtoull().Try again.\n",
				key, arg_val, errno_local);
		*value_err = true;
		return false;
	}

	if (!ignore_min_max && ((int64_t)ret_digit > max ||
				(int64_t)ret_digit < min)) {
		fprintf(stderr, "Value %ld for Key `%s` is out of valid "
				"range. Min: %ld, Max: %ld.\n",
				(int64_t)ret_digit, key, min, max);
		*value_err = true;
		return false;
	}

	memcpy(value, &ret_digit, value_len);

	return true;
}

static inline bool parse_element(const char *argv,
		char *ns, size_t ns_size,
		char *table_name, size_t table_name_size,
		__u16 *table_id)
{
	char arg_u16[KPARSER_MAX_STR_LEN_U16];
	const char *tk, *tk1;
	unsigned long ret_digit;
	int errno_local;
	bool isid = true;

	if (!argv || !strlen(argv))
		return false;

	// parsing pattern1: "<namespace>/<name>
	// parsing pattern2: "<namespace>/<object>"
	tk = strchr(argv, '/');
	tk1 = tk + 1;
	tk--;

	if (ns && ns_size) {
		if ((tk - argv + 1) > ns_size) {
			fprintf(stderr, "%s:ns_size %lu less than "
					"real size %lu\n",
					__func__, ns_size, tk - argv + 1);
			return false;
		}
		memcpy(ns, argv, (tk - argv + 1));
		ns[(tk - argv) + 1] = '\0';
	}

	if (!table_name || !table_name_size || !table_id)
		return true;

	if (tk1 == NULL) {
		fprintf(stderr, "Invalid hybrid key format:`%s`,"
				"expected:`object/<name>` or `object/<id>`\n",
				argv);
		return false;
	}

	/* There is no separator, check if this id (i.e. pure number) or name */
	tk = tk1;
	while (!tk || *tk != '\0')
		if (!isdigit(*tk)) {
			isid = false;
			break;
		}

	if (!isid) {
		// tk1 is object name
		if (strlen(tk1) + 1 > table_name_size) {
			fprintf(stderr, "%s:Create table entry command's "
				"table key name len is %ld, but max allowed "
				"key name len is %lu\n",
				__func__, strlen(tk1) + 1, table_name_size);
			return false;
		}
		strcpy(table_name, tk1);
		return true;
	}

	// tk1 is object id
	if (strlen(tk1) + 1 > sizeof(arg_u16)) {
		fprintf(stderr,
			"%s:Create table entry command's table "
			"key id's length %ld, but max allowed key "
			"id len is %lu\n",
			__func__, strlen(tk1) + 1, sizeof(arg_u16));
		return false;
	}
	strcpy(arg_u16, tk1);
	ret_digit = strtoul(arg_u16, NULL, 0);
	errno_local = errno;
	if (errno_local == EINVAL || errno_local == ERANGE) {
		fprintf(stderr, "Expected u16 digit for table key id,"
				"errno: %d in strtoull().Try again.\n",
				errno_local);
		return false;
	}
	if (ret_digit >= KPARSER_INVALID_ID) {
		fprintf(stderr, "Value %lu for table key id is out of valid "
				"range. Min: 0, Max: %d.Try again.\n",
				ret_digit, KPARSER_INVALID_ID);
		return false;
	}
	*table_id = (__u16) ret_digit;
	return true;
}

static int exec_cmd(uint8_t cmd, int32_t req_attr, int32_t rsp_attr,
		const void *cmd_arg, size_t cmd_arg_size,
		void **rsp_buf, size_t *rsp_buf_size)
{
	struct rtattr *tb[KPARSER_ATTR_MAX + 1];
	struct nlmsghdr *answer;
	struct genlmsghdr *ghdr;
	int len, rc;

	KPARSER_REQUEST(req, KPARSER_NLM_MAX_LEN, cmd, NLM_F_REQUEST);
	rc = addattr_l(&req.n, KPARSER_NLM_MAX_LEN, req_attr,
			cmd_arg, cmd_arg_size);
	if (rc != 0) {
		fprintf(stderr, "addattr_l() failed, cmd:%u attr:%d rc:%d\n",
				cmd, req_attr, rc);
		return rc;
	}

	rc = rtnl_talk(&genl_rth, &req.n, &answer);
	if (rc != 0) {
		fprintf(stderr, "rtnl_talk() failed, cmd:%u attr:%d rc:%d\n",
				cmd, req_attr, rc);
		return rc;
	}

	len = answer->nlmsg_len;

	if (answer->nlmsg_type != genl_family) {
		fprintf(stderr, "family type err, expected: %d, found:%u\n",
				genl_family, answer->nlmsg_type);
		return -1;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		fprintf(stderr, "rsp len err: %d\n", len);
		return -1;
	}

	ghdr = NLMSG_DATA(answer);
	rc = parse_rtattr(tb, KPARSER_ATTR_MAX,
			(void *) ghdr + GENL_HDRLEN, len);
	if (rc < 0) {
		fprintf(stderr, "parse_rtattr() err, rc:%d\n", rc);
		return rc;
	}

	if (tb[rsp_attr]) {
		*rsp_buf_size = RTA_PAYLOAD(tb[rsp_attr]);
		if (*rsp_buf_size) {
			*rsp_buf = calloc(1, *rsp_buf_size);
			if (!(*rsp_buf)) {
				fprintf(stderr,
					"attr:%d: calloc() failed, size:%lu\n",
					rsp_attr, *rsp_buf_size);
				*rsp_buf_size = 0;
				return -1;
			}
			memcpy(*rsp_buf, RTA_DATA(tb[rsp_attr]),
			       *rsp_buf_size);
		}
	}

	return 0;
}

#define INCOMPATIBLE_KEY_CHECK						\
do {									\
	const char *err_key_str = NULL;					\
	int i, j;							\
									\
	for (i = 0; i < incompatible_keys_len; i++) {			\
		if (!incompatible_keys[i] || err_key_str)		\
			break;						\
		for (j = 0; j < argc; j += 2) {				\
			if (argv[j] &&					\
				(keymatches(incompatible_keys[i],	\
					 argv[j]) == 0)) {		\
				err_key_str = argv[j];			\
				break;					\
			}						\
		}							\
	}								\
	if (!err_key_str)						\
		break;							\
	fprintf(stderr, "key `%s` is not compatible with key `%s`\n",	\
			err_key_str, key);				\
	rc = -EINVAL;							\
	goto out;							\
} while (0)

int do_cli(int nsid, int op, int argc, int *argidx, const char **argv,
		const char *hybrid_token, bool preprocess_done,
		bool undesired_key_check)
{
	size_t cmd_rsp_size = 0, old_cmd_rsp_size, w_offset, w_len, cmd_arg_len;
	bool ret = true, value_err = false, ignore_min_max = false;
	const struct kparser_global_namespaces *namespace;
	const struct kparser_arg_key_val_token *curr_arg;
	size_t *dst_array_size, elem_offset, elem_size;
	int i, j, rc, op_attr_id, key_start_idx = 0;
	int other_mandatory_idx, type, elem_type;
	struct kparser_conf_cmd *cmd_arg = NULL;
	char types_buf[KPARSER_SET_VAL_LEN_MAX];
	size_t offset_adjust, elem_counter;
	char tbn[KPARSER_MAX_NAME] = {};
	__u16 tbid = KPARSER_INVALID_ID;
	const char *key, *dependent_Key;
	const char **incompatible_keys;
	size_t incompatible_keys_len;
	__u32 *ns_keys_bvs = NULL;
	void *scratch_buf = NULL;
	void *cmd_rsp = NULL;
	const void *aliases;

	if (nsid <= KPARSER_NS_INVALID || nsid >= KPARSER_NS_MAX)
		return -EINVAL;

	namespace = g_namespaces[nsid];

	if (!namespace)
		return 0;

	aliases = namespace->aliases;

	if (argidx && *argidx > 0)
		key_start_idx = *argidx;

	if (hybrid_token) {
		ret = parse_element(hybrid_token, NULL, 0, tbn, sizeof(tbn),
				&tbid);
		if (!ret) {
			fprintf(stderr, "object `%s`: token err:%s\n",
					namespace->name, hybrid_token);
			return -EINVAL;
		}
	}

	if (!preprocess_done && namespace->custom_do_cli)
		return namespace->custom_do_cli(nsid, op, argc,
				argidx, argv, hybrid_token, tbn, tbid);

	if (namespace->arg_tokens_count >= KPARSER_CONFIG_MAX_KEYS) {
		fprintf(stderr, "object `%s`: key count %lu more than max %d\n",
				namespace->name, namespace->arg_tokens_count,
				KPARSER_CONFIG_MAX_KEYS);
		return -EINVAL;
	}

	cmd_arg_len = sizeof(*cmd_arg);
	cmd_arg = calloc(1, cmd_arg_len);
	if (!cmd_arg) {
		fprintf(stderr, "object `%s`: calloc() failed\n",
				namespace->name);
		return -ENOMEM;
	}
	cmd_arg->namespace_id = namespace->name_space_id;

	switch (op) {
	case op_create:
		op_attr_id = namespace->create_attr_id;
		break;

	case op_update:
		op_attr_id = namespace->update_attr_id;
		break;

	case op_read:
		ignore_min_max = true;
		op_attr_id = namespace->read_attr_id;
		cmd_arg->recursive_read_delete =
			cliflag & KPARSER_CLI_FLAG_READ_REPORT_LINKED;
		break;

	case op_lock:
		ignore_min_max = true;
		op_attr_id = namespace->create_attr_id;
		break;

	case op_unlock:
		ignore_min_max = true;
		op_attr_id = namespace->delete_attr_id;
		break;

	case op_delete:
		ignore_min_max = true;
		op_attr_id = namespace->delete_attr_id;
		break;

	default:
		fprintf(stderr, "invalid op:%d\n", op);
		return -EINVAL;
	}


	ns_keys_bvs = cmd_arg->conf_keys_bv.ns_keys_bvs;
	memset(ns_keys_bvs, 0xff, sizeof(cmd_arg->conf_keys_bv.ns_keys_bvs));

	for (i = 0; i < namespace->arg_tokens_count; i++) {
		curr_arg = &namespace->arg_tokens[i];

		key = curr_arg->key_name;
		w_offset = curr_arg->w_offset;
		w_len = curr_arg->w_len;
		elem_size = curr_arg->elem_size;
		elem_counter = curr_arg->elem_counter;
		offset_adjust = curr_arg->offset_adjust;
		type = curr_arg->type;
		elem_type = curr_arg->elem_type;

		incompatible_keys = (const char **)
			curr_arg->incompatible_keys;
		incompatible_keys_len = sizeof(curr_arg->incompatible_keys)/
			sizeof(curr_arg->incompatible_keys[0]);

		if (curr_arg->default_template_token)
			curr_arg = curr_arg->default_template_token;

		if (type != KPARSER_ARG_VAL_ARRAY)
			type = curr_arg->type;

		if (!key)
			key = curr_arg->key_name;

		// printf("processing token key:`%s`\n", key);

		switch (type) {
		case KPARSER_ARG_VAL_HYB_KEY_NAME:
			if (!hybrid_token)
				break;
			if (strlen(tbn)) {
				memcpy(((void *) cmd_arg) + w_offset, tbn,
						strlen(tbn) + 1);
				INCOMPATIBLE_KEY_CHECK;
				kparserclearbit(ns_keys_bvs, i);
			} else {
				if (curr_arg->default_val &&
						curr_arg->default_val_size) {
					memcpy(((void *) cmd_arg) + w_offset,
							curr_arg->default_val,
							curr_arg->
							default_val_size);
				}
			}
			break;

		case KPARSER_ARG_VAL_HYB_KEY_ID:
			if (!hybrid_token)
				break;
			if (tbid != KPARSER_INVALID_ID) {
				memcpy(((void *) cmd_arg) + w_offset, &tbid,
						w_len);
				INCOMPATIBLE_KEY_CHECK;
				kparserclearbit(ns_keys_bvs, i);
			} else
				memcpy(((void *) cmd_arg) + w_offset,
						&curr_arg->def_value, w_len);
			break;

		case KPARSER_ARG_VAL_STR:
			ret = parse_cmd_line_key_val_str(argc, argidx, argv,
					curr_arg->mandatory, key,
					((void *) cmd_arg) + w_offset, w_len,
					&value_err, true, aliases);
			if (ret) {
				if ((op == op_update) && curr_arg->immutable) {
					fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
					rc = -EINVAL;
					goto out;
				}
				INCOMPATIBLE_KEY_CHECK;
				kparserclearbit(ns_keys_bvs, i);
				break;
			}
			if (curr_arg->mandatory || value_err) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:`%s`\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}
			if (curr_arg->default_val &&
					curr_arg->default_val_size)
				memcpy(((void *) cmd_arg) + w_offset,
						curr_arg->default_val, w_len);
			ret = true;
			break;

		case KPARSER_ARG_VAL_U8:
		case KPARSER_ARG_VAL_U16:
		case KPARSER_ARG_VAL_S32:
		case KPARSER_ARG_VAL_U32:
		case KPARSER_ARG_VAL_U64:
			ret = parse_cmd_line_key_val_ints(argc, argidx, argv,
					curr_arg->mandatory, key,
					((void *) cmd_arg) + w_offset, w_len,
					curr_arg->min_value,
					curr_arg->max_value, &value_err,
					true, ignore_min_max, aliases);
			if (ret) {
				if ((op == op_update) && curr_arg->immutable) {
					fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
					rc = -EINVAL;
					goto out;
				}
				INCOMPATIBLE_KEY_CHECK;
				kparserclearbit(ns_keys_bvs, i);
				break;
			}
			if (curr_arg->mandatory || value_err) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:`%s`\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}
			memcpy(((void *) cmd_arg) + w_offset,
					&curr_arg->def_value, w_len);
			ret = true;
			break;

		case KPARSER_ARG_VAL_SET:
			ret = parse_cmd_line_key_val_str(argc, argidx, argv,
					curr_arg->mandatory, key,
					types_buf, sizeof(types_buf),
					&value_err, true, aliases);
			if (!ret && (curr_arg->mandatory || value_err)) {
				fprintf(stderr,
					"namespace `%s`: "
					"Failed to parse key:%s\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}
			if (!ret) {
				memcpy(((void *) cmd_arg) + w_offset,
					&curr_arg->def_value_enum, w_len);
				ret = true;
				break;
			}
			if ((op == op_update) && curr_arg->immutable) {
				fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
				rc = -EINVAL;
				goto out;
			}
			for (j = 0; j < curr_arg->value_set_len; j++) {
				if (keymatches_aliases(types_buf,
					curr_arg->value_set[j].set_value_str,
					aliases, -1) == 0) {
					memcpy(((void *) cmd_arg) + w_offset,
						&curr_arg->value_set[j].
							set_value_enum, w_len);
					INCOMPATIBLE_KEY_CHECK;
					kparserclearbit(ns_keys_bvs, i);
					break;
				}
			}
			if (j == curr_arg->value_set_len) {
				fprintf(stderr,
					"namespace `%s`: "
					"Invalid value `%s` for key: `%s`\n",
					namespace->name, types_buf, key);
				fprintf(stderr, "\tValid set is: {");
				for (j = 0; j < curr_arg->value_set_len; j++) {
					if (j == curr_arg->value_set_len - 1)
						fprintf(stderr, "%s}\n",
							curr_arg->value_set[j].
							set_value_str);
					else
						fprintf(stderr, "%s | ",
							curr_arg->value_set[j].
							set_value_str);

				}
				rc = -EINVAL;
				goto out;
			}
			break;

		case KPARSER_ARG_VAL_ARRAY:
			*argidx = 0;
			ignore_min_max = true;
array_parse_start:
			if (*argidx >= argc - 1)
				break;

			if (w_len > elem_size) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, w_len > "
					"elem_size\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}

			if (offset_adjust >= elem_size) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, offset_adjust > "
					"elem_size\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}

			scratch_buf = realloc(scratch_buf, elem_size);
			if (!scratch_buf) {
				fprintf(stderr, "object `%s`:key:%s:"
					"realloc() failed for scratch_buf\n",
					namespace->name, key);
				rc = -ENOMEM;
				goto out;
			}
			memset(scratch_buf, 0, elem_size);

			if (elem_type == KPARSER_ARG_VAL_STR) {
				ret = parse_cmd_line_key_val_str(argc, argidx,
						argv, curr_arg->mandatory, key,
						scratch_buf + offset_adjust,
						w_len, &value_err, false,
						aliases);
			} else {
				ret = parse_cmd_line_key_val_ints(argc, argidx,
						argv, curr_arg->mandatory, key,
						scratch_buf + offset_adjust,
						w_len, curr_arg->min_value,
						curr_arg->max_value, &value_err,
						false, ignore_min_max, aliases);
			}

			if (!ret) {
				if (curr_arg->mandatory || value_err) {
					fprintf(stderr,
						"namespace `%s`: "
						"Failed to parse key:`%s`\n",
						namespace->name, key);
					rc = -EINVAL;
					goto out;
				} else {
					ret = true;
					goto array_parse_start;
				}
			}

			INCOMPATIBLE_KEY_CHECK;
			if ((op == op_update) && curr_arg->immutable) {
				fprintf(stderr, "object `%s`: "
						"key:`%s` immutable\n",
						namespace->name, key);
				rc = -EINVAL;
				goto out;
			}

			dst_array_size = ((void *) cmd_arg + elem_counter);
			(*dst_array_size)++;
			cmd_arg_len += *dst_array_size * elem_size;
			cmd_arg = realloc(cmd_arg, cmd_arg_len);
			if (!cmd_arg) {
				fprintf(stderr, "object `%s`:key:%s:"
					"realloc() failed\n",
					namespace->name, key);
				rc = -ENOMEM;
				goto out;
			}
			ns_keys_bvs = cmd_arg->conf_keys_bv.ns_keys_bvs;
			elem_offset = w_offset +
				((*dst_array_size - 1) * elem_size);

			if (elem_offset + elem_size > cmd_arg_len) {
				fprintf(stderr, "object `%s`:key:%s:"
					"config error, write overflow\n",
					namespace->name, key);
				rc = -EINVAL;
				goto out;
			}

			memcpy(((void *)cmd_arg) + elem_offset,
				scratch_buf, elem_size);
			ret = true;
			goto array_parse_start;

		default:
			ret = false;
			break;
		}

		if (ret == false) {
			fprintf(stderr, "object `%s`: cmdline arg error\n",
					namespace->name);
			rc = -EINVAL;
			goto out;
		}
	}

	for (i = 0; i < namespace->arg_tokens_count; i++) {
		curr_arg = &namespace->arg_tokens[i];
		if ((op == op_read) || (curr_arg->semi_optional == false))
			continue;
		other_mandatory_idx = curr_arg->other_mandatory_idx;
		if (other_mandatory_idx == -1)
			continue;
		key = curr_arg->key_name;
		if (curr_arg->default_template_token)
			curr_arg = curr_arg->default_template_token;
		if (!key)
			key = curr_arg->key_name;
		if ((op == op_update) && curr_arg->immutable)
			continue;
#if 0
		printf("%d:I:%d\n", i, kparsertestbit(ns_keys_bvs, i));
		printf("%d:OM:%d\n", other_mandatory_idx,
				kparsertestbit(ns_keys_bvs, other_mandatory_idx));
		printf("dependency check for token key:`%s`, %d\n",
				key, curr_arg->semi_optional);
#endif

		if (kparsertestbit(ns_keys_bvs, i) &&
				kparsertestbit(ns_keys_bvs,
					other_mandatory_idx)) {
			dependent_Key = namespace->arg_tokens[
				other_mandatory_idx].key_name;
			if (namespace->arg_tokens[other_mandatory_idx].
					default_template_token)
				if (!dependent_Key)
					dependent_Key = namespace->arg_tokens[
						other_mandatory_idx].
							default_template_token
							->key_name;
			fprintf(stderr, "object `%s`: either configure key "
					"`%s` and/or key `%s`\n",
					namespace->name,
					key, dependent_Key);
			rc = -EINVAL;
			goto out;
		}
	}

	if (!undesired_key_check)
		goto undesired_key_check_validation_done;

	for (i = key_start_idx; i < argc; i += 2) {
		// printf("%s\n", argv[i]);
		// avoid checking flags here
		if (argv[i][0] == '-') {
			i--; // mind that flags are not in pair, unlike keys
			continue;
		}
		for (j = 0; j < namespace->arg_tokens_count; j++) {
			curr_arg = &namespace->arg_tokens[j];
			key = curr_arg->key_name;
			if (curr_arg->default_template_token)
				curr_arg = curr_arg->default_template_token;
			if (!key)
				key = curr_arg->key_name;
			if (argv[i] && (keymatches_aliases(argv[i], key,
							aliases, -1) == 0))
				break;
		}
		if (j == namespace->arg_tokens_count) {
			fprintf(stderr, "%s: Invalid key `%s` in cmdline\n"
					"check \"%s parser help object %s\" "
					"for all the keys of this object.\n",
					namespace->name, argv[i],
					progname, namespace->name);
			rc = -EINVAL;
			goto out;
		}
	}

undesired_key_check_validation_done:

	if (namespace->post_process_handler) {
		rc = namespace->post_process_handler(namespace, op, argc,
				argidx, argv, hybrid_token, ns_keys_bvs,
				cmd_arg);
		if (rc != 0) {
			fprintf(stderr, "%s: post processing failed\n",
					namespace->name);
			goto out;
		}
	}

#if 0
	new_json_obj(json);
	dump_an_obj(namespace, cmd_arg);
	delete_json_obj();
#endif

	rc = exec_cmd(KPARSER_CMD_CONFIGURE, op_attr_id,
			namespace->rsp_attr_id,
			cmd_arg, cmd_arg_len,
			&cmd_rsp, &cmd_rsp_size);
	if (rc != 0) {
		fprintf(stderr, "%s:exec_cmd() failed for cmd:%d "
				"attrs:{req:%d:rsp:%d}, rc:%d\n",
				namespace->name,
				KPARSER_CMD_CONFIGURE,
				op_attr_id,
				namespace->rsp_attr_id, rc);
		goto out;
	}

	old_cmd_rsp_size = cmd_rsp_size;
	new_json_obj(json);
	objsreportedcount = 0;
	i = 0;
	while (cmd_rsp_size >= sizeof(*cmd_rsp)) {
		if (i == 1)
			open_json_array(PRINT_JSON, "associatedobjects");
		dump_cmd_rsp(NULL, cmd_rsp + (old_cmd_rsp_size - cmd_rsp_size),
				&cmd_rsp_size);
		i++;
	}

	if (i >= 2)
		close_json_array(PRINT_JSON, NULL);

	delete_json_obj();
out:
	if (cmd_arg)
		free(cmd_arg);

	if (scratch_buf)
		free(scratch_buf);

	if (cmd_rsp)
		free(cmd_rsp);

	if (kmod_op_error)
		return kmod_op_error;

	return rc;
}

static int __do_cli(int op, int argc, int *argidx,
		const char **argv)
{
	const char *ns = NULL, *hybrid_token = NULL;
	char namespace[KPARSER_MAX_NAME];
	int i, slashcount = 0;

	if (argc && (*argidx <= (argc - 1)) && argv) {
		for (i = *argidx; i < strlen(argv[*argidx]); i++)
			if (argv[*argidx][i] == '/')
				slashcount++;
		if (slashcount) {
			if (slashcount != 1) {
				fprintf(stderr,
					"Invalid hybrid key format:`%s`,"
					"expected:`object/<name>` or"
					"`object/<id>`\n",
					argv[*argidx]);
				return -EINVAL;
			}
			hybrid_token = argv[*argidx];
			if (!parse_element(argv[*argidx],
					   namespace, sizeof(namespace),
					   NULL, 0, NULL)) {
			}
			ns = namespace;
		} else
			ns = argv[*argidx];
	}

	if (!ns)
		goto errout;

	for (i = 0; i < KPARSER_NS_MAX; i++) {

		if (!g_namespaces[i])
			continue;

		if (keymatches_aliases(ns, g_namespaces[i]->name,
					g_namespaces[i]->aliases, 1) == 0) {
			(*argidx)++;
			return do_cli(i, op, argc, argidx, argv,
					hybrid_token, false, true);
		}
	}

errout:
	fprintf(stderr, "Invalid namespace/object: %s\n", ns);
	usage(stderr, false, 0, NULL, NULL, false, true);
	return -EINVAL;
}

struct kparser_cli_ops {
	int op;
	const char *op_name;
	const char *description;
	bool hidden;
};

static struct kparser_cli_ops cli_ops[] = {
	{
		.op_name = "create",
		.op = op_create,
		.description = "create an object",
	},
	{
		.op_name = "read",
		.op = op_read,
		.description = "read an object",
	},
#if 0
	{
		.op_name = "update",
		.op = op_update,
		.description = "modify an object",
	},
#endif
	{
		.op_name = "delete",
		.op = op_delete,
		.description = "delete an object",
	},
	{
		.op_name = "lock",
		.op = op_lock,
		.description =
			"lock a parser object so it cannot be deleted/modified",
	},
	{
		.op_name = "unlock",
		.op = op_unlock,
		.description =
			"unlock a parser object so it can be deleted/modified",
	},
};

static const char * const arg_val_type_str[] = {
	[KPARSER_ARG_VAL_STR] = "string",
	[KPARSER_ARG_VAL_U8] = "unsigned 8 bits",
	[KPARSER_ARG_VAL_U16] = "unsigned 16 bits",
	[KPARSER_ARG_VAL_S32] = "signed 32 bits",
	[KPARSER_ARG_VAL_U32] = "unsigned 32 bits",
	[KPARSER_ARG_VAL_U64] = "unsigned 64 bits",
	[KPARSER_ARG_VAL_BOOL] = "boolean (true/false)",
	[KPARSER_ARG_VAL_FLAG] = "flag",
	[KPARSER_ARG_VAL_SET] = "set of string constants",
	[KPARSER_ARG_VAL_ARRAY] = "array of hash keys (hkeys)",
	[KPARSER_ARG_VAL_HYB_KEY_NAME] = "hash key name in hybrind format",
	[KPARSER_ARG_VAL_HYB_KEY_ID] = "hash key ID in hybrind format",
	[KPARSER_ARG_VAL_INVALID] = "end of valid values"
};

#define PRINT_HELP_INTRO()						\
	fprintf(stream,							\
	"Usage: \"%s parser [ operations ] [ objects ] [ args ] "	\
	"[-flags]\"\n"							\
	"More help 1: \"%s parser help operations\"\n"			\
	"More help 2: \"%s parser help objects\"\n"			\
	"More help 3: \"%s parser help objects <objname>\"\n"		\
	"More help 4: \"%s parser help objects <objname> <keyname>\"\n"	\
	"More help 5: \"%s parser help args\"\n"			\
	"More help 6: \"%s parser help flags\"\n",			\
	progname, progname, progname, progname, progname,		\
	progname, progname)

static void usage_text(FILE *stream, bool intro, int argc, int *argidx,
		char **argv, bool dump_ops, bool dump_objects)
{
	const struct kparser_arg_key_val_token *token;
	const char *arg_name, *ns = NULL, *arg = NULL;
	const char *default_set_value = NULL;
	int i, j, k;

	if (dump_ops)
		goto label_dump_ops;

	if (dump_objects)
		goto label_dump_objects;

	if (intro)
		PRINT_HELP_INTRO();

	if (!argc || !argidx || !argv) {
		// fprintf(stream, "type `help` for more details on usage\n");
		return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "flags") ==
			0)) || argc == 0) {
		fprintf(stream, "flags := {");
		for (i = 0; i < ARRAY_SIZE(cliflags); i++) {
			if (i == (ARRAY_SIZE(cliflags) - 1))
				fprintf(stream, "%s}\n", cliflags[i].flagname);
			else
				fprintf(stream, "%s | ", cliflags[i].flagname);
		}
		return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "operations") ==
			0)) || argc == 0) {
		if (argidx)
			(*argidx)++;
label_dump_ops:
		fprintf(stream, "operations := {");
		for (i = 0; i < ARRAY_SIZE(cli_ops); i++) {
			if (cli_ops[i].hidden == true)
				continue;
			if (i == (ARRAY_SIZE(cli_ops) - 1))
				fprintf(stream, "%s}\n", cli_ops[i].op_name);
			else
				fprintf(stream, "%s | ", cli_ops[i].op_name);
		}
		if (dump_ops)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "objects") == 0)) ||
			argc == 0) {

		if (argidx)
			(*argidx)++;

		ns = argv[*argidx];
		if (argidx)
			(*argidx)++;
		if (ns && strcmp(ns, "args"))
			goto print_args;
		ns = NULL;

label_dump_objects:
		fprintf(stream, "objects := {");
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			fprintf(stream, "%s | ", g_namespaces[i]->name);
		}
		fprintf(stream, "}\n");
		if (dump_objects)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "args") == 0)) ||
			argc == 0) {
		if (argidx)
			(*argidx)++;
		fprintf(stream,
			"\nAll possible args for each objects/namespaces:\n");
print_args:
		if (*argidx <= (argc - 1) && argv[*argidx]) {
			arg = argv[*argidx];
			if (keymatches(arg, "arg") == 0) {
				(*argidx)++;
				if (*argidx <= (argc - 1) && argv[*argidx])
					arg = argv[*argidx];
				else
					arg = NULL;
			}
		}
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			if (ns && strcmp(g_namespaces[i]->name, ns))
				continue;
			fprintf(stream, "%s:[", g_namespaces[i]->name);
			for (j = 0; j < g_namespaces[i]->arg_tokens_count;
					j++) {
				token = &g_namespaces[i]->arg_tokens[j];
				arg_name = token->key_name;
				if (token->default_template_token)
					token = token->default_template_token;
				if (!arg_name)
					arg_name = token->key_name;
				if (arg && keymatches(arg, arg_name))
					continue;
				fprintf(stream, "\n\t{");
				fprintf(stream,
					"\n\t\tname:%s, type:%s, "
					"mandatory:%d, details:%s, "
					"incompatible keys: [",
					arg_name,
					arg_val_type_str[token->type],
					token->mandatory,
					token->help_msg);
				for (k = 0; k < sizeof(token->
					incompatible_keys) / sizeof(token->
						incompatible_keys[0]); k++) {
					if (!token->incompatible_keys[k])
						break;
					fprintf(stream, "%s,",
						token->incompatible_keys[k]);
				}
				fprintf(stream, "]");
				switch (token->type) {
				case KPARSER_ARG_VAL_STR:
					fprintf(stream,
						"\n\t\tdefault:%s, maxlen:%lu",
						(const char *)
						token->default_val,
						token->str_arg_len_max);
					break;
				case KPARSER_ARG_VAL_U8:
				case KPARSER_ARG_VAL_U16:
				case KPARSER_ARG_VAL_U32:
				case KPARSER_ARG_VAL_U64:
					fprintf(stream,
						"\n\t\tmin:%llu, default:%llu, "
						"max:%llu",
						token->min_value,
						token->def_value,
						token->max_value);
					break;
				case KPARSER_ARG_VAL_SET:
					fprintf(stream, "\n\t\tset=(");
					for (k = 0; k < token->value_set_len;
							k++) {
						fprintf(stream, "`%s`",
							token->value_set[k].
							set_value_str);
						if (token->value_set[k].
							set_value_enum ==
							token->def_value_enum)
							default_set_value =
							token->value_set[k].
							set_value_str;
					}
					fprintf(stream, ")");
					fprintf(stream, "\n\t\tDefault:%s",
						default_set_value);
					break;
				case KPARSER_ARG_VAL_BOOL:
				case KPARSER_ARG_VAL_FLAG:
				case KPARSER_ARG_VAL_ARRAY:
				case KPARSER_ARG_VAL_HYB_KEY_NAME:
				case KPARSER_ARG_VAL_HYB_KEY_ID:
				default:
					break;
				}
				fprintf(stream, "\n\t}");
				if (arg)
					break;
			}
			if (arg && j == g_namespaces[i]->arg_tokens_count)
				fprintf(stream,
					"\n\t{`%s`:invalid arg name}", arg);
			fprintf(stream, "\n]\n");
		}
	}
}

static void usage_json(FILE *stream, bool intro, int argc, int *argidx,
		char **argv, bool dump_ops, bool dump_objects)
{
	const struct kparser_arg_key_val_token *token;
	const char *arg_name, *ns = NULL, *arg = NULL;
	const char *default_set_value = NULL, *empty = "";
	int i, j, k;

	if (dump_ops)
		goto label_dump_ops;

	if (dump_objects)
		goto label_dump_objects;

	if (intro)
		PRINT_HELP_INTRO();

	if (!argc || !argidx || !argv) {
		// fprintf(stream, "type `help` for more details on usage\n");
		return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "flags") ==
			0)) || argc == 0) {
		new_json_obj(json);
		open_json_object(NULL);
		open_json_object("flags");
		for (i = 0; i < ARRAY_SIZE(cliflags); i++) {
			open_json_object(cliflags[i].flagname);
			print_string(PRINT_ANY, "Description",
					"%s", cliflags[i].help);
			close_json_object();
		}
		close_json_object();
		close_json_object();
		delete_json_obj();
		return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "operations") ==
			0)) || argc == 0) {
		if (argidx)
			(*argidx)++;
label_dump_ops:
		new_json_obj(json);
		open_json_object(NULL);
		open_json_object("operations");
		for (i = 0; i < ARRAY_SIZE(cli_ops); i++) {
			if (cli_ops[i].hidden == true)
				continue;
			open_json_object(cli_ops[i].op_name);
			print_string(PRINT_ANY, "description",
					"%s", cli_ops[i].description);
			close_json_object();
		}
		close_json_object();
		close_json_object();
		delete_json_obj();
		if (dump_ops)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "objects") == 0)) ||
			argc == 0) {

		if (argidx)
			(*argidx)++;

		ns = argv[*argidx];
		if (argidx)
			(*argidx)++;
		if (ns && strcmp(ns, "args"))
			goto print_args;
		ns = NULL;

label_dump_objects:
		new_json_obj(json);
		open_json_object(NULL);
		open_json_object("objects");
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			open_json_object(g_namespaces[i]->name);
			print_string(PRINT_ANY, "description",
					"%s", g_namespaces[i]->description);
			close_json_object();
		}
		close_json_object();
		close_json_object();
		delete_json_obj();
		if (dump_objects)
			return;
	}

	if ((argc && argidx && (*argidx <= (argc - 1)) && argv &&
		argv[*argidx] && (keymatches(argv[*argidx], "args") == 0)) ||
			argc == 0) {
		if (argidx)
			(*argidx)++;
		fprintf(stream,
			"\nAll possible args for each objects/namespaces:\n");
print_args:
		if (*argidx <= (argc - 1) && argv[*argidx]) {
			arg = argv[*argidx];
			if (keymatches(arg, "arg") == 0) {
				(*argidx)++;
				if (*argidx <= (argc - 1) && argv[*argidx])
					arg = argv[*argidx];
				else
					arg = NULL;
			}
		}
		for (i = 0; i < KPARSER_NS_MAX; i++) {
			if (g_namespaces[i] == NULL)
				continue;
			if (ns && strcmp(g_namespaces[i]->name, ns))
				continue;
			new_json_obj(json);
			open_json_object(NULL);
			open_json_object(g_namespaces[i]->name);
			for (j = 0; j < g_namespaces[i]->arg_tokens_count;
					j++) {
				token = &g_namespaces[i]->arg_tokens[j];
				arg_name = token->key_name;
				if (token->default_template_token)
					token = token->default_template_token;
				if (!arg_name)
					arg_name = token->key_name;
				if (arg && keymatches(arg, arg_name))
					continue;
				open_json_object(arg_name);

				print_string(PRINT_ANY, "Type", "",
						arg_val_type_str[token->type]);
				print_uint(PRINT_ANY, "Mandatory", "",
						token->mandatory);
				print_string(PRINT_ANY, "Description", "",
						token->help_msg);
				open_json_array(PRINT_JSON,
						"Incompatible_keys");
				for (k = 0; k < sizeof(token->
					incompatible_keys) / sizeof(token->
						incompatible_keys[0]); k++) {
					if (!token->incompatible_keys[k])
						break;
					print_string(PRINT_JSON, NULL, "%s",
						token->incompatible_keys[k]);
				}
				close_json_array(PRINT_JSON, NULL);
				switch (token->type) {
				case KPARSER_ARG_VAL_STR:
					if (token->default_val)
						print_string(PRINT_ANY,
								"Default", "",
								token->
								default_val);
					else
						print_string(PRINT_ANY,
								"Default", "",
								empty);
					print_uint(PRINT_ANY, "Maxlen", "",
							token->str_arg_len_max);
					break;
				case KPARSER_ARG_VAL_U8:
				case KPARSER_ARG_VAL_U16:
				case KPARSER_ARG_VAL_U32:
				case KPARSER_ARG_VAL_U64:
					print_uint(PRINT_ANY, "Min", "",
							token->min_value);
					print_uint(PRINT_ANY, "Default", "",
							token->def_value);
					print_uint(PRINT_ANY, "Max", "",
							token->max_value);
					break;
				case KPARSER_ARG_VAL_SET:
					open_json_array(PRINT_JSON, "set");
					for (k = 0; k < token->value_set_len;
							k++) {
						print_string(PRINT_ANY, NULL,
								"%s",
							token->value_set[k].
							set_value_str);
						if (token->value_set[k].
								set_value_enum
								==
								token->
								def_value_enum)
							default_set_value =
							token->value_set[k].
							set_value_str;
					}
					close_json_array(PRINT_JSON, NULL);
					print_string(PRINT_ANY, "Default", "",
							default_set_value);
					break;
				case KPARSER_ARG_VAL_BOOL:
				case KPARSER_ARG_VAL_FLAG:
				case KPARSER_ARG_VAL_ARRAY:
				case KPARSER_ARG_VAL_HYB_KEY_NAME:
				case KPARSER_ARG_VAL_HYB_KEY_ID:
				default:
					break;
				}
				close_json_object();
				if (arg)
					break;
			}
			close_json_object();
			close_json_object();
			delete_json_obj();
			if (arg && j == g_namespaces[i]->arg_tokens_count)
				fprintf(stream,
					"\n\t{`%s`:invalid arg name}", arg);
		}
	}
}

int do_kparser(int argc, char **argv)
{
	int argidx = 0;
	int i = 0;

	usage = usage_text;
	if (json)
		usage = usage_json;

	if (argc < 1) {
		usage(stderr, true, 0, NULL, NULL, false, false);
		return -EINVAL;
	}

	if (keymatches(*argv, "help") == 0) {
		argidx++;
		usage(stdout, true, argc, &argidx, argv, false, false);
		return 0;
	}

	if (genl_init_handle(&genl_rth, KPARSER_GENL_NAME, &genl_family)) {
		fprintf(stderr, "genl_init_handle() failed!\n");
		return -EIO;
	}

	// scan for available flags
	for (argidx = 0; argidx < argc; argidx++) {
		if (!argv[argidx] || (argv[argidx][0] != '-'))
			continue;
		for (i = 0 ; i < ARRAY_SIZE(cliflags); i++) {
			if (keymatches(argv[argidx], cliflags[i].flagname) ==
					0) {
				cliflag |= cliflags[i].flagvalue;
				break;
			}
		}
		if (i == ARRAY_SIZE(cliflags)) {
			fprintf(stderr, "Invalid flag `%s` in cmdline\n"
					"check \"%s parser help flags\" "
					"for all the available flags.\n",
					argv[argidx], progname);
			return -EINVAL;
		}
	}

	argidx = 0;
	i = 0;
	do {
		if (argc == 0 || argidx >= argc || !argv || !argv[argidx])
			break;

		if (argv[argidx][0] == '-') {
			argidx++;
			continue;
		}

		if (keymatches(argv[argidx], cli_ops[i].op_name) == 0) {
			argidx++;
			return __do_cli(cli_ops[i].op, argc, &argidx,
				      (const char **) argv);
		}

		if (++i == ARRAY_SIZE(cli_ops))
			break;
	} while (1);

	fprintf(stderr, "Invalid operation: %s\n", argv[argidx]);
	usage(stderr, false, 0, NULL, NULL, true, false);
	fprintf(stderr, "Try \"%s parser help\" for more details\n", progname);
	return -EINVAL;
}
