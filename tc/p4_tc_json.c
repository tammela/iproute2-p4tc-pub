#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include "cjson_utils.h"
#include "p4_tc_json.h"
#include "p4_types.h"
#include <json_print.h>

#define SCOPE_CB ("ControlBlock")
#define SCOPE_GLOBAL ("Global")
#define SCOPE_TABLE_AND_DEFAULT ("TableAndDefault")
#define SCOPE_TABLE_ONLY ("TableOnly")
#define SCOPE_DEFAULT_ONLY ("DefaultOnly")

__u32 p4tc_find_action_scope(struct actions_list *action)
{
	if (strncmp(action->action_scope, SCOPE_GLOBAL, P4_TC_NAME_LEN) == 0)
		return P4_TC_JSON_ACT_SCOPE_GLOBAL;

	return P4_TC_JSON_ACT_SCOPE_CB;
}

static int json_parse_table_actions_data(cJSON *data_cjson,
					 struct action_data *data)
{
	char *name = NULL;
	char *type = NULL;
	int width;
	int id;
	int ret = 0;

//	printf("action data, looking at: \n<%s>\n", cJSON_Print(data_cjson));
	ret = cjson_get_string(data_cjson,
			       JSON_TABLE_LIST_TABLE_ACTION_DATA_NAME, &name);
	if (ret) {
		fprintf(stderr, "Failed to parse action_data attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_NAME);
		return -1;
	}
	ret |= cjson_get_string
		(data_cjson, JSON_TABLE_LIST_TABLE_ACTION_DATA_TYPE, &type);
	ret = cjson_get_int(data_cjson, JSON_TABLE_LIST_TABLE_ACTION_DATA_ID,
			    &id);
	if (ret) {
		fprintf(stderr, "Failed to parse action_data attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_ID);
		return -1;
	}

	ret = cjson_get_int(data_cjson, JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH,
			    &width);
	if (ret) {
		fprintf(stderr, "Failed to parse action_data attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH);
		return -1;
	}

	strncpy(data->name, name, P4_TC_NAME_LEN - 1);
	data->name[P4_TC_NAME_LEN - 1] = '\0';
	strncpy(data->type, type, P4_TC_NAME_LEN - 1);
	data->type[P4_TC_NAME_LEN - 1] = '\0';
	data->id = id;
	data->width = width;
	return 0;
}

static int json_parse_table_actions(cJSON *action_cjson,
				    struct actions_list *action)
{
	struct action_data *action_data_temp = NULL;
	cJSON *action_data_cjson = NULL;
	char *action_scope = NULL;
	char *name = NULL;
	int id;
	int ret;

	ret = cjson_get_string(action_cjson, JSON_TABLE_LIST_TABLE_ACTION_NAME,
			       &name);
	if (ret) {
		fprintf(stderr, "Failed to parse action attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_NAME);
		return -1;
	}

	ret = cjson_get_string (action_cjson,
				JSON_TABLE_LIST_TABLE_ACTION_SCOPE,
				&action_scope);
	if (ret) {
		fprintf(stderr, "Failed to parse action attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_SCOPE);
		return -1;
	}

	ret = cjson_get_int(action_cjson, JSON_TABLE_LIST_TABLE_ACTION_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse action attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_ID);
		return -1;
	}

	strncpy(action->name, name, P4_TC_NAME_LEN - 1);
	action->name[P4_TC_NAME_LEN - 1] = '\0';

	strncpy(action->action_scope, action_scope, P4_TC_NAME_LEN - 1);
	action->action_scope[P4_TC_NAME_LEN - 1] = '\0';
	action->id = id;
	ret = cjson_get_object(action_cjson, JSON_TABLE_LIST_TABLE_ACTION_DATA,
			       &action_data_cjson);
	if (ret) {
		fprintf(stderr, "Fail parse action attr:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA,
			cJSON_Print(action_cjson));
		return -1;
	}
	if (!action_data_cjson)
		return 0;

	cJSON *data_cjson = NULL;

	cJSON_ArrayForEach(data_cjson, action_data_cjson) {
		action_data_temp = calloc(1, sizeof(*action_data_temp));
		if (!action_data_temp) {
			fprintf(stderr, "No resources for action\n");
			goto cleanup_action_data;
		}

		ret = json_parse_table_actions_data(data_cjson,
						    action_data_temp);
		if (ret) {
			fprintf(stderr, "bad action data\n<%s>\n",
				cJSON_Print(action_data_cjson));
			free(action_data_temp);
			goto cleanup_action_data;
		}

		if (action->data)
			action_data_temp->next = action->data;
		action->data = action_data_temp;
		action->action_data_count++;
	}

	return 0;
cleanup_action_data:
	FREE_LIST(action->data);
	action->data = NULL;
	return -1;
}

static int json_parse_table_key_fields(cJSON *key_fields_cjson,
				struct key_fields_list *key_fields)
{
	int width;
	char *name = NULL;
	char *type = NULL;
	char *match_type = NULL;
	int id;
	int ret;

	ret = cjson_get_string(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_NAME,
			       &name);
	if (ret) {
		fprintf(stderr, "Failed to parse key name:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_NAME,
			cJSON_Print(key_fields_cjson));
		return -1;
	}

	ret = cjson_get_string(key_fields_cjson,
			       JSON_TABLE_LIST_TABLE_KEY_MATCH_TYPE,
			       &match_type);
	if (ret) {
		fprintf(stderr, "Failed to parse match type:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_MATCH_TYPE,
			cJSON_Print(key_fields_cjson));
		return -1;
	}

	ret = cjson_get_string(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_TYPE,
			       &type);
	if (ret) {
		fprintf(stderr, "Failed to parse match type:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_MATCH_TYPE,
			cJSON_Print(key_fields_cjson));
		return -1;
	}

	ret = cjson_get_int(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_FIELD_ID,
			    &id);
	if (ret) {
		fprintf(stderr, "Failed to parse match keyid:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_FIELD_ID,
			cJSON_Print(key_fields_cjson));
		return -1;
	}

	ret = cjson_get_int(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_WIDTH,
			    &width);
	if (ret) {
		fprintf(stderr, "Failed to parse key width:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_WIDTH,
			cJSON_Print(key_fields_cjson));
		return -1;
	}

#if zero_for_now
	ret |= cjson_get_int
		(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_PARSER_INSTANCE,
		 &parser_instance);
	ret |= cjson_get_bool
		(key_fields_cjson, JSON_TABLE_LIST_TABLE_KEY_MANDATORY, &mandatory);
#endif

	strncpy(key_fields->name, name, P4_TC_NAME_LEN - 1);
	key_fields->name[P4_TC_NAME_LEN - 1] = '\0';
	strncpy(key_fields->type, type, P4_TC_NAME_LEN - 1);
	key_fields->type[P4_TC_NAME_LEN - 1] = '\0';
#if zero_for_now
	key_fields->mandatory = mandatory;
	key_fields->parser_instance = parser_instance;
#endif
	key_fields->width = width;
	key_fields->id = id;
	/*TODO: Add logic to retrieve enum*/
	key_fields->match_type = 0;
	return 0;
}

static int json_parse_table(cJSON *table_cjson, struct table *table)
{
	struct key_fields_list *key_field_temp = NULL;
	struct actions_list *action_temp = NULL;
	cJSON *key_fields_cjson = NULL;
	cJSON *actions_cjson = NULL;
	char *name = NULL;
	int ksize = 0, size = 0;
	int id = 0;
	int ret;

	ret = cjson_get_string(table_cjson, JSON_TABLE_LIST_TABLE_NAME, &name);
	if (ret) {
		fprintf(stderr, "Failed to parse table name:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_NAME,
			cJSON_Print(table_cjson));
		return -1;
	}

	ret = cjson_get_int(table_cjson, JSON_TABLE_LIST_TABLE_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse table id:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_ID,
			cJSON_Print(table_cjson));
		return -1;
	}

	ret = cjson_get_int(table_cjson, JSON_TABLE_LIST_TABLE_SIZE, &size);
	if (ret) {
		fprintf(stderr, "Failed to parse table size:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_SIZE,
			cJSON_Print(table_cjson));
		return -1;
	}

	ret = cjson_get_int(table_cjson, JSON_TABLE_LIST_TABLE_KEY_SIZE,
			    &ksize);

	if (ret) {
		fprintf(stderr, "Failed to parse table keysz:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_SIZE,
			cJSON_Print(table_cjson));
		return -1;
	}

	strncpy(table->name, name, P4_TC_NAME_LEN - 1);
	table->name[P4_TC_NAME_LEN - 1] = '\0';

	table->id = id;
	table->size = size;
	table->ksize = ksize;

	ret = cjson_get_object(table_cjson, JSON_TABLE_LIST_TABLE_KEYS,
			       &key_fields_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_TABLE_LIST_TABLE_KEYS);
		return -1;
	}

	cJSON *key_field_cjson = NULL;

	cJSON_ArrayForEach(key_field_cjson, key_fields_cjson) {
		key_field_temp	= calloc(1, sizeof(*key_field_temp));
		if (!key_field_temp) {
			fprintf(stderr, "No resources for keys\n");
			goto cleanup_key_fields;
		}
		ret = json_parse_table_key_fields(key_field_cjson,
						  key_field_temp);
		if (ret) {
			fprintf(stderr, "key Object not found\n");
			free(key_field_temp);
			goto cleanup_key_fields;
		}

		if (table->key_fields)
			key_field_temp->next = table->key_fields;
		table->key_fields = key_field_temp;
		table->key_fields_count++;
	}

	ret = cjson_get_object(table_cjson, JSON_TABLE_LIST_TABLE_ACTIONS,
			       &actions_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_TABLE_LIST_TABLE_ACTIONS);
		return -1;
	}

	cJSON *action_cjson = NULL;

	cJSON_ArrayForEach(action_cjson, actions_cjson) {
		action_temp = calloc(1, sizeof(*action_temp));
		if (!action_temp) {
			fprintf(stderr, "No resources for actions\n");
			goto cleanup_actions;
		}
		ret = json_parse_table_actions(action_cjson,
					       action_temp);
		if (ret) {
			fprintf(stderr, "action Object not found\n");
			free(action_temp);
			goto cleanup_actions;
		}

		if (table->actions)
			action_temp->next = table->actions;
		table->actions = action_temp;
		table->actions_count++;
	}

	return 0;

cleanup_actions:
	FREE_LIST(table->actions);
	table->actions = NULL;
cleanup_key_fields:
	FREE_LIST(table->key_fields);
	table->key_fields = NULL;
	return -1;
}

static int json_parse_tables(cJSON *root, struct p4_tc_pipeline *pipeline_info)
{
	struct table_list *table_temp = NULL;
	cJSON *tables_cjson = NULL;
	int ret;

	ret = cjson_get_object(root, JSON_TABLE, &tables_cjson);
	if (ret) {
		fprintf(stderr, "JSON object not found\n");
		return -1;
	}
	cJSON *table_cjson = NULL;

	cJSON_ArrayForEach(table_cjson, tables_cjson) {
		table_temp = calloc(1, sizeof(*table_temp));
		if (!table_temp) {
			fprintf(stderr, "No resources: %s\n", __func__);
			goto cleanup_tables;
		}
		ret = json_parse_table(table_cjson, &table_temp->table);
		if (ret) {
			fprintf(stderr, "Failed to parse tables\n");
			free(table_temp);
			goto cleanup_tables;
		}
		if (pipeline_info->mat_tables)
			table_temp->next = pipeline_info->mat_tables;
		pipeline_info->mat_tables = table_temp;
		pipeline_info->mat_tables_count++;
	}

	return 0;

cleanup_tables:
	FREE_LIST(pipeline_info->mat_tables);
	pipeline_info->mat_tables = NULL;
	return -1;
}

static int json_parse_ext_inst_data(cJSON *insts_data_cjson,
				    struct extern_insts_data *insts_data)
{
	char *name = NULL;
	char *type = NULL;
	int width;
	int id = 0;
	int ret;

	ret = cjson_get_string(insts_data_cjson,
			       JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_NAME,
			       &name);
	if (ret) {
		fprintf(stderr, "Failed to parse inst param name:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_NAME,
			cJSON_Print(insts_data_cjson));
		return -1;
	}

	ret = cjson_get_int(insts_data_cjson,
			    JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse insts param id:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_ID,
			cJSON_Print(insts_data_cjson));
		return -1;
	}

	ret |= cjson_get_string
		(insts_data_cjson, JSON_TABLE_LIST_TABLE_ACTION_DATA_TYPE, &type);
	ret = cjson_get_int(insts_data_cjson,
			    JSON_TABLE_LIST_TABLE_ACTION_DATA_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse insts param attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_ID);
		return -1;
	}

	ret = cjson_get_int(insts_data_cjson,
			    JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH, &width);
	if (ret) {
		fprintf(stderr, "Failed to parse action_data attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH);
		return -1;
	}

	strncpy(insts_data->name, name, P4_TC_NAME_LEN - 1);
	insts_data->name[P4_TC_NAME_LEN - 1] = '\0';
	strncpy(insts_data->type, type, P4_TC_NAME_LEN - 1);
	insts_data->type[P4_TC_NAME_LEN - 1] = '\0';

	insts_data->id = id;

	return 0;
}

static int json_parse_ext_insts_list(cJSON *insts_cjson,
				    struct extern_insts_list *inst)
{
	cJSON *insts_data_cjson = NULL, *insts_data_iter_cjson = NULL;
	struct extern_insts_data *insts_data_temp = NULL;
	char *name = NULL;
	int id = 0;
	int ret;

	ret = cjson_get_string(insts_cjson, JSON_EXTERN_LIST_EXTERN_INSTS_NAME,
			       &name);
	if (ret) {
		fprintf(stderr, "Failed to parse insts name:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_NAME,
			cJSON_Print(insts_cjson));
		return -1;
	}

	ret = cjson_get_int(insts_cjson, JSON_EXTERN_LIST_EXTERN_INSTS_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse insts id:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_ID,
			cJSON_Print(insts_cjson));
		return -1;
	}

	strncpy(inst->name, name, P4_TC_NAME_LEN - 1);
	inst->name[P4_TC_NAME_LEN - 1] = '\0';

	inst->id = id;

	ret = cjson_get_object(insts_cjson,
			       JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS,
			       &insts_data_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS);
		return -1;
	}

	cJSON_ArrayForEach(insts_data_iter_cjson, insts_data_cjson) {
		insts_data_temp	= calloc(1, sizeof(*insts_data_temp));
		if (!insts_data_temp) {
			fprintf(stderr, "No resources for instanes\n");
			goto cleanup_insts;
		}
		ret = json_parse_ext_inst_data(insts_data_iter_cjson,
					       insts_data_temp);
		if (ret) {
			fprintf(stderr, "key Object not found\n");
			free(insts_data_temp);
			goto cleanup_insts;
		}

		if (inst->data)
			insts_data_temp->next = inst->data;
		inst->data = insts_data_temp;
		inst->insts_data_count++;
	}

	return 0;

cleanup_insts:
	FREE_LIST(inst->data);
	inst->data = NULL;
	return -1;
}

static int json_parse_extern(cJSON *extern_cjson, struct externs_list *ext)
{
	cJSON *insts_cjson = NULL;
	char *name = NULL;
	int id = 0;
	struct extern_insts_list *inst_temp;
	int ret;

	ret = cjson_get_string(extern_cjson, JSON_EXTERN_LIST_EXTERN_NAME, &name);
	if (ret) {
		fprintf(stderr, "Failed to parse table name:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_NAME,
			cJSON_Print(extern_cjson));
		return -1;
	}

	ret = cjson_get_int(extern_cjson, JSON_EXTERN_LIST_EXTERN_ID, &id);
	if (ret) {
		fprintf(stderr, "Failed to parse table id:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_ID,
			cJSON_Print(extern_cjson));
		return -1;
	}

	strncpy(ext->name, name, P4_TC_NAME_LEN - 1);
	ext->name[P4_TC_NAME_LEN - 1] = '\0';

	ext->id = id;

	ret = cjson_get_object(extern_cjson, JSON_EXTERN_LIST_EXTERN_INSTS,
			       &insts_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_TABLE_LIST_TABLE_KEYS);
		return -1;
	}

	cJSON *inst_cjson = NULL;

	cJSON_ArrayForEach(inst_cjson, insts_cjson) {
		inst_temp	= calloc(1, sizeof(*inst_temp));
		if (!inst_temp) {
			fprintf(stderr, "No resources for instanes\n");
			goto cleanup_insts;
		}
		ret = json_parse_ext_insts_list(inst_cjson, inst_temp);
		if (ret) {
			fprintf(stderr, "key Object not found\n");
			free(inst_temp);
			goto cleanup_insts;
		}

		if (ext->insts)
			inst_temp->next = ext->insts;
		ext->insts = inst_temp;
		ext->insts_count++;
	}

	return 0;

cleanup_insts:
	FREE_LIST(ext->insts);
	ext->insts = NULL;
	return -1;
}

static int json_parse_externs(cJSON *root, struct p4_tc_pipeline *pipeline_info)
{
	struct externs_list *extern_temp = NULL;
	cJSON *externs_cjson = NULL;
	int ret;

	ret = cjson_get_optional_object(root, JSON_EXTERNS, &externs_cjson);
	if (ret)
		return -ENOENT;

	cJSON *extern_cjson = NULL;

	cJSON_ArrayForEach(extern_cjson, externs_cjson) {
		extern_temp = calloc(1, sizeof(*extern_temp));
		if (!extern_temp) {
			fprintf(stderr, "No resources: %s\n", __func__);
			goto cleanup_externs;
		}
		ret = json_parse_extern(extern_cjson, extern_temp);
		if (ret) {
			fprintf(stderr, "Failed to parse externs\n");
			free(extern_temp);
			goto cleanup_externs;
		}
		if (pipeline_info->externs)
			extern_temp->next = pipeline_info->externs;
		pipeline_info->externs = extern_temp;
		pipeline_info->externs_count++;
	}

	return 0;

cleanup_externs:
	FREE_LIST(pipeline_info->mat_tables);
	pipeline_info->mat_tables = NULL;
	return -1;
}

static void p4_tc_print_action(struct actions_list *action, FILE *fp)
{
	fprintf(fp, "    action: %s(id %d) with scope %s and %d params\n",
		action->name, action->id, action->action_scope,
		action->action_data_count);
}

static const char *p4_tc_print_keyfield_type(enum p4_tc_match_type mtype, FILE *fp)
{
	switch (mtype) {
		case P4_TC_MATCH_TYPE_EXACT:
			return "exact";
		case P4_TC_MATCH_TYPE_TERNARY:
			return "ternary";
		case P4_TC_MATCH_TYPE_LPM:
			return "lpm";
		default:
			break;
	}

	return "unknown";
}

static void p4_tc_print_keyfield_data(struct key_fields_list *kf, __u8 *k, __u8 *m, int rlen, FILE *fp,
				      const char *prefix)
{
	struct p4_type_value v = {.value = k, .mask = m, .bitsz = kf->width};
	struct p4_type_s *t = get_p4type_byname(kf->type);
	__u32 bsz = kf->width;
	__u32 Bsz = bsz/8;
	__u32 rB = bsz%8;
	__u32 tot = Bsz + (rB?1:0);
	int bsize = 256;
	char kfld[bsize];
	char *b;
	int i, l;

	if (t) {
		t->print_p4t(" fieldval ", "fieldval", &v, fp);
		return;
	}

	//XXX: Type unknown...
	if (bsz > rlen) {
		printf("We have an error bsz %d > remainder of data %d\n", bsz, rlen);
		return;
	}

	b = kfld;
	l = snprintf(b, bsize, "%s", "0x");
	bsize -= l;
	b += l;

	for (i = tot - 1; i >= 0; i--) {
		__u8 ch = k[i] & 0xff;
		l = snprintf(b, bsize, "%02x", ch);
		bsize -= l;
		b += l;
	}

	l = snprintf(b, bsize, "%s", "/0x");
	bsize -= l;
	b += l;

	for (i = tot - 1; i >= 0; i--) {
		__u8 ch = m[i] & 0xff;
		l = snprintf(b, bsize, "%02x", ch);
		bsize -= l;
		b += l;
	}

	print_string(PRINT_ANY, "fieldval ", " value: %s", kfld);
}

static void p4_tc_print_keyfield(struct key_fields_list *field, FILE *fp)
{
	print_string(PRINT_ANY, "keyfield", "     %s ", field->name);
	print_uint(PRINT_ANY, "id", "id:%d ", field->id);
	print_uint(PRINT_ANY, "width", "size:%db ", field->width);
	print_string(PRINT_ANY, "type", "type:%s", field->type);
	print_string(PRINT_ANY, "match_type", " %s", p4_tc_print_keyfield_type(field->match_type, fp));
}

void p4_tc_print_table(struct table *t, FILE *fp)
{
	struct table *tbl = t;
	struct actions_list *actions = tbl->actions;
	struct key_fields_list *key_list = tbl->key_fields;

	fprintf(fp, "  Table: %s(id %d) with %d keyfields (size %d) and %d actions \n",
		tbl->name, tbl->id, tbl->key_fields_count,  tbl->ksize,
		tbl->actions_count);

	print_string(PRINT_FP, NULL, "   KEY\n", NULL);
	while (key_list) {
		p4_tc_print_keyfield(key_list, fp);
		print_nl();
		key_list = key_list->next;
	}

	while (actions) {
		p4_tc_print_action(actions, fp);
		actions = actions->next;
	}
}

static struct key_fields_list *p4tc_find_table_keyfield_byid(struct table *t, __u32 keyid)
{
	struct key_fields_list *key_fields = t->key_fields;

	while (key_fields) {
		if (keyid == key_fields->id)
			return key_fields;

		key_fields = key_fields->next;
	}

	return NULL;
}

#define DEF_KEY_SZ 16 /* size of __uint128_t */
void p4_tc_print_key_data(struct table *t, __u8 *key, __u8 *mask, int blen, FILE *fp, const char *prefix)
{
	struct key_fields_list *key_list = t->key_fields;
	int rlen = t->ksize;
	__uint128_t k = 0;
	__uint128_t m = 0;
	__u32 shiftv = 0;
	int kfid = 1;
	struct key_fields_list *kf;
	size_t copy_sz;
	int redo_copy;

	//printf("div %d mod %d\n", blen/DEF_KEY_SZ, blen%DEF_KEY_SZ);
	redo_copy = blen/DEF_KEY_SZ;
	copy_sz = blen%DEF_KEY_SZ;
	memcpy(&k, key, copy_sz);
	memcpy(&m, mask, copy_sz);

	open_json_array(PRINT_JSON, "key");
	print_string(PRINT_FP, NULL, "    entry key\n", NULL);

	while (key_list) {
		kf = p4tc_find_table_keyfield_byid(t, kfid);
		if (!kf) {
			fprintf(stderr, "error: failed to find keyfield ID %d\n", kfid);
			close_json_object();
			close_json_array(PRINT_JSON, NULL);
			return;
		}

		shiftv = kf->width;
		//printf("shift for next field from field %s is %db\n", kf->name, shiftv);
		open_json_object(NULL);
		p4_tc_print_keyfield(kf, fp);
		p4_tc_print_keyfield_data(kf, (__u8 *)&k, (__u8 *)&m, rlen, fp, prefix);
		rlen -= kf->width;
		if (rlen < 0) {
			fprintf(stderr, "error: Insufficient key blob %d/%d\n", rlen, t->ksize);
			close_json_object();
			close_json_array(PRINT_JSON, NULL);
			return;
		}

		close_json_object();
		print_nl();
		kfid++;
		if (kfid > t->key_fields_count)
			break;

		//XXX: wont work if we have a field straddling two 128 bit locations
		if (redo_copy) {
			shiftv = 0;
			redo_copy -= 1;
			copy_sz = DEF_KEY_SZ;
			key = key + copy_sz;
			mask = mask + copy_sz;
			memcpy(&k, key, copy_sz);
			memcpy(&m, mask, copy_sz);
		}

		k = k >> shiftv;
		m = m >> shiftv;
		key_list = key_list->next;
	}

	close_json_array(PRINT_JSON, NULL);
}

static struct extern_insts_list *
__p4tc_find_extern_inst(struct externs_list *e, const char *instname)
{
	struct extern_insts_list *iter = e->insts;

	while (iter) {
		if (!strcmp(instname, iter->name))
			return iter;

		iter = iter->next;
	}

	return NULL;
}

struct extern_insts_list *
p4tc_find_extern_inst(struct p4_tc_pipeline *p, const char *extname,
		      const char *instname)
{
	struct externs_list *iter = p->externs;

	while (iter) {
		if (!strcmp(extname, iter->name))
			return __p4tc_find_extern_inst(iter, instname);

		iter = iter->next;
	}

	return NULL;
}

struct extern_insts_data *
p4tc_find_extern_data(struct extern_insts_list *insts, const char *param_name)
{
	struct extern_insts_data *iter = insts->data;

	while (iter) {
		if (!strcmp(param_name, iter->name))
			return iter;

		iter = iter->next;
	}

	return NULL;
}

struct action_data *p4tc_find_act_data(struct actions_list *action,
				       const char *data_name)
{
	struct action_data *data = action->data;
	while (data) {
		if (!strcmp(data_name, data->name))
		    return data;

		data = data->next;
	}

	return NULL;
}

struct actions_list *p4tc_find_table_act(struct table *tbl,
					 const char *act_name)
{
	struct actions_list *actions = tbl->actions;

	while (actions) {
		if (!strcmp(act_name, actions->name))
		    return actions;

		actions = actions->next;
	}

	return NULL;
}

struct actions_list *p4tc_find_act(struct p4_tc_pipeline *p,
				   const char *act_name)
{
	struct table_list *mat_tables = p->mat_tables;
	struct actions_list *action;

	while (mat_tables) {
		action = p4tc_find_table_act(&mat_tables->table, act_name);
		if (action)
			return action;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

/*XXX: ignore keyid for now until json support multiple keys */
struct key_fields_list *p4tc_find_table_keyfield(struct table *t, __u32 keyid,
						 const char *key_field_name)
{
	struct key_fields_list *key_fields = t->key_fields;

	while (key_fields) {
		if (!strcmp(key_field_name, key_fields->name))
			return key_fields;

		key_fields = key_fields->next;
	}

	return NULL;
}

struct table *p4tc_find_table_byid(struct p4_tc_pipeline *p,
				   int tab_id)
{
	struct table_list *mat_tables = p->mat_tables;

	while (mat_tables) {
		if (tab_id == mat_tables->table.id)
			return &mat_tables->table;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

struct table *p4tc_find_table(struct p4_tc_pipeline *p, const char *tab_name)
{
	struct table_list *mat_tables = p->mat_tables;

	while (mat_tables) {
		if (!strcmp(tab_name, mat_tables->table.name))
			return &mat_tables->table;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

void p4_tc_print_pipeline(struct p4_tc_pipeline *p, FILE *fp)
{
	struct p4_tc_pipeline *pipe = p;
	struct table_list *mat_tables = p->mat_tables;
	struct table_list *mat;

	fprintf(fp, "Pipeline: %s(id %d) with %d tables\n",
		pipe->name, pipe->id, pipe->mat_tables_count);
	/* iterate the tables and print them */
	while (mat_tables) {
		mat =  pipe->mat_tables;
		p4_tc_print_table(&mat->table, stdout);
		mat_tables = pipe->mat_tables->next;
	}
}

static char *get_introspection_path(void)
{
	if (!getenv(ENV_VAR))
		return INTROSPECTION_PATH;

	return getenv(ENV_VAR);
}

/*
 * This function parses JSON describing tables for a P4 program
 */
struct p4_tc_pipeline *p4_tc_import_json(const char *pname)
{
	struct p4_tc_pipeline *pipeline_info;
	char *introspection_dir = NULL;
	char json_file_path[PATH_MAX];
	char *json_file_buffer;
	struct stat stat_b;
	size_t file_size;
	size_t num_items;
	cJSON *root;
	char *name;
	FILE *file;
	int ret;
	int fd;

	introspection_dir = get_introspection_path();
	if (!pname) {
		fprintf(stderr, "Must specify pipeline name for introspection\n");
		return NULL;
	}

	if (snprintf(json_file_path, PATH_MAX, "%s/%s.json", introspection_dir,
		     pname) >= PATH_MAX) {
		fprintf(stderr, "Pipeline name too long\n");
		return NULL;
	}

	file = fopen(json_file_path, "r");
	if (file == NULL) {
		fprintf(stderr, "XUnable to open introspection file: <%s>\n",
			json_file_path);
		return NULL;
	}

	pipeline_info = calloc(1, sizeof(*pipeline_info));
	if (!pipeline_info) {
		fprintf(stderr, "No resources\n");
		return NULL;
	}

	fd = fileno(file);
	fstat(fd, &stat_b);
	file_size = stat_b.st_size + 1;
	json_file_buffer = calloc(1, file_size);
	if (!json_file_buffer) {
		fprintf(stderr, "Could not alloc memory for json file <%s>\n",
			json_file_path);
		goto json_file_buffer_alloc_err;
	}

	num_items = fread(json_file_buffer, stat_b.st_size, 1, file);
	if (num_items != 1) {
		if (ferror(file)) {
			fprintf(stderr, "Error reading json file buffer <%s>\n",
				json_file_path);
			goto json_file_fread_err;
		}
	}

	root = cJSON_Parse(json_file_buffer);
	if (!root) {
		fprintf(stderr, "Error(%s) parsing json file <%s>\n",
			cJSON_GetErrorPtr(), json_file_path);
		goto json_file_parse_err;
	}

	ret = cjson_get_string(root, JSON_PIPELINE_NAME, &name);
	if (ret) {
		fprintf(stderr, "Failed to parse pipeline attr <%s>\n",
			JSON_PIPELINE_NAME);
		goto json_file_parse_tables_err;
	}
	strncpy(pipeline_info->name, name, P4_TC_NAME_LEN - 1);
	pipeline_info->name[P4_TC_NAME_LEN - 1] = '\0';

	ret = json_parse_tables(root, pipeline_info);
	if (ret)
		goto json_file_parse_tables_err;

	ret = json_parse_externs(root, pipeline_info);
	if (ret && ret != -ENOENT)
		goto json_file_parse_tables_err;

	cJSON_Delete(root);
	free(json_file_buffer);
	fclose(file);

	return pipeline_info;

json_file_parse_tables_err:
	cJSON_Delete(root);
json_file_parse_err:
json_file_fread_err:
	free(json_file_buffer);
json_file_buffer_alloc_err:
	fclose(file);
	return NULL;
}
