/*
* p4tc_json.c                P4 TC JSON
*
*         This program is free software; you can distribute it and/or
*         modify it under the terms of the GNU General Public License
*         as published by the Free Software Foundation; either version
*         2 of the License, or (at your option) any later version.
*
* Copyright (c) 2022-2024, Mojatatu Networks
* Copyright (c) 2022-2024, Intel Corporation.
* Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
*              Victor Nogueira <victor@mojatatu.com>
*              Pedro Tammela <pctammela@mojatatu.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include "cjson_utils.h"
#include "p4tc_json.h"
#include "p4_types.h"
#include <json_print.h>
#include "utils.h"

#define SCOPE_CB ("ControlBlock")
#define SCOPE_GLOBAL ("Global")
#define SCOPE_TABLE_AND_DEFAULT ("TableAndDefault")
#define SCOPE_TABLE_ONLY ("TableOnly")
#define SCOPE_DEFAULT_ONLY ("DefaultOnly")

static void
p4tc_json_free_extern_inst(struct p4tc_json_extern_insts_data *ext_inst)
{
	free(ext_inst);
}

static void
p4tc_json_free_extern_insts(struct p4tc_json_extern_insts_list *ext_insts)
{
	struct p4tc_json_extern_insts_data *ext_inst = ext_insts->data;
	struct p4tc_json_extern_insts_data *ext_inst_tmp;

	while (ext_inst) {
		ext_inst_tmp = ext_inst;
		ext_inst = ext_inst->next;
		p4tc_json_free_extern_inst(ext_inst_tmp);
	}

	free(ext_insts);
}

static void p4tc_json_free_extern(struct p4tc_json_externs_list *ext)
{
	struct p4tc_json_extern_insts_list *ext_inst, *ext_inst_tmp;

	ext_inst = ext->insts;
	while (ext_inst) {
		ext_inst_tmp = ext_inst;
		ext_inst = ext_inst->next;
		p4tc_json_free_extern_insts(ext_inst_tmp);
	}

	free(ext);
}

static void p4tc_json_free_key_field(struct p4tc_json_key_fields_list *key_field)
{
	free(key_field);
}

static void p4tc_json_free_action_data(struct p4tc_json_action_data *action)
{
	free(action);
}
static void p4tc_json_free_action(struct p4tc_json_actions_list *actions)
{
	struct p4tc_json_action_data *action = actions->data, *action_tmp;

	while (action) {
		action_tmp = action;
		action = action->next;
		p4tc_json_free_action_data(action_tmp);
	}

	free(actions);
}

static void p4tc_json_free_table(struct p4tc_json_table *table)
{
	struct p4tc_json_key_fields_list *key_fields, *key_fields_tmp;
	struct p4tc_json_actions_list *actions, *actions_tmp;

	key_fields = table->key_fields;
	while (key_fields) {
		key_fields_tmp = key_fields;
		key_fields = key_fields->next;
		p4tc_json_free_key_field(key_fields_tmp);
	}

	actions = table->actions;
	while (actions) {
		actions_tmp = actions;
		actions = actions->next;
		p4tc_json_free_action(actions_tmp);
	}
}

void p4tc_json_free_pipeline(struct p4tc_json_pipeline *pipeline_info)
{
	struct p4tc_json_externs_list *ext, *ext_tmp;
	struct p4tc_json_table_list *mat_tables = pipeline_info->mat_tables;
	struct p4tc_json_table_list *mat_tables_tmp;

	while (mat_tables) {
		mat_tables_tmp = mat_tables;
		p4tc_json_free_table(&mat_tables->table);
		mat_tables = mat_tables->next;
		free(mat_tables_tmp);
	}

	ext = pipeline_info->externs;
	while (ext) {
		ext_tmp = ext;
		ext = ext->next;
		p4tc_json_free_extern(ext_tmp);
	}

	free(pipeline_info);
}

__u32 p4tc_json_find_action(struct p4tc_json_actions_list *action)
{
	if (strncmp(action->action_scope, SCOPE_GLOBAL, P4TC_NAME_LEN) == 0)
		return P4TC_JSON_ACT_SCOPE_GLOBAL;

	return P4TC_JSON_ACT_SCOPE_CB;
}

static int json_parse_table_actions_data(cJSON *data_cjson,
					 struct p4tc_json_action_data *data,
					 int *runt_params_offset)
{
	char *dflt_val = NULL;
	bool runtime = false;
	char *name = NULL;
	char *type = NULL;
	int ret = 0;
	int width;
	int id;

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

	ret = cjson_get_optional_bool(data_cjson,
				      JSON_TABLE_LIST_TABLE_ACTION_DATA_RUNTIME,
				      &runtime);
	if (ret == -EINVAL) {
		fprintf(stderr, "Failed to parse action_data attr:<%s>\n",
			JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH);
		return -1;
	}

	if (runtime) {
		ret = cjson_get_string(data_cjson,
				       JSON_TABLE_LIST_TABLE_ACTION_DATA_DFLT_VAL,
				       &dflt_val);
		if (ret) {
			fprintf(stderr,
				"Failed to parse action_data attr:<%s>\n",
				JSON_TABLE_LIST_TABLE_ACTION_DATA_DFLT_VAL);
			return -1;
		}
	}

	strncpy(data->name, name, P4TC_NAME_LEN - 1);
	data->name[P4TC_NAME_LEN - 1] = '\0';
	strncpy(data->type, type, P4TC_NAME_LEN - 1);
	data->type[P4TC_NAME_LEN - 1] = '\0';
	data->id = id;
	data->width = width;
	data->runtime = runtime;
	data->offset_in_filter_fields = *runt_params_offset;

	if (runtime) {
		strncpy(data->dflt_val, dflt_val, P4TC_NAME_LEN - 1);
		*runt_params_offset += width;
	}

	return 0;
}

static int json_parse_table_actions(cJSON *action_cjson,
				    struct p4tc_json_actions_list *action,
				    int *runt_params_offset,
				    int *num_runt_params)
{
	struct p4tc_json_action_data *action_data_temp = NULL;
	struct p4tc_json_action_data *action_data_curr;
	cJSON *action_data_cjson = NULL;
	char *action_scope = NULL;
	char *name = NULL;
	int ret;
	int id;

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

	strncpy(action->name, name, P4TC_NAME_LEN - 1);
	action->name[P4TC_NAME_LEN - 1] = '\0';

	strncpy(action->action_scope, action_scope, P4TC_NAME_LEN - 1);
	action->action_scope[P4TC_NAME_LEN - 1] = '\0';
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

	action_data_curr = action->data;
	cJSON_ArrayForEach(data_cjson, action_data_cjson) {
		action_data_temp = calloc(1, sizeof(*action_data_temp));
		if (!action_data_temp) {
			fprintf(stderr, "No resources for action\n");
			goto cleanup_action_data;
		}

		ret = json_parse_table_actions_data(data_cjson,
						    action_data_temp,
						    runt_params_offset);
		if (ret) {
			fprintf(stderr, "bad action data\n<%s>\n",
				cJSON_Print(action_data_cjson));
			free(action_data_temp);
			goto cleanup_action_data;
		}

		if (action->data)
			action_data_curr->next = action_data_temp;
		else
			action->data = action_data_temp;

		*num_runt_params += (int)action_data_temp->runtime;

		action_data_curr = action_data_temp;
		action->action_data_count++;
	}

	return 0;
cleanup_action_data:
	FREE_LIST(action->data);
	action->data = NULL;
	return -1;
}

static int json_parse_table_key_matchtype(const char *match_type)
{
	if (strcmp(match_type, "exact") == 0)
		return P4TC_MATCH_TYPE_EXACT;

	if (strcmp(match_type, "lpm") == 0)
		return P4TC_MATCH_TYPE_LPM;

	if (strcmp(match_type, "ternary") == 0)
		return P4TC_MATCH_TYPE_TERNARY;

	return -1;
}

static int
json_parse_table_key_fields(cJSON *key_fields_cjson,
			    struct p4tc_json_key_fields_list *key_fields)
{
	char *match_type = NULL;
	char *name = NULL;
	char *type = NULL;
	int width;
	int ret;
	int id;

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

	ret = cjson_get_int(key_fields_cjson,
			    JSON_TABLE_LIST_TABLE_KEY_FIELD_ID,
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

	strncpy(key_fields->name, name, P4TC_NAME_LEN - 1);
	key_fields->name[P4TC_NAME_LEN - 1] = '\0';
	strncpy(key_fields->type, type, P4TC_NAME_LEN - 1);
	key_fields->type[P4TC_NAME_LEN - 1] = '\0';
#if zero_for_now
	key_fields->mandatory = mandatory;
	key_fields->parser_instance = parser_instance;
#endif
	key_fields->width = width;
	key_fields->id = id;
	key_fields->match_type = json_parse_table_key_matchtype(match_type);
	if (key_fields->match_type < 0) {
		fprintf(stderr, "Unknown match type %s\n", match_type);
		return -1;
	}
	return 0;
}

static int json_parse_table(cJSON *table_cjson, struct p4tc_json_table *table,
			    int *runt_params_offset)
{
	struct p4tc_json_key_fields_list *key_field_temp = NULL;
	struct p4tc_json_actions_list *action_temp = NULL;
	struct p4tc_json_key_fields_list *key_field_prev = NULL;
	struct p4tc_json_actions_list *action_prev = NULL;
	cJSON *key_fields_cjson = NULL;
	cJSON *actions_cjson = NULL;
	int ksize = 0, size = 0;
	char *permissions_str;
	char *name = NULL;
	__u32 bitoff = 0;
	int permissions;
	int id = 0;
	int i = 1;
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

	ret = cjson_get_int(table_cjson, JSON_TABLE_LIST_TABLE_KEY_SIZE,
			    &ksize);

	if (ret) {
		fprintf(stderr, "Failed to parse table keysz:<%s> for:\n<%s>\n",
			JSON_TABLE_LIST_TABLE_KEY_SIZE,
			cJSON_Print(table_cjson));
		return -1;
	}

	strncpy(table->name, name, P4TC_NAME_LEN - 1);
	table->name[P4TC_NAME_LEN - 1] = '\0';

	table->id = id;
	table->size = size;
	table->ksize = ksize;

	ret = cjson_get_optional_string(table_cjson,
					JSON_TABLE_LIST_TABLE_PERMISSIONS,
					&permissions_str);
	if (!ret) {
		if (get_u16((__u16 *)&permissions, permissions_str, 0) < 0) {
			fprintf(stderr,
				"Failed to convert permissions to u16 for :\n<%s>\n",
				cJSON_Print(table_cjson));
			return -1;
		}

		table->permissions = permissions;
	}

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

		key_field_temp->bitoff = bitoff;
		key_field_temp->order = i;
		if (key_field_prev)
			key_field_prev->next = key_field_temp;
		else
			table->key_fields = key_field_temp;

		table->key_fields_count++;
		key_field_prev = key_field_temp;
		bitoff += key_field_temp->width;
		i++;
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
		ret = json_parse_table_actions(action_cjson, action_temp,
					       runt_params_offset,
					       &table->num_runt_params);
		if (ret) {
			fprintf(stderr, "action Object not found\n");
			free(action_temp);
			goto cleanup_actions;
		}

		if (action_prev)
			action_prev->next = action_temp;
		else
			table->actions = action_temp;

		table->actions_count++;
		action_prev = action_temp;
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

static int json_parse_tables(cJSON *root,
			     struct p4tc_json_pipeline *pipeline_info)
{
	struct p4tc_json_table_list *table_temp = NULL;
	int runt_params_offset = 0;
	cJSON *tables_cjson = NULL;
	int num_runt_params = 0;
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
		ret = json_parse_table(table_cjson, &table_temp->table,
				       &runt_params_offset);
		if (ret) {
			fprintf(stderr, "Failed to parse tables\n");
			free(table_temp);
			goto cleanup_tables;
		}
		if (pipeline_info->mat_tables)
			table_temp->next = pipeline_info->mat_tables;
		pipeline_info->mat_tables = table_temp;
		pipeline_info->mat_tables_count++;
		num_runt_params += table_temp->table.num_runt_params;
	}
	pipeline_info->filter_fields_size = runt_params_offset;
	pipeline_info->num_runt_params = num_runt_params;

	return 0;

cleanup_tables:
	FREE_LIST(pipeline_info->mat_tables);
	pipeline_info->mat_tables = NULL;
	return -1;
}

static int
json_parse_ext_inst_data(cJSON *insts_data_cjson,
			 struct p4tc_json_extern_insts_data *insts_data)
{
	char *name = NULL;
	char *type = NULL;
	char *attr = NULL;
	int id = 0;
	int width;
	int ret;

	ret = cjson_get_string(insts_data_cjson,
			       JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_NAME,
			       &name);
	if (ret) {
		fprintf(stderr,
			"Failed to parse inst param name:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_NAME,
			cJSON_Print(insts_data_cjson));
		return -1;
	}

	ret = cjson_get_int(insts_data_cjson,
			    JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_ID, &id);
	if (ret) {
		fprintf(stderr,
			"Failed to parse insts param id:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_ID,
			cJSON_Print(insts_data_cjson));
		return -1;
	}

	ret |= cjson_get_string(insts_data_cjson,
				JSON_TABLE_LIST_TABLE_ACTION_DATA_TYPE, &type);
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

	ret = cjson_get_optional_string(insts_data_cjson,
					JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_ATTR,
					&attr);
	if (!ret)
		strncpy(insts_data->attr, attr, P4TC_NAME_LEN - 1);

	strncpy(insts_data->name, name, P4TC_NAME_LEN - 1);
	insts_data->name[P4TC_NAME_LEN - 1] = '\0';
	strncpy(insts_data->type, type, P4TC_NAME_LEN - 1);
	insts_data->type[P4TC_NAME_LEN - 1] = '\0';

	insts_data->id = id;

	return 0;
}

static int json_parse_ext_insts_list(cJSON *insts_cjson,
				     struct p4tc_json_extern_insts_list *inst)
{
	cJSON *insts_data_cjson = NULL, *insts_data_iter_cjson = NULL;
	struct p4tc_json_extern_insts_data *insts_data_temp = NULL;
	struct p4tc_json_extern_insts_data *insts_data_curr;
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
			JSON_EXTERN_LIST_EXTERN_INSTS_ID,
			cJSON_Print(insts_cjson));
		return -1;
	}

	strncpy(inst->name, name, P4TC_NAME_LEN - 1);
	inst->name[P4TC_NAME_LEN - 1] = '\0';

	inst->id = id;

	ret = cjson_get_object(insts_cjson,
			       JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS,
			       &insts_data_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS);
		return -1;
	}

	insts_data_curr = inst->data;
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
			insts_data_curr->next = insts_data_temp;
		else
			inst->data = insts_data_temp;

		insts_data_curr = insts_data_temp;
		inst->insts_data_count++;
	}

	return 0;

cleanup_insts:
	FREE_LIST(inst->data);
	inst->data = NULL;
	return -1;
}

static int json_parse_extern(cJSON *extern_cjson,
			     struct p4tc_json_externs_list *ext)
{
	struct p4tc_json_extern_insts_list *inst_temp;
	struct p4tc_json_extern_insts_list *inst_curr;
	cJSON *insts_cjson = NULL;
	char *id_str = NULL;
	char *name = NULL;
	int ret;
	int id;

	ret = cjson_get_string(extern_cjson, JSON_EXTERN_LIST_EXTERN_NAME,
			       &name);
	if (ret) {
		fprintf(stderr, "Failed to parse extern name:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_NAME,
			cJSON_Print(extern_cjson));
		return -1;
	}

	ret = cjson_get_string(extern_cjson, JSON_EXTERN_LIST_EXTERN_ID,
			       &id_str);
	if (ret) {
		fprintf(stderr, "Failed to parse extern id:<%s> for:\n<%s>\n",
			JSON_EXTERN_LIST_EXTERN_ID,
			cJSON_Print(extern_cjson));
		return -1;
	}

	if (get_u32((__u32 *)&id, id_str, 0) < 0) {
		fprintf(stderr,
			"Failed to convert extern to id to u16 for:\n<%s>\n",
			cJSON_Print(extern_cjson));
		return -1;
	}

	strncpy(ext->name, name, P4TC_NAME_LEN - 1);
	ext->name[P4TC_NAME_LEN - 1] = '\0';

	ext->id = id;

	ret = cjson_get_object(extern_cjson, JSON_EXTERN_LIST_EXTERN_INSTS,
			       &insts_cjson);
	if (ret) {
		fprintf(stderr, "JSON object <%s> not found\n",
			JSON_TABLE_LIST_TABLE_KEYS);
		return -1;
	}

	cJSON *inst_cjson = NULL;

	inst_curr = ext->insts;
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
			inst_curr->next = inst_temp;
		else
			ext->insts = inst_temp;

		inst_curr = inst_temp;
		ext->insts_count++;
	}

	return 0;

cleanup_insts:
	FREE_LIST(ext->insts);
	ext->insts = NULL;
	return -1;
}

static int json_parse_externs(cJSON *root,
			      struct p4tc_json_pipeline *pipeline_info)
{
	struct p4tc_json_externs_list *extern_temp = NULL;
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

static void p4tc_json_print_action(struct p4tc_json_actions_list *action,
				   FILE *fp)
{
	fprintf(fp, "    action: %s(id %d) with scope %s and %d params\n",
		action->name, action->id, action->action_scope,
		action->action_data_count);
}

static const char *p4tc_json_print_keyfield_type(enum p4_tc_match_type mtype,
						 FILE *fp)
{
	switch (mtype) {
		case P4TC_MATCH_TYPE_EXACT:
			return "exact";
		case P4TC_MATCH_TYPE_TERNARY:
			return "ternary";
		case P4TC_MATCH_TYPE_LPM:
			return "lpm";
		default:
			break;
	}

	return "unknown";
}

static void p4tc_json_print_keyfield_data(struct p4tc_json_key_fields_list *kf,
					  __u8 *k, __u8 *m, int rlen, FILE *fp,
					  const char *prefix)
{
	struct p4_type_value v = {.value = k, .mask = m, .bitsz = kf->width};
	__u32 bitsz;
	struct p4_type_s *t = get_p4type_byarg(kf->type, &bitsz);
	__u32 bsz = kf->width;
	__u32 Bsz = bsz/8;
	__u32 rB = bsz%8;
	__u32 tot = Bsz + (rB?1:0);
	int bsize = 256;
	char kfld[bsize];
	int i, l;
	char *b;

	if (t && t->bitsz == bitsz) {
		size_t bytesz = BITS_TO_BYTES(bitsz);
		__u8 *value_aligned;
		__u8 *mask_aligned;

		value_aligned = calloc(1, bytesz);
		if (!value_aligned)
			return;

		mask_aligned = calloc(1, bytesz);
		if (!mask_aligned) {
			free(value_aligned);
			return;
		}
		memcpy(value_aligned, k, bytesz);
		memcpy(mask_aligned, m, bytesz);

		v.value = value_aligned;
		v.mask = mask_aligned;

		t->print_p4t(" fieldval ", "fieldval", &v, fp);

		free(value_aligned);
		free(mask_aligned);
		return;
	}

	if (bsz > rlen) {
		fprintf(stderr, "We have an error bsz %d > remainder of data %d\n",
			bsz, rlen);
		return;
	}

	b = kfld;
	l = snprintf(b, bsize, "%s", "0x");
	bsize -= l;
	b += l;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (!p4type_bigendian(t))
		for (i = tot - 1; i >= 0; i--) {
			__u8 ch = k[i] & 0xff;
			l = snprintf(b, bsize, "%02x", ch);
			bsize -= l;
			b += l;
		}

	else
#endif
		for (i = 0; i < tot; i++) {
			__u8 ch = k[i] & 0xff;
			l = snprintf(b, bsize, "%02x", ch);
			bsize -= l;
			b += l;
		}

	l = snprintf(b, bsize, "%s", "/0x");
	bsize -= l;
	b += l;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (!p4type_bigendian(t))
		for (i = tot - 1; i >= 0; i--) {
			__u8 ch = m[i] & 0xff;
			l = snprintf(b, bsize, "%02x", ch);
			bsize -= l;
			b += l;
		}
	else
#endif
		for (i = 0; i < tot; i++) {
			__u8 ch = m[i] & 0xff;
			l = snprintf(b, bsize, "%02x", ch);
			bsize -= l;
			b += l;
		}

	print_string(PRINT_ANY, "fieldval ", " value: %s", kfld);
}

static void p4tc_json_print_keyfield(struct p4tc_json_key_fields_list *field,
				     FILE *fp)
{
	print_string(PRINT_ANY, "keyfield", "     %s ", field->name);
	print_uint(PRINT_ANY, "id", "id:%d ", field->id);
	print_uint(PRINT_ANY, "width", "size:%db ", field->width);
	print_string(PRINT_ANY, "type", "type:%s", field->type);
	print_string(PRINT_ANY, "match_type", " %s",
		     p4tc_json_print_keyfield_type(field->match_type, fp));
}

static void p4tc_json_print_table(struct p4tc_json_table *t, FILE *fp)
{
	struct p4tc_json_key_fields_list *key_list = t->key_fields;
	struct p4tc_json_actions_list *actions = t->actions;
	struct p4tc_json_table *tbl = t;

	fprintf(fp,
		"  Table: %s(id %d) with %d keyfields (size %d) and %d actions \n",
		tbl->name, tbl->id, tbl->key_fields_count,  tbl->ksize,
		tbl->actions_count);

	print_string(PRINT_FP, NULL, "   KEY\n", NULL);
	while (key_list) {
		p4tc_json_print_keyfield(key_list, fp);
		print_nl();
		key_list = key_list->next;
	}

	while (actions) {
		p4tc_json_print_action(actions, fp);
		actions = actions->next;
	}
}

static struct p4tc_json_key_fields_list *
p4tc_json_find_table_keyfield_byid(struct p4tc_json_table *t, __u32 keyid)
{
	struct p4tc_json_key_fields_list *key_fields = t->key_fields;

	while (key_fields) {
		if (keyid == key_fields->id)
			return key_fields;

		key_fields = key_fields->next;
	}

	return NULL;
}

static int
___p4tc_json_for_each_runtime_action_data(struct p4tc_json_table *table,
					  struct p4tc_json_actions_list *act,
					  p4tc_json_action_data_iter iter,
					  void *ptr)
{
	struct p4tc_json_action_data *data = act->data;

	while (data) {
		if (data->runtime) {
			if (iter(table, act, data, ptr) < 0)
				return -1;
		}
		data = data->next;
	}

	return 0;
}

static int
__p4tc_json_for_each_runtime_action_data(struct p4tc_json_table *table,
					 p4tc_json_action_data_iter iter,
					 void *ptr)
{
	struct p4tc_json_actions_list *acts = table->actions;

	while (acts) {
		int ret = ___p4tc_json_for_each_runtime_action_data(table,
								    acts, iter,
								    ptr);
		if (ret < 0)
			return ret;
		acts = acts->next;
	}

	return 0;
}

int p4tc_json_for_each_runtime_action_data(struct p4tc_json_pipeline *p,
					   p4tc_json_action_data_iter iter,
					   void *ptr)
{
	struct p4tc_json_table_list *mat_tables = p->mat_tables;

	while (mat_tables) {
		int ret;
		if (!mat_tables->table.num_runt_params) {
			mat_tables = mat_tables->next;
			continue;
		}

		ret = __p4tc_json_for_each_runtime_action_data(&mat_tables->table,
							       iter, ptr);
		if (ret < 0)
			return ret;
		mat_tables = mat_tables->next;
	}

	return 0;
}

#define DEF_KEY_SZ 16 /* size of __uint128_t */
void p4tc_json_print_key_data(struct p4tc_json_table *t, __u8 *key, __u8 *mask,
			      int blen, FILE *fp, const char *prefix)
{
	struct p4tc_json_key_fields_list *key_list = t->key_fields;
	struct p4tc_json_key_fields_list *kf;
	int rlen = t->ksize;
	__u32 shiftv = 0;
	int kfid = 1;

	//printf("div %d mod %d\n", blen/DEF_KEY_SZ, blen%DEF_KEY_SZ);

	open_json_array(PRINT_JSON, "key");
	print_string(PRINT_FP, NULL, "    entry key\n", NULL);

	while (key_list) {
		kf = p4tc_json_find_table_keyfield_byid(t, kfid);
		if (!kf) {
			fprintf(stderr,
				"error: failed to find keyfield ID %d\n", kfid);
			close_json_object();
			close_json_array(PRINT_JSON, NULL);
			return;
		}

		shiftv = !(kf->width % 8) ?
			kf->width : kf->width + (8 - kf->width % 8);
		//printf("shift for next field from field %s is %db\n", kf->name, shiftv);
		open_json_object(NULL);
		p4tc_json_print_keyfield(kf, fp);
		p4tc_json_print_keyfield_data(kf, key, mask, rlen,
					      fp, prefix);
		rlen -= kf->width;
		if (rlen < 0) {
			fprintf(stderr, "error: Insufficient key blob %d/%d\n",
				rlen, t->ksize);
			close_json_object();
			close_json_array(PRINT_JSON, NULL);
			return;
		}

		close_json_object();
		print_nl();
		kfid++;
		if (kfid > t->key_fields_count)
			break;

		key += BITS_TO_BYTES(shiftv);
		mask += BITS_TO_BYTES(shiftv);
		key_list = key_list->next;
	}

	close_json_array(PRINT_JSON, NULL);
}

static struct p4tc_json_extern_insts_list *
__p4tc_json_find_extern_inst(struct p4tc_json_externs_list *e,
			     const char *instname)
{
	struct p4tc_json_extern_insts_list *iter = e->insts;

	while (iter) {
		if (!strcmp(instname, iter->name))
			return iter;

		iter = iter->next;
	}

	return NULL;
}

struct p4tc_json_extern_insts_list *
p4tc_json_find_extern_inst(struct p4tc_json_pipeline *p, const char *extname,
			   const char *instname)
{
	struct p4tc_json_externs_list *iter = p->externs;

	while (iter) {
		if (!strcmp(extname, iter->name))
			return __p4tc_json_find_extern_inst(iter, instname);

		iter = iter->next;
	}

	return NULL;
}

struct p4tc_json_externs_list *
p4tc_json_find_extern(struct p4tc_json_pipeline *p, const char *extname)
{
	struct p4tc_json_externs_list *iter = p->externs;

	while (iter) {
		if (!strcmp(extname, iter->name))
			return iter;

		iter = iter->next;
	}

	return NULL;
}

struct p4tc_json_extern_insts_data *
p4tc_json_find_extern_data(struct p4tc_json_extern_insts_list *insts,
			   const char *param_name)
{
	struct p4tc_json_extern_insts_data *iter = insts->data;

	while (iter) {
		if (!strcmp(param_name, iter->name))
			return iter;

		iter = iter->next;
	}

	return NULL;
}

struct p4tc_json_action_data *
p4tc_json_find_act_data(struct p4tc_json_actions_list *action,
			const char *data_name)
{
	struct p4tc_json_action_data *data = action->data;
	while (data) {
		if (!strcmp(data_name, data->name))
		    return data;

		data = data->next;
	}

	return NULL;
}

struct p4tc_json_actions_list *
p4tc_json_find_table_act(struct p4tc_json_table *tbl,
			 const char *act_name)
{
	struct p4tc_json_actions_list *actions = tbl->actions;

	while (actions) {
		if (!strcmp(act_name, actions->name))
		    return actions;

		actions = actions->next;
	}

	return NULL;
}

struct p4tc_json_actions_list *
p4tc_json_find_act(struct p4tc_json_pipeline *p,
		   const char *act_name)
{
	struct p4tc_json_table_list *mat_tables = p->mat_tables;
	struct p4tc_json_actions_list *action;

	while (mat_tables) {
		action = p4tc_json_find_table_act(&mat_tables->table, act_name);
		if (action)
			return action;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

/* ignore keyid for now until json support multiple keys */
struct p4tc_json_key_fields_list *
p4tc_json_find_table_keyfield(struct p4tc_json_table *t, __u32 keyid,
			      const char *key_field_name)
{
	struct p4tc_json_key_fields_list *key_fields = t->key_fields;

	while (key_fields) {
		if (!strcmp(key_field_name, key_fields->name))
			return key_fields;

		key_fields = key_fields->next;
	}

	return NULL;
}

struct p4tc_json_table *
p4tc_json_find_table_byid(struct p4tc_json_pipeline *p, int tab_id)
{
	struct p4tc_json_table_list *mat_tables = p->mat_tables;

	while (mat_tables) {
		if (tab_id == mat_tables->table.id)
			return &mat_tables->table;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

struct p4tc_json_table *p4tc_json_find_table(struct p4tc_json_pipeline *p,
					     const char *tab_name)
{
	struct p4tc_json_table_list *mat_tables = p->mat_tables;

	while (mat_tables) {
		if (!strcmp(tab_name, mat_tables->table.name))
			return &mat_tables->table;

		mat_tables = mat_tables->next;
	}

	return NULL;
}

/* Looks up arch file profiles to see whether there is a profile that matches
 * the specified aging time.
 */
struct p4tc_json_profile *
p4tc_json_find_profile_by_aging(struct p4tc_arch_json *a, __u64 aging_ms)
{
	struct p4tc_json_profiles_list *profiles_list = a->profiles_list;

	while (profiles_list) {
		struct p4tc_json_profile *profile = &profiles_list->profile;

		if (profile->aging_ms == aging_ms)
			return profile;

		profiles_list = profiles_list->next;
	}

	return NULL;
}

void p4tc_json_print_pipeline(struct p4tc_json_pipeline *p, FILE *fp)
{
	struct p4tc_json_table_list *mat_tables = p->mat_tables;
	struct p4tc_json_pipeline *pipe = p;
	struct p4tc_json_table_list *mat;

	/* iterate the tables and print them */
	while (mat_tables) {
		mat =  pipe->mat_tables;
		p4tc_json_print_table(&mat->table, stdout);
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
struct p4tc_json_pipeline *p4tc_json_import(const char *pname)
{
	struct p4tc_json_pipeline *pipeline_info;
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
		fprintf(stderr,
			"Must specify pipeline name for introspection\n");
		return NULL;
	}

	if (snprintf(json_file_path, PATH_MAX, "%s/%s.json", introspection_dir,
		     pname) >= PATH_MAX) {
		fprintf(stderr, "Pipeline name too long\n");
		return NULL;
	}

	file = fopen(json_file_path, "r");
	if (file == NULL) {
		fprintf(stderr, "Unable to open introspection file: <%s>\n",
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
	strncpy(pipeline_info->name, name, P4TC_NAME_LEN - 1);
	pipeline_info->name[P4TC_NAME_LEN - 1] = '\0';

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

static int json_parse_profile(cJSON *profile_cjson,
			      struct p4tc_json_profile *profile)
{
	char *name = NULL;
	int aging;
	int ret;

	ret = cjson_get_string(profile_cjson, JSON_PROFILE_NAME, &name);
	if (ret) {
		fprintf(stderr,
			"Failed to parse profile name:<%s> for:\n<%s>\n",
			JSON_PROFILE_NAME,
			cJSON_Print(profile_cjson));
		return -1;
	}

	ret = cjson_get_int(profile_cjson, JSON_PROFILE_AGING, &aging);
	if (ret) {
		fprintf(stderr,
			"Failed to parse profile aging:<%s> for:\n<%s>\n",
			JSON_PROFILE_AGING,
			cJSON_Print(profile_cjson));
		return -1;
	}

	strncpy(profile->name, name, P4TC_NAME_LEN - 1);
	profile->name[P4TC_NAME_LEN - 1] = '\0';

	profile->aging_ms = aging;

	return 0;
}

static int json_parse_profiles(cJSON *root, struct p4tc_arch_json *arch_info)
{
	struct p4tc_json_profiles_list *profile_temp = NULL;
	cJSON *profiles_cjson = NULL;
	int ret;

	ret = cjson_get_object(root, JSON_PROFILES_LIST, &profiles_cjson);
	if (ret) {
		fprintf(stderr, "JSON object not found\n");
		return -1;
	}
	cJSON *profile_cjson = NULL;

	cJSON_ArrayForEach(profile_cjson, profiles_cjson) {
		profile_temp = calloc(1, sizeof(*profile_temp));
		if (!profile_temp) {
			fprintf(stderr, "No resources: %s\n", __func__);
			goto cleanup_profiles;
		}
		ret = json_parse_profile(profile_cjson, &profile_temp->profile);
		if (ret) {
			fprintf(stderr, "Failed to parse profiles\n");
			free(profile_temp);
			goto cleanup_profiles;
		}
		if (arch_info->profiles_list)
			profile_temp->next = arch_info->profiles_list;
		arch_info->profiles_list = profile_temp;
		arch_info->profiles_count++;
	}

	return 0;

cleanup_profiles:
	FREE_LIST(arch_info->profiles_list);
	arch_info->profiles_list = NULL;
	return -1;
}

/* Imports arch file which will hold all expire time profiles.
 * If user specifies this file when creating a table entry, the code will
 * lookup in the arch file to see whether there is a profile that matches the
 * specified aging time.
 */
struct p4tc_arch_json *p4tc_json_import_arch(const char *arch)
{
	struct p4tc_arch_json *arch_info;
	char json_file_path[PATH_MAX];
	char *json_file_buffer;
	struct stat stat_b;
	size_t file_size;
	size_t num_items;
	cJSON *root;
	FILE *file;
	int ret;
	int fd;

	if (!arch) {
		fprintf(stderr, "Must specify arch name\n");
		return NULL;
	}

	file = fopen(arch, "r");
	if (file == NULL) {
		fprintf(stderr, "Unable to open arch file: <%s>\n",
			json_file_path);
		return NULL;
	}

	arch_info = calloc(1, sizeof(*arch_info));
	if (!arch_info) {
		fprintf(stderr, "No resources\n");
		goto fp_close;
	}

	fd = fileno(file);
	fstat(fd, &stat_b);
	file_size = stat_b.st_size + 1;
	json_file_buffer = calloc(1, file_size);
	if (!json_file_buffer) {
		fprintf(stderr, "Could not alloc memory for json file <%s>\n",
			json_file_path);
		goto free_arch_info;
	}

	num_items = fread(json_file_buffer, stat_b.st_size, 1, file);
	if (num_items != 1) {
		if (ferror(file)) {
			fprintf(stderr, "Error reading json file buffer <%s>\n",
				json_file_path);
			goto free_json_file_buffer;
		}
	}

	root = cJSON_Parse(json_file_buffer);
	if (!root) {
		fprintf(stderr, "Error(%s) parsing json file <%s>\n",
			cJSON_GetErrorPtr(), json_file_path);
		goto free_json_file_buffer;
	}

	ret = json_parse_profiles(root, arch_info);
	if (ret && ret != ENOENT)
		goto delete_root;

	return arch_info;

delete_root:
	cJSON_Delete(root);

free_json_file_buffer:
	free(json_file_buffer);

free_arch_info:
	free(arch_info);

fp_close:
	fclose(file);
	return NULL;
}
