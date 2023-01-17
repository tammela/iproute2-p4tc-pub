/* Internal definitions for p4c json artifacts */

#ifndef __JSON_INFRA_H__
#define __JSON_INFRA_H__
#include <stdbool.h>
#include <linux/types.h>

#define P4_TC_NAME_LEN 256
#define ENV_VAR "INTROSPECTION"

/* Macros for json file*/
#define JSON_PIPELINE_ID "id"
#define JSON_PIPELINE_NAME "pipeline_name"
#define JSON_TABLE "tables"
#define JSON_TABLE_LIST_TABLE_NAME "name"
#define JSON_TABLE_LIST_TABLE_ID "id"
#define JSON_TABLE_LIST_TABLE_SIZE "tentries"
#define JSON_TABLE_LIST_TABLE_KEYS "keyfields"
#define JSON_TABLE_LIST_TABLE_KEY_SIZE "keysize"
#define JSON_TABLE_LIST_TABLE_KEY_FIELD_ID "id" //keyfield id
#define JSON_TABLE_LIST_TABLE_KEY_NAME "name"
#define JSON_TABLE_LIST_TABLE_KEY_TYPE "type"
#define JSON_TABLE_LIST_TABLE_KEY_MATCH_TYPE "match_type"
#define JSON_TABLE_LIST_TABLE_KEY_WIDTH "bitwidth"
#define JSON_TABLE_LIST_TABLE_KEY_MANDATORY "mandatory"
#define JSON_TABLE_LIST_TABLE_ACTIONS "actions"
#define JSON_TABLE_LIST_TABLE_ACTION_NAME "name"
#define JSON_TABLE_LIST_TABLE_ACTION_SCOPE "action_scope"
#define JSON_TABLE_LIST_TABLE_ACTION_ID "id"
#define JSON_TABLE_LIST_TABLE_ACTION_DATA "params"
#define JSON_TABLE_LIST_TABLE_ACTION_DATA_ID "id"
#define JSON_TABLE_LIST_TABLE_ACTION_DATA_NAME "name"
#define JSON_TABLE_LIST_TABLE_ACTION_DATA_TYPE "type"
#define JSON_TABLE_LIST_TABLE_ACTION_DATA_WIDTH "bitwidth"
#define JSON_EXTERNS "externs"
#define JSON_EXTERN_LIST_EXTERN_ID "id"
#define JSON_EXTERN_LIST_EXTERN_NAME "name"
#define JSON_EXTERN_LIST_EXTERN_ANNOTATIONS "annotations"
#define JSON_EXTERN_LIST_EXTERN_INSTS "instances"
#define JSON_EXTERN_LIST_EXTERN_INSTS_NAME "inst_name"
#define JSON_EXTERN_LIST_EXTERN_INSTS_ID "inst_id"
#define JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS "params"
#define JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_NAME "name"
#define JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_ID "id"
#define JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_TYPE "type"
#define JSON_EXTERN_LIST_EXTERN_INSTS_PARAMS_WIDTH "bitwidth"

#define JSON_PROFILES_LIST "profiles"
#define JSON_PROFILE_NAME "name"
#define JSON_PROFILE_AGING "aging"

enum p4_tc_match_type {
	P4_TC_MATCH_TYPE_EXACT = 0,
	P4_TC_MATCH_TYPE_TERNARY,
	P4_TC_MATCH_TYPE_LPM,
	P4_TC_MATCH_TYPE_INVALID
};

struct key_fields_list {
	int id;
	char name[P4_TC_NAME_LEN];
	char type[P4_TC_NAME_LEN];
	int parser_instance; //XXX: we should be using the name instead
	int width;
	bool mandatory;
	enum p4_tc_match_type match_type;
	struct key_fields_list *next;
};

struct action_data {
	int id;
	char name[P4_TC_NAME_LEN];
	char type[P4_TC_NAME_LEN];
	int width;
	struct action_data *next;
};

struct actions_list {
	int id;
	char name[P4_TC_NAME_LEN];
	char action_scope[P4_TC_NAME_LEN];
	int action_data_count;
	struct action_data *data;
	struct actions_list *next;
};

struct extern_insts_data {
	int id;
	char name[P4_TC_NAME_LEN];
	char type[P4_TC_NAME_LEN];
	int width;
	struct extern_insts_data *next;
};

struct extern_insts_list {
	int id;
	char name[P4_TC_NAME_LEN];
	char type[P4_TC_NAME_LEN];
	int width;
	struct extern_insts_data *data;
	struct extern_insts_list *next;
	int insts_data_count;
};

struct externs_list {
	int id;
	char name[P4_TC_NAME_LEN];
	struct extern_insts_list *insts;
	struct externs_list *next;
	int insts_count;
};

struct table {
	char name[P4_TC_NAME_LEN];
	int id;
	int size;
	__u32 ksize;
	//XXX: Assumes only one key; we may have more.
	int key_fields_count;
	struct key_fields_list *key_fields;
	int actions_count;
	struct actions_list *actions;
};

struct table_list {
	struct table table;
	struct table_list *next;
};

struct p4_tc_pipeline {
	char name[P4_TC_NAME_LEN];
	__u32 id;
	int mat_tables_count;
	int metadata_count;
	struct table_list *mat_tables;
	int actions_count;
	struct externs_list *externs;
	int externs_count;
};

struct profile {
	char name[P4_TC_NAME_LEN];
	__u64 aging_ms;
};

struct profiles_list {
	struct profile profile;
	struct profiles_list *next;
};

struct p4_tc_arch_json {
	char name[P4_TC_NAME_LEN];
	struct profiles_list *profiles_list;
	int profiles_count;
};

#endif /* __JSON_INFRA_H__ */
