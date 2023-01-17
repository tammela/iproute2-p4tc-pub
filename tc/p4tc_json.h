/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __JSON_IMPORT_H__
#define __JSON_IMPORT_H__

#include "p4tc_json_infra.h"

#define P4TC_JSON_ACT_SCOPE_GLOBAL  0x1
#define P4TC_JSON_ACT_SCOPE_CB  0x2

#define FREE_LIST(head) \
	{ \
		void *temp; \
		while (head) { \
			temp = head->next; \
			free(head); \
			head = temp; \
		} \
	}

struct p4tc_json_pipeline *p4tc_json_import(const char *pname);
void p4tc_json_free_pipeline(struct p4tc_json_pipeline *pipeline_info);
void p4tc_json_print_pipeline(struct p4tc_json_pipeline *pipeline,
			      FILE *fp);
void p4tc_print_json_table(struct p4tc_json_table *t,
			   FILE *fp);
void p4tc_json_print_key_data(struct p4tc_json_table *t, __u8 *k, __u8 *m,
			      int blen, FILE *fp, const char *prefix);
struct p4tc_json_actions_list *
p4tc_json_find_table_act(struct p4tc_json_table *tbl,
			 const char *act_name);
struct p4tc_json_actions_list *
p4tc_json_find_act(struct p4tc_json_pipeline *pipe, const char *act_name);
/* Here data == param */
struct p4tc_json_action_data *
p4tc_json_find_act_data(struct p4tc_json_actions_list *action,
			const char *data_name);
struct p4tc_json_table *p4tc_json_find_table(struct p4tc_json_pipeline *p,
					     const char *tab_name);
struct p4tc_json_table *p4tc_json_find_table_byid(struct p4tc_json_pipeline *p,
						  int tab_id);
struct p4tc_json_key_fields_list *
p4tc_json_find_table_keyfield(struct p4tc_json_table *t,
			      __u32 keyid,
			      const char *key_field_name);
__u32 p4tc_json_find_action(struct p4tc_json_actions_list *action);

struct p4tc_json_externs_list *
p4tc_json_find_extern(struct p4tc_json_pipeline *p, const char *extname);
struct p4tc_json_extern_insts_list *
p4tc_json_find_extern_inst(struct p4tc_json_pipeline *p, const char *extname,
			   const char *instname);
struct p4tc_json_extern_insts_data *
p4tc_json_find_extern_data(struct p4tc_json_extern_insts_list *insts,
			   const char *param_name);

struct p4tc_json_profile *
p4tc_json_find_profile_by_aging(struct p4tc_arch_json *a, __u64 aging_ms);
struct p4tc_arch_json *p4tc_json_import_arch(const char *arch);

static inline struct p4tc_json_key_fields_list *
p4tc_json_table_keyfield_iter_start(struct p4tc_json_table *t)
{
	return t->key_fields;
}

static inline struct p4tc_json_key_fields_list *
p4tc_json_table_keyfield_next(struct p4tc_json_key_fields_list *key_field)
{
	return key_field->next;
}

static inline struct p4tc_json_actions_list *
p4tc_json_table_action_iter_start(struct p4tc_json_table *t)
{
	return t->actions;
}

static inline struct p4tc_json_actions_list *
p4tc_json_action_next(struct p4tc_json_actions_list *action)
{
	return action->next;
}

static inline struct p4tc_json_action_data *
p4tc_json_action_data_start_iter(struct p4tc_json_actions_list *action)
{
	return action->data;
}

static inline struct p4tc_json_action_data *
p4tc_json_action_data_next(struct p4tc_json_action_data *data)
{
	return data->next;
}

static inline struct p4tc_json_table_list *
p4tc_json_table_iter_start(struct p4tc_json_pipeline *pipeline)
{
	return pipeline->mat_tables;
}

static inline struct p4tc_json_table_list *
p4tc_json_table_next(struct p4tc_json_table_list *tables_list)
{
	return tables_list->next;
}

static inline struct p4tc_json_externs_list *
p4tc_json_extern_iter_start(struct p4tc_json_pipeline *pipeline)
{
	return pipeline->externs;
}

static inline struct p4tc_json_externs_list *
p4tc_json_extern_iter_next(struct p4tc_json_externs_list *externs_list)
{
	return externs_list->next;
}

static inline struct p4tc_json_extern_insts_list *
p4tc_json_ext_inst_iter_start(struct p4tc_json_externs_list *externs_list)
{
	return externs_list->insts;
}

static inline struct p4tc_json_extern_insts_list *
p4tc_json_ext_inst_iter_next(struct p4tc_json_extern_insts_list *externs_list)
{
	return externs_list->next;
}

static inline struct p4tc_json_extern_insts_data *
p4tc_json_ext_insts_data_start_iter(struct p4tc_json_extern_insts_list *ext_insts_list)
{
	return ext_insts_list->data;
}

static inline struct p4tc_json_extern_insts_data *
p4tc_json_ext_insts_data_iter_next(struct p4tc_json_extern_insts_data *ext_insts_data)
{
	return ext_insts_data->next;
}

typedef int (*p4tc_json_action_data_iter)(struct p4tc_json_table *,
					  struct p4tc_json_actions_list *,
					  struct p4tc_json_action_data *,
					  void *);

int p4tc_json_for_each_runtime_action_data(struct p4tc_json_pipeline *p,
					   p4tc_json_action_data_iter iter,
					   void *ptr);

#endif /*__JSON_IMPORT_H__*/
