#ifndef __JSON_IMPORT_H__
#define __JSON_IMPORT_H__

#include "p4_tc_json_infra.h"

#define P4_TC_JSON_ACT_SCOPE_GLOBAL  0x1
#define P4_TC_JSON_ACT_SCOPE_CB  0x2

#define FREE_LIST(head) \
	{ \
		void *temp; \
		while (head) { \
			temp = head->next; \
			free(head); \
			head = temp; \
		} \
	}

struct p4_tc_pipeline *p4_tc_import_json(const char *pname);
void p4_tc_print_pipeline(struct p4_tc_pipeline *pipeline, FILE *fp);
void p4_tc_print_table(struct table *t, FILE *fp);
void p4_tc_print_key_data(struct table *t, __u8 *k, __u8 *m, int blen, FILE *fp,
			  const char *prefix);
struct actions_list *p4tc_find_table_act(struct table *tbl,
					 const char *act_name);
struct actions_list *p4tc_find_act(struct p4_tc_pipeline *pipe,
				   const char *act_name);
/* Here data == param */
struct action_data *p4tc_find_act_data(struct actions_list *action,
					 const char *data_name);
struct table *p4tc_find_table(struct p4_tc_pipeline *p, const char *tab_name);
struct table *p4tc_find_table_byid(struct p4_tc_pipeline *p, int tab_id);
struct key_fields_list *p4tc_find_table_keyfield(struct table *t, __u32 keyid,
						 const char *key_field_name);
__u32 p4tc_find_action_scope(struct actions_list *action);

struct extern_insts_list *
p4tc_find_extern_inst(struct p4_tc_pipeline *p, const char *extname,
		      const char *instname);
struct extern_insts_data *
p4tc_find_extern_data(struct extern_insts_list *insts, const char *param_name);

#endif /*__JSON_IMPORT_H__*/
