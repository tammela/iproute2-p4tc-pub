#ifndef __JSON_IMPORT_H__
#define __JSON_IMPORT_H__

#include "p4_tc_json_infra.h"

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
struct actions_list *p4tc_find_act(struct p4_tc_pipeline *pipe,
				   const char *act_name);
struct table *p4tc_find_table(struct p4_tc_pipeline *p, const char *tab_name);
struct table *p4tc_find_table_byid(struct p4_tc_pipeline *p, int tab_id);
struct key_fields_list *p4tc_find_table_keyfield(struct table *t, __u32 keyid,
						 const char *key_field_name);

#endif /*__JSON_IMPORT_H__*/
