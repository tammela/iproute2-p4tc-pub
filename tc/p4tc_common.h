/* SPDX-License-Identifier: GPL-2.0 */

#define TMPL_ARRAY_START_IDX 1
#define PATH_OBJ_IDX 0
#define PATH_PNAME_IDX 1
#define PATH_CBNAME_IDX 2
#define PATH_MNAME_IDX 3
#define PATH_TBCNAME_IDX 3
#define PATH_TINAME_IDX 4
#define PATH_ANAME_IDX 3

#define PATH_PARSERNAME_IDX 2
#define PATH_HDRNAME_IDX 3
#define PATH_HDRFIELDNAME_IDX 4

#define MAX_PATH_COMPONENTS 5

void parse_path(char *path, char **p4tcpath);
int get_obj_type(const char *str_obj_type);

#define STR_IS_EMPTY(str) ((str)[0] == '\0')

int concat_cb_name(char *full_name, const char *cbname,
		   const char *objname, size_t sz);
