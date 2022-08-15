/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DB_NAMES_H_
#define DB_NAMES_H_ 1

#define IDNAME_MAX 256
#define NAME_MAX_LEN 512

struct db_entry {
	struct db_entry *next;
	unsigned int id;
	char *name;
};

struct db_names {
	unsigned int size;
	struct db_entry *cached;
	struct db_entry **hash;
	int max;
};

struct db_names *db_names_alloc(void);
int db_names_load(struct db_names *db, const char *path);
void db_names_free(struct db_names *db);

char *id_to_name(struct db_names *db, int id, char *name);

int fread_id_name(FILE *fp, int *id, char *namebuf);
void names_tab_initialize(const char *file, char **tab, int size);

#endif
