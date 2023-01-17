#ifndef __CJSON_UTILS__
#define __CJSON_UTILS__
#include "cJSON.h"
#include <stdbool.h>

#define cJSON_FOR_EACH(it, parent) \
	for ((it) = (parent)->child; (it) != NULL; (it) = (it)->next)

int cjson_get_string(cJSON *cjson, char *key, char **val);
int cjson_get_object(cJSON *cjson, char *key, cJSON **val);
int cjson_get_optional_object(cJSON *cjson, char *key, cJSON **val);
int cjson_get_int(cJSON *cjson, char *key, int *val);
int cjson_get_bool(cJSON *cjson, char *key, bool *val);

#endif /*__CJSON_UTILS__*/
