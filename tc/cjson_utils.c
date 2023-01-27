#include <stdio.h>

#include "cjson_utils.h"

int cjson_get_string(cJSON *cjson, char *key, char **val)
{
	cJSON *tmp = cJSON_GetObjectItem(cjson, key);

	if (!tmp) {
		fprintf(stderr, "attr <%s> not found\n", key);
		return -1;
	}

	if (tmp->type != cJSON_String) {
		fprintf(stderr, "Unexpected error type not string <%s>\n", key);
		return -1;
	}

	*val = tmp->valuestring;
	return 0;
}

int cjson_get_object(cJSON *cjson, char *key, cJSON **val)
{
	cJSON *tmp = cJSON_GetObjectItem(cjson, key);

	if (tmp == NULL || tmp->type == cJSON_NULL) {
		fprintf(stderr, "Unexpected error type not NULL <%s>\n", key);
		return -1;
	}

	*val = tmp;
	return 0;
}

int cjson_get_int(cJSON *cjson, char *key, int *val)
{
	cJSON *tmp = cJSON_GetObjectItem(cjson, key);

	if (tmp == NULL || tmp->type != cJSON_Number) {
		fprintf(stderr, "Unexpected error type not number <%s>\n",
			key);
		return -1;
	}

	*val = tmp->valueint;
	return 0;
}

int cjson_get_bool(cJSON *cjson, char *key, bool *val)
{
	cJSON *tmp = cJSON_GetObjectItem(cjson, key);

	if (tmp == NULL) {
		fprintf(stderr, "Unexpected error object NULL\n");
		return -1;
	}

	if (tmp->type == cJSON_False) {
		*val = false;
	} else if (tmp->type == cJSON_True) {
		*val = true;
	} else {
		fprintf(stderr, "Unexpected error not false or true <%s>\n",
			key);
		return -1;
	}
	return 0;
}
