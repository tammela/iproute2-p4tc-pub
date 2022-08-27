/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __P4T_H__
#define __P4T_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <alloca.h>
#include "utils.h"
#include "tc_util.h"
#include "tc_common.h"
#include "list.h"

#define P4T_MAX_TYPE_NAME 32

#define P4T_MAX_STR_SZ 16
struct p4_type_s {
	int containid;
	size_t bitsz;
	__u8 startbit;
	__u8 endbit;
	int (*parse_p4t)(void *val, const char *arg, int base);
	void (*print_p4t)(const char *n, void *val, __u8 bitstart, __u8 bitend,
			  FILE *f);
	const char *name;
	__u8 flags;
	struct hlist_node hlist;
};

struct p4_type_s *get_p4type_byid(int id);
struct p4_type_s *get_p4type_bysize(int sz, __u8 flags);
struct p4_type_s *get_p4type_byname(const char *name);
struct p4_type_s *get_p4type_byarg(const char *argv, __u32 *bitsz);

void register_p4_types(void);
void unregister_p4_types(void);

#endif /* __P4T_H__ */
