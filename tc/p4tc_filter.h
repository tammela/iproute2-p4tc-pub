#ifndef _P4TC_EXPR_H_
#define _P4TC_EXPR_H_
#include "p4tc_filter_parser.h"
#include <string.h>
#include "p4tc_common.h"

#define P4TC_EXPR_FMTMSG_LEN  80

struct typedexpr {
	enum exprtype t;
	union {
		char errmsg_fmt[P4TC_EXPR_FMTMSG_LEN]; // ET_ERR
		const char *errmsg; // ET_ERR
		struct {			// ET_BOOL
			int v;				// only 0 and 1 allowed
		} boolean;
		struct {			// ET_INTEGER
			char *s;
			__u64 i;
			struct p4_type_s *typ;
		} integer;
		struct {			// ET_STRING
			unsigned char *txt;
			int len;
		} string;
		struct {			// ET_IPv4
			__u32 a;
			__u32 mask;
		} ipv4;
		struct {			// ET_IPv6
			unsigned char a[16];
			__u32 mask;
		} ipv6;
		struct {			// ET_MAC
			unsigned char a[6];
		} mac;
		struct {			// ET_NAME
			char *name;
			void *data;
			struct p4_type_s *typ;
		} name;
		struct {			// ET_UNARY
			enum unary_op op;				// U_*
			struct typedexpr *arg;
		} unary;
		struct {			// ET_BINARY
			struct typedexpr *lhs;
			enum binary_op op;				// B_*
			struct typedexpr *rhs;
		} binary;
	};
};

struct typedexpr *type_expr(struct parsedexpr *e);
void free_typedexpr(struct typedexpr *t);
void dump_typed_expr(struct typedexpr *t, int indent);
void add_typed_expr(struct nlmsghdr *n, struct typedexpr *t);
int register_known_unprefixed_names(void);

#endif
