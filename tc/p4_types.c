#include "p4_types.h"

enum {
	P4T_TYPE_UNSIGNED = (1 << 0),
	P4T_TYPE_SIGNED = (1 << 1),
	P4T_TYPE_BIGENDIAN = (1 << 2),
};

#define P4T_TYPE_UNSIGNED 0x1
#define P4T_TYPE_SIGNED 0x2
#define P4T_TYPE_BIGENDIAN 0x4

#define BITSZ_IRRELEVANT 0

static struct hlist_head types_list = {};

static int parse_p4t_u8_val(void *val, const char *arg, int base)
{
	__u8 *newval = val;
	__u8 ival;


	if (get_u8(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_s8_val(void *val, const char *arg, int base)
{
	__s8 *newval = val;
	__s8 ival;

	if (get_s8(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u16_val(void *val, const char *arg, int base)
{
	__u16 *newval = val;
	__u16 ival;

	if (get_u16(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_s16_val(void *val, const char *arg, int base)
{
	__s16 *newval = val;
	__s16 ival;

	if (get_s16(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_be16_val(void *val, const char *arg, int base)
{
	__be16 *newval = val;
	__be16 ival;

	if (get_be16(&ival, arg, base))
		return -1;

	*newval = htons(ival);
	return 0;
}

static int parse_p4t_s32_val(void *val, const char *arg, int base)
{
	__s32 *newval = val;
	__s32 ival;

	if (get_s32(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u64_val(void *val, const char *arg, int base)
{
	__u64 *newval = val;
	__u64 ival;

	if (get_u64(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u32_val(void *val, const char *arg, int base)
{
	__u32 *newval = val;
	__u32 ival;

	if (get_u32(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_be32_val(void *val, const char *arg, int base)
{
	__be32 *newval = val;
	__be32 ival;

	if (get_be32(&ival, arg, base))
		return -1;

	*newval = htonl(ival);
	return 0;
}

static int parse_p4t_ipv4_val(void *val, const char *arg, int base)
{
	inet_prefix *newaddr = val;
	inet_prefix iaddr;

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET))
		return -1;

	*newaddr = iaddr;

	return 0;
}

static void print_p4t_u8_val(const char *name, void *val, __u8 bitstart,
			     __u8 bitend, FILE *f)
{
	__u8 *ival = val;

	fprintf(f, "type value %s[%u-%u].%u\n", name, bitstart, bitend, *ival);
}

static void print_p4t_u16_val(const char *name, void *val, __u8 bitstart,
			      __u8 bitend, FILE *f)
{
	__u16 *ival = val;

	fprintf(f, "type value %s[%u-%u].%u\n", name, bitstart, bitend, *ival);
}

static void print_p4t_be16_val(const char *name, void *val, __u8 bitstart,
			       __u8 bitend, FILE *f)
{
	__be16 *ival = val;

	fprintf(f, "type value %s[%u-%u].%u\n", name, bitstart, bitend,
		ntohs(*ival));
}

static void print_p4t_u32_val(const char *name, void *val, __u8 bitstart,
			      __u8 bitend, FILE *f)
{
	__u32 *ival = val;

	fprintf(f, "type value %s[%u-%u].%u\n", name, bitstart, bitend, *ival);
}

static void print_p4t_be32_val(const char *name, void *val, __u8 bitstart,
			       __u8 bitend, FILE *f)
{
	__be32 *ival = val;

	fprintf(f, "type value %s[%u-%u].%u\n", name, bitstart, bitend,
		ntohl(*ival));
}


static void print_p4t_u64_val(const char *name, void *val, __u8 bitstart,
			      __u8 bitend, FILE *f)
{
	__u64 *ival = val;

	fprintf(f, "type value %s[%u-%u].%llu\n", name, bitstart, bitend,
		*ival);
}

struct p4_type_s *get_p4type_byid(int id)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (type->containid == id)
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_bysize(int sz, __u8 flags)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (type->bitsz == sz && (flags & type->flags))
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_byname(const char *name)
{
	struct hlist_node *t, *tmp_child;

	hlist_for_each_safe(t, tmp_child, &types_list) {
		struct p4_type_s *type;

		type = container_of(t, struct p4_type_s, hlist);
		if (strcasecmp(type->name, name) == 0)
			return type;
	}

	return NULL;
}

struct p4_type_s *get_p4type_byarg(const char *argv, __u32 *bitsz)
{
	struct p4_type_s *p4_type;
	int rc;

	/* fix-size integer */
	if (strncmp("bit", argv, 3) == 0 || strncmp("int", argv, 3) == 0) {
		__u8 flags = P4T_TYPE_UNSIGNED;
		__u8 containersz;

		rc = sscanf(argv, "bit%u", bitsz);
		if (rc != 1) {
			rc = sscanf(argv, "int%u", bitsz);
			if (rc != 1) {
				fprintf(stderr, "Invalid type %s\n", argv);
				return NULL;
			}
			flags = P4T_TYPE_SIGNED;
		}
		if (*bitsz <= 8) {
			containersz = 8;
		} else if (*bitsz <= 16) {
			containersz = 16;
		} else if (*bitsz <= 32) {
			containersz = 32;
		} else if (*bitsz <= 64) {
			containersz = 64;
		} else if (*bitsz <= 128) {
			containersz = 128;
		} else {
			fprintf(stderr, "bad size %d\n", *bitsz);
			return NULL;
		}

		p4_type = get_p4type_bysize(containersz, flags);
	/* Something else */
	} else {
		p4_type = get_p4type_byname(argv);
		if (!p4_type) {
			fprintf(stderr, "Unknown p4 type %s\n", argv);
			return NULL;
		}
		*bitsz = p4_type->bitsz;
	}

	return p4_type;
}

static struct p4_type_s u8_typ = {
	.containid = P4T_U8,
	.bitsz = 8,
	.startbit = 0,
	.endbit = 7,
	.parse_p4t = parse_p4t_u8_val,
	.print_p4t = print_p4t_u8_val,
	.name = "bit8",
	.flags = P4T_TYPE_UNSIGNED,
};
static struct p4_type_s u16_typ = {
	.containid = P4T_U16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_u16_val,
	.print_p4t = print_p4t_u16_val,
	.name = "bit16",
	.flags = P4T_TYPE_UNSIGNED,
};

static struct p4_type_s u32_typ = {
	.containid = P4T_U32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_u32_val,
	.print_p4t = print_p4t_u32_val,
	.name = "bit32",
	.flags = P4T_TYPE_UNSIGNED,
};

static struct p4_type_s be32_typ = {
	.containid = P4T_BE32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_be32_val,
	.print_p4t = print_p4t_be32_val,
	.name = "be32",
	.flags = P4T_TYPE_BIGENDIAN,
};

static struct p4_type_s u64_typ = {
	.containid = P4T_U64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.parse_p4t = parse_p4t_u64_val,
	.print_p4t = print_p4t_u64_val,
	.name = "bit64",
	.flags = P4T_TYPE_UNSIGNED,
};
static struct p4_type_s u128_typ = {
	.containid = P4T_U128,
	.parse_p4t = NULL,
	.print_p4t = NULL,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "bit128",
	.flags = P4T_TYPE_UNSIGNED,
};

static struct p4_type_s s8_typ = {
	.containid = P4T_S8,
	.bitsz = 8,
	.startbit = 0,
	.endbit = 7,
	.parse_p4t = parse_p4t_s8_val,
	.print_p4t = NULL,
	.name = "int8",
	.flags = P4T_TYPE_SIGNED,
};

static struct p4_type_s s16_typ = {
	.containid = P4T_S16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_s16_val,
	.print_p4t = NULL,
	.name = "int16",
	.flags = P4T_TYPE_SIGNED,
};

static struct p4_type_s be16_typ = {
	.containid = P4T_BE16,
	.bitsz = 16,
	.startbit = 0,
	.endbit = 15,
	.parse_p4t = parse_p4t_be16_val,
	.print_p4t = print_p4t_be16_val,
	.name = "be16",
	.flags = P4T_TYPE_BIGENDIAN,
};

static struct p4_type_s s32_typ = {
	.containid = P4T_S32,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_s32_val,
	.print_p4t = NULL,
	.name = "int32",
	.flags = P4T_TYPE_SIGNED,
};

static struct p4_type_s s64_typ = {
	.containid = P4T_S64,
	.bitsz = 64,
	.startbit = 0,
	.endbit = 63,
	.name = "int64",
	.flags = P4T_TYPE_SIGNED,
};

static struct p4_type_s s128_typ = {
	.containid = P4T_S128,
	.bitsz = 128,
	.startbit = 0,
	.endbit = 127,
	.name = "int128",
	.flags = P4T_TYPE_SIGNED,
};

static struct p4_type_s string_typ = {
	.containid = P4T_STRING,
	.bitsz = P4T_MAX_STR_SZ * 8,
	.startbit = BITSZ_IRRELEVANT,
	.endbit = BITSZ_IRRELEVANT,
	.name = "strn"
};

static struct p4_type_s nulstring_typ = {
	.containid = P4T_NUL_STRING,
	.bitsz = P4T_MAX_STR_SZ * 8,
	.startbit = BITSZ_IRRELEVANT,
	.endbit = BITSZ_IRRELEVANT,
	.name = "nstrn"
};

static struct p4_type_s mac_typ = {
	.containid = P4T_MACADDR,
	.parse_p4t = NULL,
	.print_p4t = NULL,
	.bitsz = 48,
	.startbit = 0,
	.endbit = 47,
	.name = "macaddr"
};

static struct p4_type_s ipv4_typ = {
	.containid = P4T_IPV4ADDR,
	.parse_p4t = parse_p4t_ipv4_val,
	.print_p4t = NULL,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.name = "ipv4"
};

void register_p4_types(void)
{
	hlist_add_head(&u8_typ.hlist, &types_list);
	hlist_add_head(&u16_typ.hlist, &types_list);
	hlist_add_head(&u32_typ.hlist, &types_list);
	hlist_add_head(&u64_typ.hlist, &types_list);
	hlist_add_head(&u128_typ.hlist, &types_list);
	hlist_add_head(&s8_typ.hlist, &types_list);
	hlist_add_head(&s16_typ.hlist, &types_list);
	hlist_add_head(&s32_typ.hlist, &types_list);
	hlist_add_head(&s64_typ.hlist, &types_list);
	hlist_add_head(&s128_typ.hlist, &types_list);
	hlist_add_head(&be16_typ.hlist, &types_list);
	hlist_add_head(&be32_typ.hlist, &types_list);
	hlist_add_head(&string_typ.hlist, &types_list);
	hlist_add_head(&nulstring_typ.hlist, &types_list);
	hlist_add_head(&mac_typ.hlist, &types_list);
	hlist_add_head(&ipv4_typ.hlist, &types_list);
}

void unregister_p4_types(void)
{
	hlist_del(&u8_typ.hlist);
	hlist_del(&u16_typ.hlist);
	hlist_del(&u32_typ.hlist);
	hlist_del(&u64_typ.hlist);
	hlist_del(&u128_typ.hlist);
	hlist_del(&s8_typ.hlist);
	hlist_del(&s16_typ.hlist);
	hlist_del(&s32_typ.hlist);
	hlist_del(&s64_typ.hlist);
	hlist_del(&s128_typ.hlist);
	hlist_del(&be16_typ.hlist);
	hlist_del(&be32_typ.hlist);
	hlist_del(&string_typ.hlist);
	hlist_del(&nulstring_typ.hlist);
	hlist_del(&mac_typ.hlist);
	hlist_del(&ipv4_typ.hlist);
}
