#include "p4_types.h"

#define P4T_TYPE_UNSIGNED 0x1
#define P4T_TYPE_SIGNED 0x2
#define P4T_TYPE_BIGENDIAN 0x4

#define BITSZ_IRRELEVANT 0

static struct hlist_head types_list = {};

static int parse_p4t_u8_val(struct p4_type_value *val, const char *arg, int base)
{
	__u8 *newval = val->value;
	__u8 ival;


	if (get_u8(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_s8_val(struct p4_type_value *val, const char *arg, int base)
{
	__s8 *newval = val->value;
	__s8 ival;

	if (get_s8(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u16_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u16 *newval = val->value;
	__u16 ival;

	if (get_u16(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_s16_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__s16 *newval = val->value;
	__s16 ival;

	if (get_s16(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_be16_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be16 *newval = val->value;
	__be16 ival;

	if (get_be16(&ival, arg, base))
		return -1;

	*newval = htons(ival);
	return 0;
}

static int parse_p4t_s32_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__s32 *newval = val->value;
	__s32 ival;

	if (get_s32(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u64_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u64 *newval = val->value;
	__u64 ival;

	if (get_u64(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_u32_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	__u32 *newval = val->value;
	__u32 ival;

	if (get_u32(&ival, arg, base))
		return -1;

	*newval = ival;
	return 0;
}

static int parse_p4t_bool_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u32 *newval = val->value;

	if (strcmp(arg, "true") == 0) {
		*newval = true;
	} else if (strcmp(arg, "false") == 0) {
		*newval = false;
	} else {
		fprintf(stderr, "Unknown boolean value %s\n", arg);
		return -1;
	}

	return 0;
}

static int parse_p4t_be32_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__be32 *newval = val->value;
	__be32 ival;

	if (get_be32(&ival, arg, base))
		return -1;

	*newval = htonl(ival);
	return 0;
}

static int parse_p4t_ipv4_val(struct p4_type_value *val, const char *arg,
			      int base)
{
	__u32 *newaddr = val->value;
	__u32 *new_mask = val->mask;
	inet_prefix iaddr;

	if (get_prefix_1(&iaddr, (char *)arg, AF_INET))
		return -1;

	memcpy(newaddr, iaddr.data, sizeof(__u32));
	*new_mask = htonl(~0u << (32 - iaddr.bitlen));

	return 0;
}

static int parse_p4t_dev_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	const char *devname = arg;
	__u32 *newval = val->value;
	int idx;

	idx = ll_name_to_index(devname);
	if (!idx) {
		fprintf(stderr, "Invalid dev %s\n", devname);
		return -1;
	}

	*newval = idx;

	return 0;
}

static int parse_p4t_mac_val(struct p4_type_value *val, const char *arg,
			     int base)
{
	char *newval = val->value;

	if (ll_addr_a2n(newval, ETH_ALEN, arg) < 0) {
		fprintf(stderr, "mac is invalid %s\n", newval);
		return -1;
	}

	return 0;
}

static void print_p4t_u8_val(const char *name, struct p4_type_value *val,
			     FILE *f)
{
	__u8 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", *ival);
}

static void print_p4t_u16_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	__u16 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", *ival);
}

static void print_p4t_be16_val(const char *name, struct p4_type_value *val,
			       FILE *f)
{
	__be16 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", *ival);
}

static void print_p4t_u32_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	__u32 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", *ival);
}

static void print_p4t_bool_val(const char *name, struct p4_type_value *val,
			       FILE *f)
{
	bool *ival = val->value;

	print_bool(PRINT_ANY, "value", "value %s", *ival);
}

static void print_p4t_s32_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	__s32 *ival = val->value;

	print_int(PRINT_ANY, "value", "value %d", *ival);
}

static void print_p4t_be32_val(const char *name, struct p4_type_value *val,
			       FILE *f)
{
	__be32 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", ntohl(*ival));
}


static void print_p4t_u64_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	__u64 *ival = val->value;

	print_uint(PRINT_ANY, "value", "value %u", *ival);
}

static void print_p4t_dev_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	const char *ifname = val->value;

	print_string(PRINT_ANY, "value", "value %s", ifname);
}

static void print_p4t_mac_val(const char *name, struct p4_type_value *val,
			      FILE *f)
{
	unsigned char *mac_val = val->value;
	SPRINT_BUF(b1);

	ll_addr_n2a(mac_val, ETH_ALEN, 0, b1, sizeof(b1));
	print_string(PRINT_ANY, "value", "value %s", b1);
}

static void print_p4t_ipv4_val(const char *name, struct p4_type_value *val,
			       FILE *f)
{
	__u8 *addr = val->value;
	SPRINT_BUF(buf1);
	SPRINT_BUF(buf2);
	__be32 mask_val;
	int len;

	mask_val = htonl((*(__be32 *)val->mask));
	len = ffs(mask_val);
	len = len ? 33 - len : 0;
	snprintf(buf2, sizeof(buf2), "%s/%d",
		 format_host_r(AF_INET, 4, addr, buf1, sizeof(buf1)),
		 len);

	print_string(PRINT_ANY, "value", "value %s", buf2);
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

static struct p4_type_s dev_typ = {
	.containid = P4T_DEV,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.parse_p4t = parse_p4t_dev_val,
	.print_p4t = print_p4t_dev_val,
	.name = "dev",
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
	.print_p4t = print_p4t_s32_val,
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
	.parse_p4t = parse_p4t_mac_val,
	.print_p4t = print_p4t_mac_val,
	.bitsz = 48,
	.startbit = 0,
	.endbit = 47,
	.name = "macaddr"
};

static struct p4_type_s ipv4_typ = {
	.containid = P4T_IPV4ADDR,
	.parse_p4t = parse_p4t_ipv4_val,
	.print_p4t = print_p4t_ipv4_val,
	.bitsz = 32,
	.startbit = 0,
	.endbit = 31,
	.name = "ipv4"
};

static struct p4_type_s bool_typ = {
	.containid = P4T_BOOL,
	.bitsz = 1,
	.startbit = 0,
	.endbit = 0,
	.parse_p4t = parse_p4t_bool_val,
	.print_p4t = print_p4t_bool_val,
	.name = "bool",
};

static struct p4_type_s key_typ = {
	.containid = P4T_KEY,
	.bitsz = P4TC_MAX_KEYSZ,
	.startbit = 0,
	.endbit = P4TC_MAX_KEYSZ - 1,
	.name = "key",
};

void register_p4_types(void)
{
	hlist_add_head(&u8_typ.hlist, &types_list);
	hlist_add_head(&u16_typ.hlist, &types_list);
	hlist_add_head(&u32_typ.hlist, &types_list);
	hlist_add_head(&bool_typ.hlist, &types_list);
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
	hlist_add_head(&dev_typ.hlist, &types_list);
	hlist_add_head(&key_typ.hlist, &types_list);
}

void unregister_p4_types(void)
{
	hlist_del(&u8_typ.hlist);
	hlist_del(&u16_typ.hlist);
	hlist_del(&u32_typ.hlist);
	hlist_del(&bool_typ.hlist);
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
	hlist_del(&dev_typ.hlist);
	hlist_del(&key_typ.hlist);
}
