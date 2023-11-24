/* SPDX-License-Identifier: GPL-2.0 */
#ifndef WH_PARSE_EXPR_H_0e136a48_
#define WH_PARSE_EXPR_H_0e136a48_

#include <stdint.h>
#include <strings.h>
#include <utils.h>

/*
 * Rudimentary expression parser.
 *
 * The input string takes the form of a length and a function to
 *  retrieve the character at a given offset <= the length.  The output
 *  takes the form of a parse tree, stored as a self-recursive struct
 *  parsedexpr.
 *
 * Operators supported, in order of precedence
 *
 *	all unary operators (~, !, unary -, unary +)
 *	*, %, ?
 *	binary -, binary +
 *	<<, >>
 *	=, ==, !=, /=, <>, <, <=, >, >=
 *	&
 *	^
 *	|
 *	@in (see below for more)
 *	&&
 *	^^
 *	||
 *	ternary (? :)
 *
 * Operands can be constants or names; names are unbroken strings of
 *  letters, digits, underscores, dots, and slashes, not beginning with
 *  a digit.  The meaning of names is beyond the scope of this parser;
 *  assigning meanings to names must be handled elsewhere.
 *
 * Note that, in contrast to C, = is a comparison, equivalent to ==,
 *  and /= is not-equal, not divide-and-assign.  Also, <>, which is an
 *  error in C, is supported as a third form of not-equal, and ^^, also
 *  an error in C, is logical XOR.  Also unlike C, there is a hard
 *  distinction between boolean values and integer values - mixing
 *  them, treating a boolean as an integer or vice versa, is an error.
 *  This means Boolean constants are desirable; they are spelled @true
 *  and @false.  (They are not, strictly, necessary; (0==0) and (0==1)
 *  amount to the same thing in practice, but they are slower and at
 *  least a little more cryptic.)
 *
 * Furthermore, division is ?, not /, because / can appear in names.
 *
 * Multiple types are supported.  All the integer types can be freely
 *  intermixed; narrower types promote to wider types as necessary.
 *  Booleans cannot, as mentioned above, be mixed with any other type.
 *  All the string types are operationally identical, since they all
 *  use the same representation.  The remaining two types - IP address
 *  and IEEE MAC address - are distinct so they can have idiosyncratic
 *  representations and operations.
 *
 * @in is used with IP addresses and MAC addresses.  IP addresses can
 *  have a mask width appended, as in 172.16.40.32/28 or
 *  fe80:0:a00::/48, and MAC addresses can have don't-care nibbles, as
 *  in f2:0b:a4:xx:xx:xx.  When compared for (in)equality, or when on
 *  the left-hand side of @in, mask widths are ignored and bits below
 *  the mask (for addresses) and don't-care bits (for MACs) are treated
 *  as zero.  When on the right-hand side of @in, widths and don't-care
 *  bits are used to tell whether the address on the LHS falls into the
 *  set of addresses represented by the RHS.
 *
 * If we write IPv6 addresses and MAC addresses undecorated, there is a
 *  parsing ambiguity: is (x>5)?20: a ternary operator about to accept
 *  its RHS, or is it a partial ternary operator whose incomplete MHS
 *  is an IPv6 or MAC address?  I see no good way to disambiguate, so
 *  until someone suggests something better, I'm requiring IP addresses
 *  and MAC addresses to have identifying prefixes.  Specifically:
 *
 * An IPv4 address, possibly with width appended, requires a prefix
 *  @4:, as in
 *
 *	addr @in @4:172.16.0.0/16
 *
 * An IPv6 address, possibly with a width appended, requires a prefix
 *  @6:, as in
 *
 *	addr @in @6:fe80::/16
 *
 * A MAC address, possibly with don't-care nibbles, requires a prefix
 *  @MAC:, as in
 *
 *	ethsrc @in @MAC:08:00:20:xx:xx:xx
 */

/*
 * The unary operators available.
 */
enum unary_op {
	U_ERR = 1, // not a unary operator
	U_MINUS, // -
	U_LOGNOT, // !
};

/*
 * The binary operators available.
 */
enum binary_op {
	B_ERR = 1, // not a binary operator
	B_EQ, // =, ==
	B_NE, // !=, /=, <>
	B_LT, // <
	B_GT, // >
	B_LE, // <=
	B_GE, // >=
	B_LOGAND, // &&
	B_LOGOR, // ||
	B_LOGXOR, // ^^
};

/*
 * The types an expression can have.  ET_ERR is used for errors and
 *  nothing else - see the comment on parse_expr().  ET_VAL is used for
 *  constant values, ET_NAME for names, and ET_UNARY, and ET_BINARY
 *  for expressions using unary, binary, and operators, respectively.
 *
 * Arguably the types used for constants - ET_INTEGER, ET_STRING,
 *  ET_IPv4, ET_IPv6, and ET_MAC - should not be here, instead being
 *  replaced by a generic ET_CONST which has a further discriminant.
 *  We may want to change to that scheme eventually.
 */
enum exprtype {
	ET_ERR = 1,
	ET_BOOL,
	ET_INTEGER,
	ET_STRING,
	ET_IPv4,
	ET_IPv6,
	ET_MAC,
	ET_NAME,
	ET_UNARY,
	ET_BINARY,
};

/*
 * There is no op field in ternary because there is only one ternary
 *  operator (if we ever add another ternary operator this will have to
 *  change).
 *
 * The done and donearg fields in string exist to deal with cleaning up
 *  possibly-large amounts of memory allocated for the txt field.  They
 *  are set by whatever sets up the txt field; they must be called
 *  whenever it is time to dispose of it, to avoid leaking memory.  If
 *  x is the struct parsedexpr * being disposed of, the call looks like
 *  (*x->string.done)(x,x->string.donearg).
 *
 * ET_IPv4 and ET_IPv6 width values are set to -1 if no width at all
 *  was specified.  For ET_MAC, a is the address and m is the mask (for
 *  representing MACs like 10:20:30:xx:xx:xx).
 */
struct parsedexpr;

struct parsedexpr {
	enum exprtype t;
	union {
		const char *errmsg; // ET_ERR
		struct { // ET_BOOL
			int v; // only 0 and 1 allowed
		} boolean;
		struct { // ET_INTEGER
			char *s;
			__u64 i;
		} integer;
		struct { // ET_STRING
			unsigned char *txt;
			int len;
			void (*done)(struct parsedexpr *e, void *str);
			void *donearg;
		} string;
		struct { // ET_IPv4
			unsigned char a[4];
			int width;
		} ipv4;
		struct { // ET_IPv6
			unsigned char a[16];
			int width;
		} ipv6;
		struct { // ET_MAC
			unsigned char a[6];
			unsigned char m[6];
		} mac;
		struct { // ET_NAME
			char *name;
			void *data;
		} name;
		struct { // ET_UNARY
			enum unary_op op; // U_*
			struct parsedexpr *arg;
		} unary;
		struct { // ET_BINARY
			struct parsedexpr *lhs;
			enum binary_op op; // B_*
			struct parsedexpr *rhs;
		} binary;
	};
};

/*
 * Main parser entry point.  Arguments:
 *
 *	1) string length
 *	2) callback: return the string character at a given offset
 *	3) opaque pointer passed to (2)
 *
 * Return value is the struct parsedexpr.  On error, the returned struct parsedexpr
 *  is of type ET_ERR (which does not otherwise occur), with errmsg
 *  pointing to an error message string.
 *
 * ET_ERR errmsg strings are not guaranteed to remain valid after the
 *  next call into the parser, even if the returned struct parsedexpr pointer
 *  is not freed.  Other strings, in constrast, remain valid until the
 *  containing struct parsedexpr tree is freed.
 */
struct parsedexpr *parse_expr(int slen, char (*)(int o, void *cbarg), void *cbarg);

/*
 * Convenience wrapper for parse_expr that takes a const char * and
 *  length rather than a length and callback.  Except for how the chars
 *  are obtained, this is identical to parse_expr.
 *
 * As a further convenience, if the second argument is negative, strlen
 *  is called on the first argument and the result is used as the
 *  length.
 */
struct parsedexpr *parse_expr_string(const char *str, int length);

/*
 * Convenience wrapper for parse_expr that takes an argc/argv-style
 *  array-of-strings rather than a length and callback.  Conceptually,
 *  it is still parsing a single string, formed by concatenating all
 *  the argv[] elements with a space as the separator.  But this string
 *  is not actually materialized anywhere; it is synthesized on the fly
 *  internally.
 *
 * For the sake of its principal anticipated use case, this actually
 *  takes not argc and argv, but pointers to them.  It updates the
 *  pointed-to values as it goes.
 *
 * The code does not do anything with (to use the argc/argv names)
 *  argv[i] for i outside [0..argc).  In particular, in contrast to the
 *  paradigmmatic argc/argv scheme specified by C for calls to main(),
 *  there is no requirement that argv[argc] be anything in particular.
 *
 * Except for the first two arguments, this is identical to parse_expr.
 */
struct parsedexpr *parse_expr_args(int *, const char * const **, void *);

/*
 * Walk an expression recursively.
 *
 * The struct parsedexpr is walked, calling the callbacks for each node.  The
 *  first callback is called before a node's children are processed;
 *  the second, after.  If the node doesn't have children, the second
 *  callback is called immediately after the first.  Either callback
 *  may be nil, in which case that call is skipped.  (Actually, both
 *  may be, but such calls are useless.)
 *
 * The last argument is a cookie passed as the second argument whenever
 *  a callback is called.
 *
 * The callback can also throw out, with things such as longjmp or a
 *  gcc nested goto.
 *
 * For more complicated tasks, such as generating a text form of the
 *  parsed expression, it is generally best to do your own recursive
 *  walk of the struct parsedexpr tree.
 */
void walk_parsedexpr(struct parsedexpr *e,
		     void (*pre)(struct parsedexpr *e, void *cbarg),
		     void (*post)(struct parsedexpr *e, void *cbarg),
		     void *cbarg);

/*
 * Free up a struct parsedexpr tree.
 */
void free_parsedexpr(struct parsedexpr *e);

void dump_expr(struct parsedexpr *e, int indent);

#endif
