/*
 * parser_expr.c		P4 TC Expression Parser for Filters
 *
 *		This program is free software; you can distribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2022-24, Mojatatu Networks
 * Copyright (c) 2022-24, Intel Corporation.
 * Authors:     Jamal Hadi Salim <jhs@mojatatu.com>
 *              Victor Nogueira <victor@mojatatu.com>
 *              Pedro Tammela <pctammela@mojatatu.com>
 */

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "p4tc_filter_parser.h"

struct es {
	unsigned char *b;
	int a;
	int l;
};

struct strwrap {
	const char *s;
	int l;
};

struct ctx {
	int len;
	int o;
	char (*gc)(int o, void *cbarg);
	void *cbarg;
};

struct argpriv {
	int *acp;
	const char * const **avp;
	int ac;
	const char *const *av;
	int *lv;
	int *plv;
	int lastx;
	char lastc;
	int nextx;
	int nextax;
	int nextowa;
	int lt;
	void *cbarg;
};

#define Cisspace(x) isspace((unsigned char)(x))
#define Cisdigit(x) isdigit((unsigned char)(x))

static struct parsedexpr err_pe;

static struct parsedexpr *parse_top(struct ctx *); // forward

static int end(struct ctx *c)
{
	return c->o >= c->len;
}

static char get(struct ctx *c)
{
	if (c->o >= c->len)
		abort();
	return (*c->gc)(c->o++, c->cbarg);
}

static void unget(struct ctx *c)
{
	if (c->o < 1)
		abort();
	c->o--;
}

static void skipwhite(struct ctx *c)
{
	char ch;

	while (1) {
		if (end(c))
			return;
		ch = get(c);
		if (!Cisspace(ch)) {
			unget(c);
			return;
		}
	}
}

static struct parsedexpr *err_expr(const char *msg)
{
	err_pe.t = ET_ERR;
	err_pe.errmsg = msg;
	return &err_pe;
}

static void es_init(struct es *es)
{
	es->b = 0;
	es->a = 0;
	es->l = 0;
}

static void es_done(struct es *es)
{
	free(es->b);
	es->b = 0;
}

static void *es_buf(struct es *es)
{
	return es->b;
}

static int es_len(struct es *es)
{
	return es->l;
}

static int es_append_1(struct es *es, unsigned char ch)
{
	if (es->l >= es->a) {
		unsigned char *b2;

		b2 = realloc(es->b, es->a = es->l + 8);
		if (!b2) {
			free(es->b);
			return 1;
		}
		es->b = b2;
	}
	es->b[es->l++] = ch;
	return 0;
}

static struct parsedexpr *parse_unary(struct ctx *c,
				      enum unary_op (*op)(struct ctx *ctx),
				      struct parsedexpr *(*sub)(struct ctx *ctx))
{
	struct parsedexpr *rv;
	struct parsedexpr **xp;
	enum unary_op uo;
	struct parsedexpr *e;

	skipwhite(c);
	if (end(c))
		return err_expr("no expression found");
	xp = &rv;
	while (1) {
		uo = (*op)(c);
		if (uo == U_ERR)
			break;
		e = malloc(sizeof(struct parsedexpr));
		if (!e) {
			*xp = 0;
			free_parsedexpr(rv);
			return err_expr("malloc() failed");
		}
		e->t = ET_UNARY;
		e->unary.op = uo;
		*xp = e;
		xp = &e->unary.arg;
	}
	e = (*sub)(c);
	if (e->t == ET_ERR) {
		*xp = 0;
		free_parsedexpr(rv);
		return e;
	}
	*xp = e;
	return rv;
}

static struct parsedexpr *
parse_binary_left(struct ctx *c, enum binary_op (*op)(struct ctx *ctx),
		  struct parsedexpr *(*sub)(struct ctx *ctx))
{
	struct parsedexpr *lhs;
	struct parsedexpr *rhs;
	struct parsedexpr *e;
	enum binary_op bo;

	lhs = (*sub)(c);
	if (lhs->t == ET_ERR)
		return lhs;
	while (1) {
		skipwhite(c);
		if (end(c))
			return lhs;
		bo = (*op)(c);
		if (bo == B_ERR)
			return lhs;
		rhs = (*sub)(c);
		if (rhs->t == ET_ERR) {
			free_parsedexpr(lhs);
			return rhs;
		}
		e = malloc(sizeof(struct parsedexpr));
		if (!e) {
			free_parsedexpr(lhs);
			free_parsedexpr(rhs);
			return err_expr("malloc() failed");
		}
		e->t = ET_BINARY;
		e->binary.lhs = lhs;
		e->binary.op = bo;
		e->binary.rhs = rhs;
		lhs = e;
	}
}

static struct parsedexpr *parse_binary_non(struct ctx *c, enum binary_op (*op)(struct ctx *),
				    struct parsedexpr *(*sub)(struct ctx *))
{
	struct parsedexpr *lhs;
	enum binary_op bo;
	struct parsedexpr *rhs;
	struct parsedexpr *e;

	lhs = (*sub)(c);
	if (lhs->t == ET_ERR)
		return lhs;
	skipwhite(c);
	if (end(c))
		return lhs;
	bo = (*op)(c);
	if (bo == B_ERR)
		return lhs;
	rhs = (*sub)(c);
	if (rhs->t == ET_ERR) {
		free_parsedexpr(lhs);
		return rhs;
	}
	e = malloc(sizeof(struct parsedexpr));
	if (!e) {
		free_parsedexpr(lhs);
		free_parsedexpr(rhs);
		return err_expr("malloc() failed");
	}
	e->t = ET_BINARY;
	e->binary.lhs = lhs;
	e->binary.op = bo;
	e->binary.rhs = rhs;
	return e;
}

static unsigned int digitval(char ch)
{
	switch (ch) {
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'a':
	case 'A':
		return 10;
	case 'b':
	case 'B':
		return 11;
	case 'c':
	case 'C':
		return 12;
	case 'd':
	case 'D':
		return 13;
	case 'e':
	case 'E':
		return 14;
	case 'f':
	case 'F':
		return 15;
	}
	return 16;
}

static struct parsedexpr *parse_parens(struct ctx *c)
{
	struct parsedexpr *e;
	char ch;

	e = parse_top(c);
	if (e->t == ET_ERR)
		return e;
	skipwhite(c);
	if (end(c)) {
		free_parsedexpr(e);
		return err_expr("unclosed (");
	}
	ch = get(c);
	if (ch != ')') {
		free_parsedexpr(e);
		return err_expr("improperly closed (");
	}
	return e;
}

static struct parsedexpr *parse_number(struct ctx *c, char ch)
{
	unsigned int base;
	struct parsedexpr *e;
	unsigned int dv;
	long long v;
	int ndigs;
	struct es s;

	es_init(&s);
	do {
		base = 10;
		ndigs = 0;
		if (ch == '0') {
			es_append_1(&s, ch);
			if (end(c)) {
				v = 0;
				break;
			}
			ch = get(c);
			if ((ch == 'x') || (ch == 'X')) {
				es_append_1(&s, ch);
				base = 16;
			} else {
				base = 8;
				ndigs = 1;
				unget(c);
			}
		} else {
			unget(c);
		}
		v = 0;
		dv = 0; // in case end(c) is true
		while (1) {
			if (end(c))
				break;
			ch = get(c);
			dv = digitval(ch);
			if (dv >= base) {
				unget(c);
				break;
			}
			es_append_1(&s, ch);
			v = (v * base) + dv;
			ndigs++;
		}
		if (ndigs == 0) {
			es_done(&s);
			return err_expr("incomplete constant");
		}
	} while (0);
	e = malloc(sizeof(struct parsedexpr));
	if (!e)
		return err_expr("malloc() failed");
	e->t = ET_INTEGER;
	e->integer.i = v;
	es_append_1(&s, '\0');
	e->integer.s = es_buf(&s);
	return e;
}

static void free_simple(struct parsedexpr *v, void *fv)
{
	(void)v;
	free(fv);
}

static struct parsedexpr *parse_string(struct ctx *c)
{
	struct es s;
	char ch;
	unsigned char chv;
	int bq;
	int octn;
	struct parsedexpr *e;

	es_init(&s);
	bq = 0;
	// Apparently some compilers are too stupid to figure out that chv and
	//  octn are always set before they're used - but also too stupid to
	//  know that, generating a warning anyway.  And apparently we're not
	//  willing to shut off warning options just because they're broken in
	//  ways like this.  So we waste cycles instead.  :-?
	chv = 0;
	octn = 0;
	while (1) {
		if (end(c)) {
			es_done(&s);
			return err_expr("unclosed string constant");
		}
		ch = get(c);
		if (bq) {
			if (octn) {
				switch (ch) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					if (octn < 3) {
						chv = (chv << 3) | (ch - '0');
						octn++;
						continue;
					}
					/* fall through */
				default:
					unget(c);
					bq = 0;
					break;
				}
			} else {
				switch (ch) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					chv = ch - '0';
					octn = 1;
					continue;
					break;
				case 'a':
					chv = 7;
					break;
				case 'b':
					chv = 8;
					break;
				case 'e':
					chv = 27;
					break;
				case 'n':
					chv = 10;
					break;
				case 'r':
					chv = 13;
					break;
				case 't':
					chv = 9;
					break;
				default:
					chv = ch;
					break;
				}
				bq = 0;
			}
		} else {
			switch (ch) {
			case '\\':
				bq = 1;
				octn = 0;
				continue;
			case '"':
				e = malloc(sizeof(struct parsedexpr));
				e->t = ET_STRING;
				e->string.txt = es_buf(&s);
				e->string.len = es_len(&s);
				e->string.done = &free_simple;
				e->string.donearg = e->string.txt;
				return e;
			}
			chv = ch;
		}
		if (es_append_1(&s, chv))
			return err_expr("realloc() failed");
	}
}

static struct parsedexpr *parse_base64_string(struct ctx *c)
{
	unsigned int cv;
	struct parsedexpr *e;
	struct es s;
	__u32 acc;
	int accn;
	char ch;

	es_init(&s);
	acc = 0;
	accn = 0;
	while (1) {
		if (end(c)) {
			es_done(&s);
			return err_expr("unclosed base-64 constant");
		}
		ch = get(c);
		switch (ch) {
		case 'A':
			cv = 0;
			break;
		case 'B':
			cv = 1;
			break;
		case 'C':
			cv = 2;
			break;
		case 'D':
			cv = 3;
			break;
		case 'E':
			cv = 4;
			break;
		case 'F':
			cv = 5;
			break;
		case 'G':
			cv = 6;
			break;
		case 'H':
			cv = 7;
			break;
		case 'I':
			cv = 8;
			break;
		case 'J':
			cv = 9;
			break;
		case 'K':
			cv = 10;
			break;
		case 'L':
			cv = 11;
			break;
		case 'M':
			cv = 12;
			break;
		case 'N':
			cv = 13;
			break;
		case 'O':
			cv = 14;
			break;
		case 'P':
			cv = 15;
			break;
		case 'Q':
			cv = 16;
			break;
		case 'R':
			cv = 17;
			break;
		case 'S':
			cv = 18;
			break;
		case 'T':
			cv = 19;
			break;
		case 'U':
			cv = 20;
			break;
		case 'V':
			cv = 21;
			break;
		case 'W':
			cv = 22;
			break;
		case 'X':
			cv = 23;
			break;
		case 'Y':
			cv = 24;
			break;
		case 'Z':
			cv = 25;
			break;
		case 'a':
			cv = 26;
			break;
		case 'b':
			cv = 27;
			break;
		case 'c':
			cv = 28;
			break;
		case 'd':
			cv = 29;
			break;
		case 'e':
			cv = 30;
			break;
		case 'f':
			cv = 31;
			break;
		case 'g':
			cv = 32;
			break;
		case 'h':
			cv = 33;
			break;
		case 'i':
			cv = 34;
			break;
		case 'j':
			cv = 35;
			break;
		case 'k':
			cv = 36;
			break;
		case 'l':
			cv = 37;
			break;
		case 'm':
			cv = 38;
			break;
		case 'n':
			cv = 39;
			break;
		case 'o':
			cv = 40;
			break;
		case 'p':
			cv = 41;
			break;
		case 'q':
			cv = 42;
			break;
		case 'r':
			cv = 43;
			break;
		case 's':
			cv = 44;
			break;
		case 't':
			cv = 45;
			break;
		case 'u':
			cv = 46;
			break;
		case 'v':
			cv = 47;
			break;
		case 'w':
			cv = 48;
			break;
		case 'x':
			cv = 49;
			break;
		case 'y':
			cv = 50;
			break;
		case 'z':
			cv = 51;
			break;
		case '0':
			cv = 52;
			break;
		case '1':
			cv = 53;
			break;
		case '2':
			cv = 54;
			break;
		case '3':
			cv = 55;
			break;
		case '4':
			cv = 56;
			break;
		case '5':
			cv = 57;
			break;
		case '6':
			cv = 58;
			break;
		case '7':
			cv = 59;
			break;
		case '8':
			cv = 60;
			break;
		case '9':
			cv = 61;
			break;
		case '+':
			cv = 62;
			break;
		case '/':
			cv = 63;
			break;
		case '"':
			switch (accn) {
			case 0:
				break;
			case 1:
				if (es_append_1(&s, acc << 2))
					return err_expr("realloc() failed");
				break;
			case 2:
				if (es_append_1(&s, acc >> 4))
					return err_expr("realloc() failed");
				if (es_append_1(&s, (acc << 4) & 0xff))
					return err_expr("realloc() failed");
				break;
			default:
				abort();
				break;
			}
			e = malloc(sizeof(struct parsedexpr));
			e->t = ET_STRING;
			e->string.txt = es_buf(&s);
			e->string.len = es_len(&s);
			e->string.done = &free_simple;
			e->string.donearg = e->string.txt;
			return e;
		}
		acc = (acc << 6) | cv;
		accn++;
		if (accn < 3)
			continue;
		if (es_append_1(&s, (acc >> 16) & 0xff) ||
		    es_append_1(&s, (acc >> 8) & 0xff) ||
		    es_append_1(&s, acc & 0xff))
			return err_expr("realloc() failed");
		acc = 0;
		accn = 0;
	}
}

static struct parsedexpr *parse_primary(struct ctx *c)
{
	struct parsedexpr *e;
	struct es s;
	char ch;

	skipwhite(c);
	if (end(c))
		return err_expr("missing expression");
	ch = get(c);

	switch (ch) {
	case '(':
		return parse_parens(c);
	case '"':
		return parse_string(c);
	}
	if (Cisdigit(ch))
		return parse_number(c, ch);
	unget(c);
	es_init(&s);
	while (1) {
		if (end(c))
			break;
		ch = get(c);
		switch (ch) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
		case '_':
		case '.':
		case '/':
			if (es_append_1(&s, ch))
				return err_expr("realloc() failed");
			continue;
		}
		unget(c);
		break;
	}
	if (es_len(&s) < 1) {
		es_done(&s);
		return err_expr("syntax error");
	}
	if ((es_len(&s) == 3) && !strncasecmp(es_buf(&s), "b64", 3) &&
	    !end(c)) {
		ch = get(c);
		if (ch == '"') {
			es_done(&s);
			return parse_base64_string(c);
		}
		unget(c);
	}
	e = malloc(sizeof(struct parsedexpr));
	if (!e) {
		es_done(&s);
		return err_expr("malloc() failed");
	}
	if ((es_len(&s) == 4) && !strncmp(es_buf(&s),"True",4)) {
		e->t = ET_BOOL;
		e->boolean.v = 1;
		return e;
	}
	if ((es_len(&s) == 5) && !strncmp(es_buf(&s),"False",5)) {
		e->t = ET_BOOL;
		e->boolean.v = 0;
		return e;
	}
	es_append_1(&s, '\0');
	e->t = ET_NAME;
	e->name.data = 0;
	e->name.name = es_buf(&s);
	return e;
}

static int onechar(struct ctx *c, char ch1, const char *nofollow)
{
	char ch;

	ch = get(c);
	if (ch != ch1) {
		unget(c);
		return 0;
	}
	if (nofollow && !end(c)) {
		ch = get(c);
		unget(c);
		if (index(nofollow, ch)) {
			unget(c);
			return 0;
		}
	}
	return 1;
}

static int twochar(struct ctx *c, char ch1, char ch2)
{
	char ch;

	ch = get(c);
	if (ch != ch1 || end(c)) {
		unget(c);
		return 0;
	}
	ch = get(c);
	if (ch != ch2) {
		unget(c);
		unget(c);
		return 0;
	}
	return 1;
}

static enum unary_op op_unary(struct ctx *c)
{
	if (onechar(c, '-', 0))
		return U_MINUS;
	if (onechar(c, '!', "="))
		return U_LOGNOT;
	return U_ERR;
}

static struct parsedexpr *parse_u(struct ctx *c)
{
	return parse_unary(c, &op_unary, &parse_primary);
}

static enum binary_op op_cmp(struct ctx *c)
{
	char ch;

	ch = get(c);
	switch (ch) {
	case '=':
		if (end(c))
			return B_EQ;
		ch = get(c);
		if (ch != '=')
			unget(c);
		return B_EQ;
	case '!':
	case '/':
		if (end(c)) {
			unget(c);
			return B_ERR;
		}
		ch = get(c);
		if (ch != '=') {
			unget(c);
			unget(c);
			return B_ERR;
		}
		return B_NE;
	case '<':
		if (end(c))
			return B_LT;
		ch = get(c);
		switch (ch) {
		case '<':
			return B_ERR;
		case '=':
			return B_LE;
		case '>':
			return B_NE;
		}
		unget(c);
		return B_LT;
	case '>':
		if (end(c))
			return B_GT;
		ch = get(c);
		switch (ch) {
		case '=':
			return B_GE;
		case '>':
			return B_ERR;
		}
		unget(c);
		return B_GT;
	}
	unget(c);

	return B_ERR;
}

static struct parsedexpr *parse_cmp(struct ctx *c)
{
	return parse_binary_non(c, &op_cmp, &parse_u);
}

static enum binary_op op_land(struct ctx *c)
{
	return twochar(c, '&', '&') ? B_LOGAND : B_ERR;
}

static struct parsedexpr *parse_land(struct ctx *c)
{
	return parse_binary_left(c, &op_land, &parse_cmp);
}

static enum binary_op op_lxor(struct ctx *c)
{
	return twochar(c, '^', '^') ? B_LOGXOR : B_ERR;
}

static struct parsedexpr *parse_lxor(struct ctx *c)
{
	return parse_binary_left(c, &op_lxor, &parse_land);
}

static enum binary_op op_lor(struct ctx *c)
{
	return twochar(c, '|', '|') ? B_LOGOR : B_ERR;
}

static struct parsedexpr *parse_lor(struct ctx *c)
{
	return parse_binary_left(c, &op_lor, &parse_lxor);
}

static struct parsedexpr *parse_top(struct ctx *c)
{
	return parse_lor(c);
}

struct parsedexpr *parse_expr(int slen, char (*gc)(int o, void *cbarg), void *cbarg)
{
	struct ctx ctx;
	struct parsedexpr *e;

	ctx.len = slen;
	ctx.o = 0;
	ctx.gc = gc;
	ctx.cbarg = cbarg;
	e = parse_top(&ctx);
	skipwhite(&ctx);
	if (!end(&ctx)) {
		free_parsedexpr(e);
		return err_expr("Junk after expression");
	}
	return e;
}

static char strwrap_gc(int o, void *swv)
{
	// Do we want to sanity-check o here?
	// We have no error-reporting channel....
	return ((struct strwrap *)swv)->s[o];
}

struct parsedexpr *parse_expr_string(const char *str, int slen)
{
	struct strwrap sw;

	if (slen < 0)
		slen = strlen(str);
	sw.s = str;
	sw.l = slen;
	return parse_expr(slen, &strwrap_gc, &sw);
}

void walk_parsedexpr(struct parsedexpr *e, void (*pre)(struct parsedexpr *, void *),
		     void (*post)(struct parsedexpr *, void *), void *cbarg)
{
	if (pre)
		(*pre)(e, cbarg);
	switch (e->t) {
	default:
		abort();
		break;
	case ET_BOOL:
	case ET_INTEGER:
	case ET_STRING:
	case ET_IPv4:
	case ET_IPv6:
	case ET_MAC:
	case ET_NAME:
		break;
	case ET_UNARY:
		walk_parsedexpr(e->unary.arg, pre, post, cbarg);
		break;
	case ET_BINARY:
		walk_parsedexpr(e->binary.lhs, pre, post, cbarg);
		walk_parsedexpr(e->binary.rhs, pre, post, cbarg);
		break;
	}
	if (post)
		(*post)(e, cbarg);
}

/*
 * This is a separate function because more is involved than just
 *  setting p->nextax; we also want to advance the pointed-to argc and
 *  argv values.  (For almost all purposes, setting them once just
 *  before parse_expr_args returns would be good enough.  But I'm told
 *  we want to advance them live, and it's fairly easy to do.)
 */
static void set_nextax(struct argpriv *p, int x)
{
	p->nextax = x;
	*p->acp = p->ac - x;
	*p->avp = p->av + x;
}

/*
 * Return-next-char function.
 *
 * We optimize two common cases: (1) re-getting the last character and
 *  (2) getting the next character.  (1) is what lastx and lastc are
 *  for; (2) is what nextx/nextax/nextowa are for.  If we don't hit
 *  either one, we search for the right arg.
 *
 * If the parser is changed so backing up more than one character is
 *  common, this should be improved.  One easy avenue for improvement
 *  is special-casing x==p->lastx-1.
 *
 * This code doesn't consider an arg consumed until we advance past the
 *  synthetic space inserted after the arg (I would say "between the
 *  arg and the next arg" except that there is a synthetic space after
 *  the last arg).  Changing this means storing through p->acp and
 *  p->avp at times other than just when we change p->nextax.
 */
static char arg_ch(int x, void *pv)
{
	struct argpriv *p;
	char c;

	p = pv;
	if (x < 0 || x > p->lt) { // Invalid call - indicates bug in parser or corruption here.
		// Do we abort(), or return something, or what?
		// For the moment, I'm returning NUL.
		return '\0';
	}
	if (x == p->lastx)
		return p->lastc;
	if (x != p->nextx) { // If this turns out to be a performance issue,
		// maybe replace it with binary search?
		int i;

		for (i = p->ac - 1; (i >= 0) && (x < p->plv[i]); i--)
			;
		if (i <
		    0) { // Corrupt data structures (or invalid call not caught above).
			// Do we abort(), or return something, or what?
			// For the moment, I'm returning NUL.
			return '\0';
		}
		p->nextx = x;
		p->nextowa = x - p->plv[i];
		set_nextax(p, i);
	}
	p->nextx++;
	if (p->nextowa >=
	    p->lv[p->nextax]) { // The > case is actually an error.
		// IMO the firewall value is outweighed by code complexity.
		c = ' ';
		set_nextax(p,p->nextax+1);
		p->nextowa = 0;
	} else {
		c = p->av[p->nextax][p->nextowa];
		p->nextowa++;
	}
	return c;
}

/*
 * This function depends on C99-style variable-length arrays.  It also
 *  depends on the first argument being strictly greater than zero.
 *  Each of these could be fixed were they to be problematic.
 */
struct parsedexpr *parse_expr_args(int *argcp, const char * const **argvp,
				   void *cbarg)
{
	struct argpriv priv;
	int i;
	int l;
	int tl;

	priv.acp = argcp;
	priv.avp = argvp;
	priv.ac = *argcp;
	priv.av = *argvp;
	do {
		int lens[priv.ac];
		int prevlens[priv.ac];
		tl = 0;
		for (i=0;i<priv.ac;i++)
		{ l = strlen(priv.av[i]);
			prevlens[i] = tl;
			lens[i] = l;
			tl += l + (i ? 1 : 0);
		}
		priv.lv = &lens[0];
		priv.plv = &prevlens[0];
		priv.lt = tl;
		priv.lastx = -1;
		priv.nextx = 0;
		priv.nextax = 0;
		priv.nextowa = 0;
		priv.cbarg = cbarg;
		return(parse_expr(tl,&arg_ch,&priv));
	} while(0);
}

void free_parsedexpr(struct parsedexpr *e)
{
	if (!e)
		return;
	switch (e->t) {
	default:
		abort();
	case ET_ERR:
	case ET_BOOL:
	case ET_IPv4:
	case ET_IPv6:
	case ET_MAC:
		return;
	case ET_INTEGER:
		free(e->integer.s);
		break;
	case ET_STRING:
		(*e->string.done)(e, e->string.donearg);
		break;
	case ET_NAME:
		free(e->name.name);
		break;
	case ET_UNARY:
		free_parsedexpr(e->unary.arg);
		break;
	case ET_BINARY:
		free_parsedexpr(e->binary.lhs);
		free_parsedexpr(e->binary.rhs);
		break;
	}
	free(e);
}

void dump_expr(struct parsedexpr *e, int indent)
{
	printf("%*s", indent, "");
	switch (e->t) {
	default:
		printf("? type = %d\nerrmsg %s\n", (int)e->t, e->errmsg);
		break;
	case ET_BOOL:
		printf("bool = %s\n", e->boolean.v ? "true" : "false");
		break;
	case ET_INTEGER:
		printf("integer = %llu [%s]\n",
		       (unsigned long long)e->integer.i, e->integer.s);
		break;
	case ET_STRING:
		printf("string = %.*s\n", e->string.len,
		       e->string.txt); // XXX should handle nonprintables
		break;
	case ET_IPv4:
		printf("IPv4 = %d.%d.%d.%d", e->ipv4.a[0], e->ipv4.a[1],
		       e->ipv4.a[2], e->ipv4.a[3]);
		if (e->ipv4.width >= 0)
			printf("/%d", e->ipv4.width);
		printf("\n");
		break;
	case ET_IPv6:
		printf("IPv6 = %x:%x:%x:%x:%x:%x:%x:%x",
		       (e->ipv6.a[0] * 256) + e->ipv6.a[1],
		       (e->ipv6.a[2] * 256) + e->ipv6.a[3],
		       (e->ipv6.a[4] * 256) + e->ipv6.a[5],
		       (e->ipv6.a[6] * 256) + e->ipv6.a[7],
		       (e->ipv6.a[8] * 256) + e->ipv6.a[9],
		       (e->ipv6.a[10] * 256) + e->ipv6.a[11],
		       (e->ipv6.a[12] * 256) + e->ipv6.a[13],
		       (e->ipv6.a[14] * 256) + e->ipv6.a[15]);
		if (e->ipv6.width >= 0)
			printf("/%d", e->ipv6.width);
		printf("\n");
		break;
	case ET_MAC:
		printf("MAC = %02x:%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x:%02x\n",
		       e->mac.a[0], e->mac.a[1], e->mac.a[2], e->mac.a[3],
		       e->mac.a[4], e->mac.a[5], e->mac.m[0], e->mac.m[1],
		       e->mac.m[2], e->mac.m[3], e->mac.m[4], e->mac.m[5]);
		break;
	case ET_NAME:
		printf("name = %s\n", e->name.name);
		break;
	case ET_UNARY:
		switch (e->unary.op) {
		default:
			printf("?unary(%d)", (int)e->unary.op);
			dump_expr(e->unary.arg, indent + 2);
			break;
#define OP(op)                                                                 \
	case U_##op:                                                           \
		printf("U_" #op "\n");                                         \
		dump_expr(e->unary.arg, indent + 2);                           \
		break;
			OP(MINUS)
			OP(LOGNOT)
#undef OP
		}
		break;
	case ET_BINARY:
		switch (e->binary.op) {
		default:
			printf("?binary(%d)", (int)e->unary.op);
			dump_expr(e->binary.lhs, indent + 2);
			dump_expr(e->binary.rhs, indent + 2);
			break;
#define OP(op)                                                                 \
	case B_##op:                                                           \
		printf("B_" #op "\n");                                         \
		dump_expr(e->binary.lhs, indent + 2);                          \
		dump_expr(e->binary.rhs, indent + 2);                          \
		break;
			OP(EQ)
			OP(NE)
			OP(LT)
			OP(GT)
			OP(LE)
			OP(GE)
			OP(LOGAND)
			OP(LOGOR)
			OP(LOGXOR)
#undef OP
		}
		break;
	}
}
