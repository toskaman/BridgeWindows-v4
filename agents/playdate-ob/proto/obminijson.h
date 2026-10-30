/* obminijson: tiny JSON DOM for agent<->bridge messages. C99, no deposits.
 * Pool-based (no malloc): OB_JPOOL nodes; strings unescaped in place.
 * \\uXXXX decodes BMP only (surrogates become '?'); enough for ASCII control text. */
#ifndef OBMINIJSON_H
#define OBMINIJSON_H
#include <stddef.h>

#define OB_JPOOL 96
#define OB_JSTR 2048

typedef enum { OJ_NULL, OJ_BOOL, OJ_NUM, OJ_STR, OJ_OBJ, OJ_ARR } oj_type;
typedef struct oj_node { oj_type t; long num; int boolean; char *str; char *key; int child; int next; } oj_node;
typedef struct { oj_node n[OB_JPOOL]; int used; char buf[OB_JSTR]; size_t buflen; } oj_pool;

/* Parse doc[0..len) as one JSON value; returns root index or -1. */
int oj_parse(oj_pool *p, const char *doc, size_t len);
/* Object member by key, or -1. */
int oj_get(oj_pool *p, int obj, const char *key);
/* Append JSON-escaped src to dst (dstsize incl. NUL); returns 0 on truncation. */
int oj_escape(const char *src, char *dst, size_t dstsize);

#endif
