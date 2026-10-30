#include "obminijson.h"
#include <string.h>

typedef struct { const char *s; size_t n, i; oj_pool *p; } cur;

static void skip_ws(cur *c) {
    while (c->i < c->n && (c->s[c->i]==' '||c->s[c->i]=='\t'||c->s[c->i]=='\n'||c->s[c->i]=='\r')) c->i++;
}

static int new_node(cur *c, oj_type t) {
    if (c->p->used >= OB_JPOOL) return -1;
    { int k = c->p->used++; c->p->n[k].t = t; c->p->n[k].child = -1; c->p->n[k].next = -1;
      c->p->n[k].str = 0; c->p->n[k].key = 0; c->p->n[k].num = 0; c->p->n[k].boolean = 0; return k; }
}

static int hex4(const char *s, unsigned *v) {
    unsigned r = 0; int i;
    for (i = 0; i < 4; ++i) {
        char ch = s[i]; r <<= 4;
        if (ch>='0'&&ch<='9') r |= (unsigned)(ch-'0');
        else if (ch>='a'&&ch<='f') r |= (unsigned)(ch-'a'+10);
        else if (ch>='A'&&ch<='F') r |= (unsigned)(ch-'A'+10);
        else return 0;
    }
    *v = r; return 1;
}

/* Parse a string starting AFTER the opening quote; stores unescaped text, returns node or -1. */
static int parse_str(cur *c) {
    char tmp[OB_JSTR]; size_t o = 0; int k;
    while (c->i < c->n) {
        char ch = c->s[c->i++];
        if (ch == '"') break;
        if (o + 4 >= sizeof(tmp)) return -1;
        if (ch == '\\' && c->i < c->n) {
            char e = c->s[c->i++];
            if (e=='"') tmp[o++]='"'; else if (e=='\\') tmp[o++]='\\'; else if (e=='/') tmp[o++]='/';
            else if (e=='n') tmp[o++]='\n'; else if (e=='r') tmp[o++]='\r'; else if (e=='t') tmp[o++]='\t';
            else if (e=='b') tmp[o++]='\b'; else if (e=='f') tmp[o++]='\f';
            else if (e=='u' && c->i + 4 <= c->n) {
                unsigned v;
                if (!hex4(c->s + c->i, &v)) return -1;
                c->i += 4;
                if (v < 0x80) tmp[o++] = (char)v;
                else if (v < 0x800) { tmp[o++]=(char)(0xC0|(v>>6)); tmp[o++]=(char)(0x80|(v&63)); }
                else { tmp[o++]=(char)(0xE0|(v>>12)); tmp[o++]=(char)(0x80|((v>>6)&63)); tmp[o++]=(char)(0x80|(v&63)); }
            }
            else return -1;
        } else tmp[o++] = ch;
    }
    tmp[o] = 0;
    if (c->p->buflen + o + 1 > sizeof(c->p->buf)) return -1;
    k = new_node(c, OJ_STR);
    if (k < 0) return -1;
    memcpy(c->p->buf + c->p->buflen, tmp, o + 1);
    c->p->n[k].str = c->p->buf + c->p->buflen;
    c->p->buflen += o + 1;
    return k;
}

static int parse_val(cur *c);

static int parse_obj(cur *c) {
    int k = new_node(c, OJ_OBJ), *tail = 0; int first = 1;
    if (k < 0) return -1;
    tail = &c->p->n[k].child;
    skip_ws(c);
    if (c->i < c->n && c->s[c->i] == '}') { c->i++; return k; }
    for (;;) {
        int ks, v;
        skip_ws(c);
        if (c->i >= c->n || c->s[c->i] != '"') return -1;
        c->i++;
        ks = parse_str(c);
        if (ks < 0) return -1;
        skip_ws(c);
        if (c->i >= c->n || c->s[c->i] != ':') return -1;
        c->i++;
        v = parse_val(c);
        if (v < 0) return -1;
        c->p->n[v].key = c->p->n[ks].str;
        (void)first;
        *tail = v; tail = &c->p->n[v].next;
        skip_ws(c);
        if (c->i < c->n && c->s[c->i] == ',') { c->i++; continue; }
        if (c->i < c->n && c->s[c->i] == '}') { c->i++; return k; }
        return -1;
    }
}

static int parse_arr(cur *c) {
    int k = new_node(c, OJ_ARR), *tail;
    if (k < 0) return -1;
    tail = &c->p->n[k].child;
    skip_ws(c);
    if (c->i < c->n && c->s[c->i] == ']') { c->i++; return k; }
    for (;;) {
        int v = parse_val(c);
        if (v < 0) return -1;
        *tail = v; tail = &c->p->n[v].next;
        skip_ws(c);
        if (c->i < c->n && c->s[c->i] == ',') { c->i++; continue; }
        if (c->i < c->n && c->s[c->i] == ']') { c->i++; return k; }
        return -1;
    }
}

static int parse_val(cur *c) {
    int k;
    skip_ws(c);
    if (c->i >= c->n) return -1;
    { char ch = c->s[c->i];
      if (ch == '{') { c->i++; return parse_obj(c); }
      if (ch == '[') { c->i++; return parse_arr(c); }
      if (ch == '"') { c->i++; return parse_str(c); }
      if ((ch >= '0' && ch <= '9') || ch == '-') {
          long v = 0; int neg = 0;
          if (ch == '-') { neg = 1; c->i++; }
          while (c->i < c->n && c->s[c->i] >= '0' && c->s[c->i] <= '9')
              v = v * 10 + (c->s[c->i++] - '0');
          while (c->i < c->n && ((c->s[c->i] >= '0' && c->s[c->i] <= '9') || c->s[c->i]=='.' ||
                 c->s[c->i]=='e' || c->s[c->i]=='E' || c->s[c->i]=='+' || c->s[c->i]=='-')) c->i++;
          k = new_node(c, OJ_NUM);
          if (k < 0) return -1;
          c->p->n[k].num = neg ? -v : v;
          return k;
      }
      if (c->n - c->i >= 4 && !memcmp(c->s + c->i, "true", 4)) { c->i += 4; k = new_node(c, OJ_BOOL); if (k>=0) c->p->n[k].boolean=1; return k; }
      if (c->n - c->i >= 5 && !memcmp(c->s + c->i, "false", 5)) { c->i += 5; return new_node(c, OJ_BOOL); }
      if (c->n - c->i >= 4 && !memcmp(c->s + c->i, "null", 4)) { c->i += 4; return new_node(c, OJ_NULL); }
      return -1; }
}

int oj_parse(oj_pool *p, const char *doc, size_t len) {
    cur c;
    int k;
    p->used = 0; p->buflen = 0;
    c.s = doc; c.n = len; c.i = 0; c.p = p;
    k = parse_val(&c);
    if (k < 0) return -1;
    skip_ws(&c);
    return (c.i == c.n) ? k : -1;
}

int oj_get(oj_pool *p, int obj, const char *key) {
    int k;
    if (obj < 0 || obj >= p->used || p->n[obj].t != OJ_OBJ) return -1;
    for (k = p->n[obj].child; k >= 0; k = p->n[k].next)
        if (p->n[k].key && !strcmp(p->n[k].key, key)) return k;
    return -1;
}

int oj_escape(const char *src, char *dst, size_t dstsize) {
    size_t o = 0;
    if (!src) src = "";
    while (*src && o + 6 < dstsize) {
        unsigned char ch = (unsigned char)*src++;
        if (ch == '"') { dst[o++]='\\'; dst[o++]='"'; }
        else if (ch == '\\') { dst[o++]='\\'; dst[o++]='\\'; }
        else if (ch == '\n') { dst[o++]='\\'; dst[o++]='n'; }
        else if (ch == '\r') { dst[o++]='\\'; dst[o++]='r'; }
        else if (ch == '\t') { dst[o++]='\\'; dst[o++]='t'; }
        else if (ch < 0x20) {
            static const char *H = "0123456789abcdef";
            if (o + 6 >= dstsize) break;
            dst[o++]='\\'; dst[o++]='u'; dst[o++]='0'; dst[o++]='0';
            dst[o++]=H[ch>>4]; dst[o++]=H[ch&15];
        }
        else dst[o++] = (char)ch;
    }
    if (dstsize == 0) return 0;
    dst[o < dstsize ? o : dstsize - 1] = 0;
    return *src == 0;
}
