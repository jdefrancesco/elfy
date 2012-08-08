#ifndef _BSO_COMMON_H
#define _BSO_COMMON_H 1

#define IMPORT extern
#define EXPORT 
#define PRIVATE static
#define INLINE static inline

IMPORT int d_query(const char *fmt, ...);

IMPORT const char *d_userabort;

#endif /* _BSO_COMMON_H */
