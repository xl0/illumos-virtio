
#include <sys/dditypes.h>
#include <sys/sysmacros.h>

void dev_err(dev_info_t *dip, int ce, char *fmt, ...);
void dev_panic(dev_info_t *dip, char *fmt, ...);

void hex_dump(char *prefix, void *addr, int len);

/*
 * Stolen from the Linux kernel! Will find a BSD one, but pls don't
 * sue us yet. ;)
 */
#define	container_of(ptr, type, member) ( \
{ \
	const typeof(((type *)0)->member) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); \
})
