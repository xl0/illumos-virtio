
#include <sys/dditypes.h>
#include <sys/sysmacros.h>

void dev_err(dev_info_t *dip, int ce, char *fmt, ...);
void dev_panic(dev_info_t *dip, char *fmt, ...);

void hex_dump(char *prefix, void *addr, int len);

static inline int up_to_power2(int i) {

    if (ISP2(i))
        return i;

    /* Highbit returns h+1. */
    return (1 << (highbit(i) - 1));
}

/* XXX Stolen from the Linux kernel! Need to find a BSD one, or too trivial to
 * be copyrightable? */
#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) );})

