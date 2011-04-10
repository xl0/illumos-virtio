
#include <sys/dditypes.h>

void dev_err(dev_info_t *dip, int ce, char *fmt, ...);
void dev_panic(dev_info_t *dip, char *fmt, ...);

