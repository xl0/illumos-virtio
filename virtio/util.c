
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include "util.h"

/* 
 * Add to ddi? 
 */
void
dev_err(dev_info_t *dip, int ce, char *fmt, ...)
{
	va_list ap;
	char    buf[256];

	ASSERT(dip != NULL);

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(ce, "%s%d: %s", ddi_driver_name(dip),
		ddi_get_instance(dip), buf);
}

void dev_panic(dev_info_t *dip, char *fmt, ...)
{
	va_list ap;
	char    buf[256];

	ASSERT(dip != NULL);

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	panic("%s%d: %s", ddi_driver_name(dip),
		ddi_get_instance(dip), buf);
}

void hex_dump(char *prefix, void *addr, int len)
{
	unsigned char *base = addr;
	char buff[256], *bptr;
	int i = 0;
	bptr = buff;

	cmn_err(CE_NOTE, "Dumping %d bytes starting from 0x%p", len, base);

	while (i < len) {
		sprintf(bptr, "%02x ", base[i]);
		bptr += 3;
		i++;

		if (!(i % 16)) {
			cmn_err(CE_NOTE, "%s: 0x%p: %s", prefix, base + i - 16, buff);
			bptr = buff;
		}
	}

	if (i % 16)
		cmn_err(CE_NOTE, "%s: 0x%p: %s", prefix, base + i - (i % 16), buff);
}
