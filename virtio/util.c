
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


