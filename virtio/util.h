
#include <sys/dditypes.h>
#include <sys/sysmacros.h>
#include <sys/log.h>

#if defined (__GNUC__)
#define dev_err(dip, ce, fmt, ...)	\
	cmn_err(ce, "%s%d: " fmt, ddi_driver_name(dip),	\
			ddi_get_instance(dip), ## __VA_ARGS__);
#elif defined (__SUNPRO_C)
	/*
	 * The Sun Studio does not support the ##__VAR_ARGS__ extension,
	 * so we fall back to the function with a constant size buffer.
	 */

	/* Get rid of this when/if we drop SS support */

/* PRINTFLIKE3 */
static void
dev_err(dev_info_t *dip, int ce, char *fmt, ...)
{
	va_list ap;
	char buf[LOG_MSGSIZE];

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	cmn_err(ce, "%s%d: %s", ddi_driver_name(dip),
			ddi_get_instance(dip), buf);
}
#else
#error "Unknown compiler"
#endif

#ifdef DEBUG
#define dev_debug(dip, fmt, arg...) \
	dev_err(dip, fmt, ##arg)
#else
#define dev_debug(dip, fmt, arg...)
#endif

/*
 * container_of taken from FreeBSD.
 * Copyright (c) 1992-2011 The FreeBSD Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE
 */
#define	container_of(p, stype, field) \
	((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))
