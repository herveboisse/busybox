/* vi: set sw=4 ts=4: */
/*
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 *
 * Copyright 2001-2023 by Peter Bieringer <pb (at) bieringer.de>
 *
 * Busybox port: Hervé Boisse <admin@netgeek.ovh>
 */
//config:config IPV6CALC
//config:	bool "ipv6calc (xx kb)"
//config:	default y
//config:	depends on FEATURE_IPV6
//config:	help
//config:	Formats and calculates IPv6/IPv4/MAC addresses
//config:
//config:config FEATURE_IPV6CALC_LONG_OPTIONS
//config:	bool "Enable long options"
//config:	default y
//config:	depends on IPV6CALC && LONG_OPTS

//applet:IF_IPV6CALC(APPLET_NOEXEC(ipv6calc, ipv6calc, BB_DIR_BIN, BB_SUID_DROP, ipv6calc))

//kbuild:lib-$(CONFIG_IPV6CALC) += ipv6calc.o

//usage:#define ipv6calc_trivial_usage
//usage:       "[-q]"
//usage:#define ipv6calc_full_usage "\n\n"
//usage:       "Formats and calculates IPv6/IPv4/MAC addresses\n"
//usage:     "\n	-q		Be more quiet (auto-enabled in pipe mode"

#include "libbb.h"

#define IPV6CALC_OPTS			"q"
enum {
	OPT_QUIET		= 1 << 0,
};

#if ENABLE_FEATURE_IPV6CALC_LONG_OPTIONS
static const char ipv6calc_longopts[] ALIGN1 =
	"quiet\0"		No_argument			"q"
	;
#endif

int ipv6calc_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int ipv6calc_main(int argc UNUSED_PARAM, char **argv)
{
	unsigned int opt;

#if ENABLE_FEATURE_IPV6CALC_LONG_OPTIONS
	opt = getopt32long(argv, IPV6CALC_OPTS, ipv6calc_longopts
#else
	opt = getopt32(argv, IPV6CALC_OPTS
#endif
	);

	printf("opt = 0x%x\n", opt);

	return 1;
}
