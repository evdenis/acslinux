#!/bin/bash -x

export KERNELDIR=${KERNELDIR:-/lib/modules/$(uname -r)/build}

preconfig='#ifndef PRECONFIG_H
#define PRECONFIG_H

#define __KERNEL__
#define MODULE

#include <linux/kconfig.h>

#endif
'

trap "rm -f ./preconfig.h" EXIT
echo "$preconfig" > './preconfig.h'


frama-c -pp-annot -cpp-extra-args " -C -E -x c \
		-include ./preconfig.h \
		-I . \
      -D FRAMAC_WORKAROUND=1 \
		-I ${KERNELDIR}/arch/x86/include/ \
		-I ${KERNELDIR}/arch/x86/include/generated/ \
		-I ${KERNELDIR}/include/ \
		-I ${KERNELDIR}/include/generated/ \
		-I ${KERNELDIR}/arch/x86/include/uapi/ \
		-I ${KERNELDIR}/arch/x86/include/generated/uapi/ \
		-I ${KERNELDIR}/include/uapi/ \
		-I ${KERNELDIR}/include/generated/uapi/ \
		-isystem $(gcc -print-search-dirs | grep install | cut -d ':' -f 2)/include/" -jessie acslinux_hooks.c

