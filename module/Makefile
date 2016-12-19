# Makefile for vNFChain
#
# Copyright 2015-17 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#


ifdef FAKE_TUN # make FAKE_TUN=1
EXTRA_CFLAGS += -DFAKE_TUN=1
endif


TARGET:= vnfchain.ko

CFILES = vnfc.c vnfc_file.c vnfc_net.c vnfc_ethtool.c vnfc_flow.c vnfc_service.c

vnfchain-objs:= $(CFILES:.c=.o)

all: ${TARGET}

install:
	insmod vnfchain.ko
	chmod 666 /dev/net/vnfc

uninstall:
	rmmod vnfchain

$(TARGET): $(CFILES)
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 modules EXTRA_CFLAGS="$(EXTRA_CFLAGS) -I`pwd`/../include/vnfchain"

test: test.cpp
	g++ -o test test.cpp -I../include
	@echo "You have to execute 'setcap cap_net_admin+ep test' as root"

clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` V=1 clean

obj-m:= vnfchain.o

vnfc.c: vnfc.h vnfc_file.h vnfc_net.h vnfc_flow.h vnfc_ethtool.h

vnfc_file.c: vnfc.h vnfc_file.h vnfc_net.h vnfc_flow.h vnfc_service.h

vnfc_net.c: vnfc.h vnfc_net.h vnfc_flow.h

vnfc_ethtool.c: vnfc.h vnfc_ethtool.h

vnfc_flow.c: vnfc.h vnfc_flow.h

vnfc_service.c: vnfc.h vnfc_service.h

clean-files := *.o *.ko *.mod.[co] *~ test
