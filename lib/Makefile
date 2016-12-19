# Makefile for vNFChain Library
#
# Copyright 2015-16 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
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

IPATH := ../include/vnfchain

RTE_SDK := /usr/share/dpdk
RTE_TARGET := x86_64-native-linuxapp-gcc
DPDK_IPATH := ${RTE_SDK}/${RTE_TARGET}/include
DPDK_LPATH := ${RTE_SDK}/${RTE_TARGET}/lib

CFLAGS = -Wall -I${IPATH} #-std=c11

ifdef VNFC_DEBUG  # make VNFC_DEBUG=1
CFLAGS += -O0 -g -DVNFC_DEBUG=1
else
CFLAGS += -O3 -DNDEBUG=1
endif

ifdef FAKE_TUN # make FAKE_TUN=1
CFLAGS += -DFAKE_TUN=1
endif

ifdef USE_DPDK # make USE_DPDK=1
CFLAGS += -DUSE_DPDK=1 -I${DPDK_IPATH} -mssse3
endif


TARGET:= libvnfchain.so

OBJS  = vnfc.o vnfc_io.o vnfc_utils.o vnfc_packet.o vnfc_pktpool.o
OBJS += utils/objpool.o utils/shm.o utils/poll.o utils/socket.o
OBJS += vhu/server.o vhu/memory.o vhu/proto.o vhu/vring.o -lhugetlbfs
ifdef VNFC_DEBUG
OBJS += vhu/debug.o
endif

ifdef USE_DPDK
DPDK_OBJS = ${DPDK_LPATH}/librte_eal.a ${DPDK_LPATH}/librte_mempool.a \
            ${DPDK_LPATH}/librte_mbuf.a ${DPDK_LPATH}/librte_ring.a
OBJS += dpdk/dpdk.o dpdk/ring_client.o ${DPDK_OBJS} -lpthread
endif


%.o: %.c
	gcc ${CFLAGS} -fPIC -c $(@D)/$(<F) -o $(@D)/$(@F)

all: ${OBJS}
	if [ -a ${TARGET} ]; then rm ${TARGET}; fi;
	gcc -shared -Wl,-soname,${TARGET} -o ${TARGET}.1.0.0 ${OBJS}
	ln -s ${TARGET}.1.0.0 ${TARGET}

cleaner:
	gcc -o pktpool_cleaner utils/pktpool_cleaner.c

clean:
	rm *.o utils/*.o vhu/*.o dpdk/*.o ${TARGET}* 2> /dev/null || true


vnfc.o: vnfc.c ${IPATH}/vnfc.h ${IPATH}/if_vnfc.h ${IPATH}/vnfc_utils.h \
	    ${IPATH}/vnfc_pktpool.h ${IPATH}/vnfc_packet.h ${IPATH}/utils/print.h \
		${IPATH}/utils/poll.h ${IPATH}/utils/socket.h ${IPATH}/vhu/server.h

vnfc_io.o: vnfc_io.c ${IPATH}/vnfc_io.h ${IPATH}/vnfc.h ${IPATH}/if_vnfc.h \
	       ${IPATH}/vnfc_utils.h ${IPATH}/vnfc_packet.h ${IPATH$/utils/print.h \
		   {IPATH}/utils/poll.h ${IPATH}/utils/socket.h ${IPATH}/vhu/server.h

vnfc_utils.o: vnfc_utils.c ${IPATH}/vnfc_utils.h ${IPATH}/vnfc.h \
	          ${IPATH}/vnfc_packet.h ${IPATH}/utils/socket.h ${IPATH}/utils/poll.h

vnfc_packet.o: vnfc_packet.c ${IPATH}/vnfc_packet.h

vnfc_pktpool.o: vnfc_pktpool.c ${IPATH}/vnfc_pktpool.h ${IPATH}/utils/objpool.h

utils/objpool.o: utils/objpool.c ${IPATH}/utils/objpool.h ${IPATH}/utils/shm.h

utils/shm.o: utils/shm.c ${IPATH}/utils/shm.h

utils/poll.o: utils/poll.c ${IPATH}/utils/poll.h

utils/socket.o: utils/socket.c ${IPATH}/utils/socket.h

vhu/server.o: vhu/server.c ${IPATH}/vhu/server.h ${IPATH}/vhu/memory.h \
	          ${IPATH}/vhu/proto.h ${IPATH}/vhu/vring.h

vhu/memory.o: vhu/memory.c ${IPATH}/vhu/memory.h ${IPATH}/vhu/proto.h \
	          ${IPATH}/utils/shm.h

vhu/proto.o: vhu/proto.c ${IPATH}/vhu/proto.h ${IPATH}/vhu/memory.h \
	         ${IPATH}/vhu/vring.h ${IPATH}/vhu/server.h ${IPATH}/utils/shm.h \
			 ${IPATH}/utils/poll.h

vhu/vring.o: vhu/vring.c ${IPATH}/vhu/vring.h ${IPATH}/utils/shm.h \
	         ${IPATH}/utils/print.h

ifdef VNFC_DEBUG
vhu/debug.o: vhu/debug.c ${IPATH}/vhu/debug.h ${IPATH}/vhu/vring.h \
	         ${IPATH}/vhu/proto.h
endif

ifdef USE_DPDK
dpdk/dpdk.o: dpdk/dpdk.c ${IPATH}/dpdk/dpdk.h

dpdk/ring_client.o: dpdk/ring_client.c ${IPATH}/dpdk/ring_client.h
endif
