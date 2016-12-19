# Makefile for vNFChain Library Test Programs
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

IPATH := ../../include/vnfchain

CPP:= g++

CPPFLAGS:= -Wall -g -I${IPATH} -std=c++11 -D_GLIBCXX_USE_NANOSLEEP -DVNFC_DEBUG=1

TARGET:= objpool_test packet_test vnfc_test

VNFCLIB:= ../libvnfchain.so.1.0.0

LIBPATH:= ../


%.o: %.cpp
	${CPP} ${CPPFLAGS} -c $<

all: ${VNFCLIB} ${TARGET}

clean:
	rm *.o ${TARGET} 2> /dev/null

objpool_test: objpool_test.o ../utils/objpool.o ../utils/shm.o
	${CPP} -o $@ $^ -pthread -lrt

packet_test: packet_test.o ../vnfc_pktpool.o ../vnfc_packet.o ../utils/objpool.o ../utils/shm.o
	${CPP} -o $@ $^ -lrt

vnfc_test: vnfc_test.o ${VNFCLIB}
	${CPP} -o $@ $^ -lrt

objpool_test.o: objpool_test.cpp ${IPATH}/utils/objpool.h ../utils/objpool.c

packet_test.o: packet_test.cpp ${IPATH}/vnfc_packet.h ${IPATH}/vnfc_pktpool.h ../vnfc_packet.c ../vnfc_pktpool.c

vnfc_test.o: vnfc_test.cpp ${IPATH}/vnfc.h

${VNFCLIB}:
	$(MAKE) -C ../ VNFC_DEBUG=1
