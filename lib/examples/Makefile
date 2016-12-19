# Makefile for vNFChain Example Services
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

CPP:= g++

CPPFLAGS:= -Wall -O3 -std=c++11 -I../../include

TARGET:= simple_service #simple_thread_service

VNFCLIB:= ../libvnfchain.so.1.0.0

LIBPATH:= ../


%.o: %.cpp
	${CPP} ${CPPFLAGS} -c $<

all: ${VNFCLIB} ${TARGET}

clean:
	rm *.o ${TARGET} 2> /dev/null || true

simple_service: simple_service.o ${VNFCLIB}
	${CPP} -o $@ $^ -L${LIBPATH} -lvnfchain -lrt -ldl 

simple_thread_service: simple_thread_service.o ${VNFCLIB}
	${CPP} -o $@ $^ -L${LIBPATH} -lvnfchain -pthread -lrt -ldl 

IPATH := ../../include/vnfchain

simple_service.o: simple_service.cpp ${IPATH}/vnfc.h ${IPATH}/vnfc_io.h ${IPATH}/vnfc_packet.h

simple_thread_service.o: simple_thread_service.cpp ${IPATH}/vnfc.h ${IPATH}/vnfc_io.h ${IPATH}/vnfc_packet.h

${VNFCLIB}:
	$(MAKE) -C ../
