CC=gcc
TOPDIR=../..
TESTS=eigrp_fsm_test
CFLAGS=-std=gnu11 -DHAVE_CONFIG_H=1 -I${TOPDIR} -I${TOPDIR}/eigrpd -I${TOPDIR}/lib
LIBS=${TOPDIR}/eigrpd/libeigrp.a ${TOPDIR}/lib/.libs/libfrr.a -lcriterion -lpthread -ldl -lcrypt -lm -ljson-c -lrt

all: ${TESTS}

eigrp_fsm_test: 
	gcc ${CFLAGS} eigrp_fsm_test.c -o eigrp_fsm_test ${LIBS}

clean:
	rm -f ${TESTS} *.o ~* *.swp
