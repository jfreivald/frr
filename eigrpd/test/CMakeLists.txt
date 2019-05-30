cmake_minimum_required(VERSION 3.13)
project(test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_CONFIG_H=1")

include_directories(. ../ ../.. ../../lib/)

add_executable(eigrp_fsm_test eigrp_fsm_test.c)
link_directories(.. ../.. ../../lib/.libs)
target_link_libraries(eigrp_fsm_test ${CMAKE_SOURCE_DIR}/../libeigrp.a ${CMAKE_SOURCE_DIR}/../../lib/.libs/libfrr.a criterion pthread dl crypt m json-c rt)