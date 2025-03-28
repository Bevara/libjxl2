cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "-O3 -Wall -Wextra")
set(CMAKE_C_FLAGS "-O3 -Wall -Wextra")

add_definitions(-fpic)

SET(LIBJXL_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/dec_jxl.c
)

SET(LIBJXL_LIB
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libjxl.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libhwy.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbrotlicommon.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbrotlidec.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libc.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libc++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/libc++abi.a
)

SET(LIBJXL_INC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_filter(libjxl
        "${LIBJXL_SRC}"
        "${LIBJXL_LIB}"
        []
        ""
        "${LIBJXL_INC}"
        ""
        "1")
