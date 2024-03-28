cmake_minimum_required(VERSION 3.7)
project(Filters)

include(filters.cmake)

add_definitions(-fpic)

SET(LIBJXL_SRC
        ${CMAKE_SOURCE_DIR}/reframe_jxl.c
        ${CMAKE_SOURCE_DIR}/dec_jxl.c
)

SET(LIBJXL_LIB
        ${CMAKE_SOURCE_DIR}/lib/libjxl.a
        ${CMAKE_SOURCE_DIR}/lib/libhwy.a
        ${CMAKE_SOURCE_DIR}/lib/libbrotlicommon.a
        ${CMAKE_SOURCE_DIR}/lib/libbrotlidec.a
        /emsdk/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten/pic/libc.a
        /emsdk/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten/pic/libc++.a
        /emsdk/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten/pic/libc++abi.a
)

SET(LIBJXL_INC
        ${CMAKE_SOURCE_DIR}/include
)

add_filter(libjxl
        "${LIBJXL_SRC}"
        "${LIBJXL_LIB}"
        []
        ""
        "${LIBJXL_INC}"
        ""
        "1")