cmake_minimum_required(VERSION 3.14)
project(SocketHook LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} SHARED)

target_sources(${PROJECT_NAME} PRIVATE
    SocketHook/SocketHook.cpp
    Util/Log/Logger.cpp
    Third/minHook/src/buffer.c
    Third/minHook/src/hook.c
    Third/minHook/src/trampoline.c
    Third/minHook/src/hde/hde64.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    .
    Third/minHook/include
)

if(MINGW)
    target_link_options(${PROJECT_NAME} PRIVATE
        -static-libgcc
        -static-libstdc++
    )
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32)

set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""
    OUTPUT_NAME "SocketHook"
    SUFFIX ".dll"
)