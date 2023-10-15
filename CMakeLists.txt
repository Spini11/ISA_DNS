cmake_minimum_required(VERSION 3.20.0)
project(
    ISA_DNS
    LANGUAGES CXX
)
add_executable(
    dns
    ./main.cpp
    ./main.h
    ./dns.cpp
    ./dns.h
    ./arguments.cpp
    ./arguments.h
)
set_target_properties(
    dns
    PROPERTIES
    CXX_STANDARD 11
)
target_compile_options(dns PRIVATE "-Wall" "-Wextra" "-pedantic")