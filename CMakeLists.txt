cmake_minimum_required(VERSION 3.3)
project(hound)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

set(SOURCE_FILES main.c)
add_executable(hound ${SOURCE_FILES})
target_link_libraries(hound pcap)
