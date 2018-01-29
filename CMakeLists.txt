cmake_minimum_required(VERSION 2.6)
project(blocksync)

add_executable(blocksync blocksync.c)
target_link_libraries(blocksync gcrypt)

install(TARGETS blocksync RUNTIME DESTINATION bin)
