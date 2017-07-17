cmake_minimum_required(VERSION 2.6)
project(mouSSHd)

set(mouSSHd_VERSION_MAJOR 1)
set(mouSSHd_VERSION_MINOR 0)

find_package(libssh REQUIRED)

add_executable(mouSSHd main.c)
target_link_libraries(mouSSHd ${LIBSSH_LIBRARIES})
