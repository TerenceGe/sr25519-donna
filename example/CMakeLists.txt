cmake_minimum_required(VERSION 3.15)

project(sr25519_donna_example VERSION 1.0.0 DESCRIPTION "sr25519 donna example")

set(SOURCE_FILES
  src/print.h
  src/print.c
  src/main.c
  )

include_directories(${PROJECT_SOURCE_DIR}/src)

include_directories(../build/include/)
link_directories(../build/lib/)

add_library(sr25519_donna STATIC IMPORTED)
# set_property(TARGET sr25519_donna PROPERTY IMPORTED_LOCATION ../_install/lib/libsr25519_donna_static.a)

add_executable(sr25519DonnaExample ${SOURCE_FILES})
target_link_libraries(sr25519DonnaExample sr25519_donna)
