cmake_minimum_required(VERSION 3.15)

project(sr25519_donna_example VERSION 1.0.0 DESCRIPTION "sr25519 donna example")

set(SOURCE_FILES
  src/print.h
  src/print.c
  src/main.c
  )

include_directories(${PROJECT_SOURCE_DIR}/src)

include_directories(../build/include/) # replace it with your sr25519-donna installed location if required
link_directories(../build/lib/) # replace it with your sr25519-donna installed location if required

add_executable(sr25519DonnaExample ${SOURCE_FILES})
target_link_libraries(sr25519DonnaExample libsr25519_donna_static.a)
