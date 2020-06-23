cmake_minimum_required(VERSION 3.15)

project(sr25519_donna VERSION 1.0.0 DESCRIPTION "c implementation of schnorrkel algorithm")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-c -O3")

add_definitions(-DED25519_CUSTOMRANDOM)
add_definitions(-DED25519_CUSTOMHASH)
add_definitions(-DED25519_NO_INLINE_ASM)

if(SR25519_FORCE_32BIT)
  add_definitions(-DED25519_FORCE_32BIT)
endif()

if(SR25519_CUSTOMRANDOM)
  add_definitions(-DSR25519_CUSTOMRANDOM)
endif()

if(SR25519_CUSTOMHASH)
  add_definitions(-DSR25519_CUSTOMHASH)
endif()

set(SOURCE_FILES
  src/ed25519-donna/curve25519-donna-32bit.h
  src/ed25519-donna/curve25519-donna-64bit.h
  src/ed25519-donna/curve25519-donna-helpers.h
  src/ed25519-donna/curve25519-donna-sse2.h
  src/ed25519-donna/ed25519-donna-32bit-sse2.h
  src/ed25519-donna/ed25519-donna-32bit-tables.h
  src/ed25519-donna/ed25519-donna-64bit-sse2.h
  src/ed25519-donna/ed25519-donna-64bit-tables.h
  src/ed25519-donna/ed25519-donna-64bit-x86-32bit.h
  src/ed25519-donna/ed25519-donna-64bit-x86.h
  src/ed25519-donna/ed25519-donna-basepoint-table.h
  src/ed25519-donna/ed25519-donna-batchverify.h
  src/ed25519-donna/ed25519-donna-impl-base.h
  src/ed25519-donna/ed25519-donna-impl-sse2.h
  src/ed25519-donna/ed25519-donna-portable-identify.h
  src/ed25519-donna/ed25519-donna-portable.h
  src/ed25519-donna/ed25519-donna.h
  src/ed25519-donna/ed25519-hash-custom.h
  src/ed25519-donna/ed25519-hash.h
  src/ed25519-donna/ed25519-randombytes-custom.h
  src/ed25519-donna/ed25519-randombytes.h
  src/ed25519-donna/ed25519.c
  src/ed25519-donna/ed25519.h
  src/ed25519-donna/modm-donna-32bit.h
  src/ed25519-donna/modm-donna-64bit.h
  src/ed25519-donna/regression.h

  src/memzero.h
  src/memzero.c
  src/sha2.h
  src/sha2.c
  src/merlin.h
  src/merlin.c
  src/ristretto255.h
  src/ristretto255.c
  src/sr25519.c

  src/core.h
  src/core.c
  src/randombytes_sysrandom.h
  src/randombytes_sysrandom.c
  src/sr25519-randombytes-default.c

  src/sr25519-hash-custom.h
  src/sr25519-hash.h

  src/vrf.h
  src/vrf.c
  )

set(INCLUDE_FILES
  src/sr25519.h
  src/sr25519-donna.h
  src/sr25519-randombytes.h
  src/sr25519-randombytes-custom.h
  src/sr25519-randombytes-default.h
  )

add_library(sr25519_donna SHARED ${SOURCE_FILES})
add_library(sr25519_donna_static STATIC ${SOURCE_FILES})

install(TARGETS sr25519_donna DESTINATION lib)
install(TARGETS sr25519_donna_static DESTINATION lib)
install(FILES ${INCLUDE_FILES} DESTINATION include)

enable_testing()

add_executable(sr25519DonnaTests tests/test_check.c)
include_directories(${PROJECT_SOURCE_DIR}/src)
target_link_libraries(sr25519DonnaTests sr25519_donna)

add_test(NAME test_check COMMAND sr25519DonnaTests)
