cmake_minimum_required(VERSION 3.15)

project(sr25519_donna VERSION 1.0.0 DESCRIPTION "c implementation of schnorrkel algorithm")

set(SOURCE_FILES
  src/memzero.h
  src/sha2.h
  src/sha3.h

  src/ed25519-donna/curve25519-donna-32bit.h
  src/ed25519-donna/curve25519-donna-helpers.h
  src/ed25519-donna/curve25519-donna-scalarmult-base.h
  src/ed25519-donna/ed25519-donna-32bit-tables.h
  src/ed25519-donna/ed25519-donna-basepoint-table.h
  src/ed25519-donna/ed25519-donna-impl-base.h
  src/ed25519-donna/ed25519-donna-portable.h
  src/ed25519-donna/ed25519-donna.h
  src/ed25519-donna/ed25519-hash-custom-keccak.h
  src/ed25519-donna/ed25519-hash-custom-sha3.h
  src/ed25519-donna/ed25519-hash-custom.h
  src/ed25519-donna/ed25519-keccak.h
  src/ed25519-donna/ed25519-sha3.h
  src/ed25519-donna/ed25519.h
  src/ed25519-donna/modm-donna-32bit.h

  src/merlin.h
  src/ristretto255.h
  src/sr25519.h
  src/sr25519-donna.h

  src/randombytes/core.h
  src/randombytes/randombytes_sysrandom.h

  src/memzero.c
  src/sha2.c
  src/sha3.c

  src/ed25519-donna/curve25519-donna-32bit.c
  src/ed25519-donna/curve25519-donna-helpers.c
  src/ed25519-donna/curve25519-donna-scalarmult-base.c
  src/ed25519-donna/ed25519-donna-32bit-tables.c
  src/ed25519-donna/ed25519-donna-basepoint-table.c
  src/ed25519-donna/ed25519-donna-impl-base.c
  src/ed25519-donna/ed25519-keccak.c
  src/ed25519-donna/ed25519-sha3.c
  src/ed25519-donna/ed25519.c
  src/ed25519-donna/modm-donna-32bit.c

  src/randombytes/core.c
  src/randombytes/randombytes.c
  src/randombytes/randombytes_sysrandom.c

  src/merlin.c
  src/ristretto255.c
  src/sr25519.c
  )

add_library(sr25519_donna SHARED ${SOURCE_FILES})

enable_testing()

add_executable(sr25519DonnaTests tests/test_check.c)
include_directories(${PROJECT_SOURCE_DIR}/src)
target_link_libraries(sr25519DonnaTests sr25519_donna)

add_test(NAME test_check COMMAND sr25519DonnaTests)
