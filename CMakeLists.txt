cmake_minimum_required(VERSION 3.10)

project(vodozemac_ios C)

set(CMAKE_C_STANDARD 11)

# Find the Rust compiler
find_program(RUSTC rustc)
if(NOT RUSTC)
    message(FATAL_ERROR "Rust compiler not found")
endif()

# Build the Rust library
set(LIB_NAME vodozemac_ios)
set(RUST_LIB ${CMAKE_SOURCE_DIR}/target/debug/lib${LIB_NAME}.a)
execute_process(COMMAND cargo build WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
if(NOT EXISTS ${RUST_LIB})
    message(FATAL_ERROR "Failed to build Rust library")
endif()

# Generate the C header file using cbindgen
set(CBINDGEN ${CMAKE_SOURCE_DIR}/cbindgen.toml)
set(HDR_FILE ${CMAKE_BINARY_DIR}/vodozemac_ios.h)
execute_process(COMMAND ${RUSTC} --print sysroot OUTPUT_VARIABLE RUST_SYSROOT OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${RUST_SYSROOT}/bin/cargo run --manifest-path ${CMAKE_SOURCE_DIR}/Cargo.toml -- ${CBINDGEN} -o ${HDR_FILE} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Build the C wrapper library
set(C_LIB_NAME vodozemac_ios C)
set(C_LIB_SRC ${CMAKE_SOURCE_DIR}/vodozemac_ios.h)
add_library(${C_LIB_NAME} SHARED ${C_LIB_SRC})
target_include_directories(${C_LIB_NAME} PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(${C_LIB_NAME} ${RUST_LIB})

# Build the test program
set(TEST_NAME test_lib)
set(TEST_SRC ${CMAKE_SOURCE_DIR}/src/test_lib.c)
add_executable(${TEST_NAME} ${TEST_SRC})
target_link_libraries(${TEST_NAME} ${C_LIB_NAME})