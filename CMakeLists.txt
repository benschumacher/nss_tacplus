cmake_minimum_required(VERSION 3.15)
project(nss_tacplus VERSION 1.0.1 LANGUAGES C)

# Project metadata
set(PROJECT_DESCRIPTION "NSS module for TACACS+ authentication")
set(PROJECT_HOMEPAGE_URL "https://github.com/benschumacher/nss_tacplus")

# Build options
option(BUILD_TESTING "Build test suite" ON)
option(ENABLE_HARDENING "Enable security hardening flags" ON)
option(ENABLE_SANITIZERS "Enable sanitizers (ASan, UBSan)" OFF)

# C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)  # gnu99

# Find required dependencies
find_library(TAC_LIBRARY NAMES tac PATHS /usr/local/lib)
find_path(TAC_INCLUDE_DIR libtac/libtac.h PATHS /usr/local/include)

if(NOT TAC_LIBRARY OR NOT TAC_INCLUDE_DIR)
    message(WARNING "libtac not found. You need pam_tacplus installed.")
    message(WARNING "Install from: https://github.com/jeroennijhof/pam_tacplus")
    message(WARNING "  git clone https://github.com/jeroennijhof/pam_tacplus.git")
    message(WARNING "  cd pam_tacplus && autoreconf -i && ./configure && make && sudo make install")
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-g -ggdb -O0")
set(CMAKE_C_FLAGS_RELEASE "-O2")

# Security hardening flags
if(ENABLE_HARDENING)
    set(HARDENING_FLAGS
        -D_FORTIFY_SOURCE=2
        -fstack-protector-strong
        -fstack-clash-protection
        -fPIE
        -Wformat
        -Wformat-security
    )
    add_compile_options(${HARDENING_FLAGS})
    add_link_options(-Wl,-z,relro -Wl,-z,now)
endif()

# Sanitizers for development
if(ENABLE_SANITIZERS)
    set(SANITIZER_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
    add_compile_options(${SANITIZER_FLAGS})
    add_link_options(${SANITIZER_FLAGS})
endif()

# Main library
add_library(nss_tacplus SHARED
    src/nss_tacplus.c
)

target_include_directories(nss_tacplus PRIVATE
    ${TAC_INCLUDE_DIR}
)

target_link_libraries(nss_tacplus PRIVATE
    ${TAC_LIBRARY}
    pthread
    nsl
)

# Set the output name to match NSS convention
set_target_properties(nss_tacplus PROPERTIES
    OUTPUT_NAME "nss_tacplus"
    VERSION 2
    SOVERSION 2
    PREFIX "lib"
    SUFFIX ".so.2"
)

# RPATH handling
set_target_properties(nss_tacplus PROPERTIES
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH FALSE
)

# Test harness tool
add_executable(dlharness
    test/dlharness.c
)

target_link_libraries(dlharness PRIVATE
    ${CMAKE_DL_LIBS}
)

# Installation
include(GNUInstallDirs)

install(TARGETS nss_tacplus
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES etc/tacplus.conf
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ
)

install(FILES etc/pam.d/tacacs+
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/pam.d
    RENAME tacacs
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)

install(FILES README.md LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Testing
if(BUILD_TESTING)
    enable_testing()
    # Tests will be added here
    add_test(NAME dlharness_help
        COMMAND dlharness
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_tests_properties(dlharness_help PROPERTIES
        WILL_FAIL TRUE  # Expected to fail without args
    )
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "nss_tacplus configuration:")
message(STATUS "  Version:          ${PROJECT_VERSION}")
message(STATUS "  Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "  C flags:          ${CMAKE_C_FLAGS}")
message(STATUS "  Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "  Testing enabled:  ${BUILD_TESTING}")
message(STATUS "  Hardening:        ${ENABLE_HARDENING}")
message(STATUS "  Sanitizers:       ${ENABLE_SANITIZERS}")
message(STATUS "  libtac found:     ${TAC_LIBRARY}")
message(STATUS "  libtac include:   ${TAC_INCLUDE_DIR}")
message(STATUS "")
