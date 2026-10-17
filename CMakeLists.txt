cmake_minimum_required(VERSION 3.16)

project(salesforce-curl-client
  VERSION 1.0.0
  DESCRIPTION "A small Salesforce REST client in C, built on libcurl"
  LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    Debug Release RelWithDebInfo MinSizeRel)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# --- options ----------------------------------------------------------------
option(SFCC_BUILD_TESTS "Build the test suite" ON)
option(SFCC_WERROR "Treat warnings as errors" OFF)

# --- libcurl ----------------------------------------------------------------
#
# The one dependency that cannot be vendored. Everything else here is either
# vendored (cJSON) or in libc.
#
# Linux/macOS: libcurl is usually present. If not:
#     pacman -S libcurl        # Arch
#     apt install libcurl4-openssl-dev   # Debian/Ubuntu
#     brew install curl        # macOS (then point CMAKE_PREFIX_PATH at it)
#
# Windows: nothing is bundled. Use vcpkg, which supplies both libcurl and its
# dependencies:
#     vcpkg install curl:x64-windows-static-md
#     cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
# The static-md triplet is the one to prefer. See the CURL_STATICLIB note
# below for why the choice of triplet is not cosmetic.

# vcpkg's zlib, built as a static library on Windows, installs zs.lib and
# zsd.lib. Those are the names zlib's own CMake build produces when only a
# static library is requested, and FindZLIB only searches for them when
# ZLIB_USE_STATIC_LIBS is set -- otherwise it looks for zlib.lib, does not find
# it, and reports "missing: ZLIB_LIBRARY" having already found the header and
# read its version. That reads like a broken install rather than a naming
# difference, and costs a CI round trip to diagnose.
#
# Gated on vcpkg rather than applied unconditionally: a system zlib on Linux is
# libz.so and must keep the default search. vcpkg's toolchain exports both
# VCPKG_LIBRARY_LINKAGE and VCPKG_TARGET_TRIPLET; the former is authoritative,
# the latter is a fallback for the case where only the triplet was set.
set(SFCC_VCPKG_STATIC OFF)
if(DEFINED VCPKG_LIBRARY_LINKAGE AND VCPKG_LIBRARY_LINKAGE STREQUAL "static")
  set(SFCC_VCPKG_STATIC ON)
elseif(NOT DEFINED VCPKG_LIBRARY_LINKAGE AND DEFINED VCPKG_TARGET_TRIPLET
       AND VCPKG_TARGET_TRIPLET MATCHES "static")
  set(SFCC_VCPKG_STATIC ON)
endif()
if(SFCC_VCPKG_STATIC)
  set(ZLIB_USE_STATIC_LIBS ON)
endif()

find_package(CURL REQUIRED)

# FindCURL has exported a usable imported target since CMake 3.14, but not in
# every configuration, so fall back to building one by hand rather than failing
# on an older or unusual setup.
if(TARGET CURL::libcurl)
  set(SFCC_CURL_TARGET CURL::libcurl)
else()
  add_library(sfcc_curl INTERFACE)
  target_include_directories(sfcc_curl INTERFACE ${CURL_INCLUDE_DIRS})
  target_link_libraries(sfcc_curl INTERFACE ${CURL_LIBRARIES})
  set(SFCC_CURL_TARGET sfcc_curl)
endif()

# On Windows, linking the static libcurl requires the same preprocessor define
# that its own headers use to switch between __declspec(dllimport) and plain
# linkage. Omit it and you get either unresolved symbols or a link error
# mentioning __imp_curl_easy_init, which is a genuinely confusing first
# experience with vcpkg. CMake's FindCURL already defines CURL_STATICLIB when it
# detects a static library; this covers the paths where it does not.
if(WIN32 AND (NOT BUILD_SHARED_LIBS OR SFCC_VCPKG_STATIC))
  if(TARGET CURL::libcurl)
    get_target_property(_sfcc_curl_type CURL::libcurl TYPE)
    # A vcpkg static triplet settles the linkage regardless of how the imported
    # target reports itself, and UNKNOWN_LIBRARY is a common way for a config
    # package to describe a static library. Trust the triplet over the type
    # rather than silently skipping the define and failing to link later.
    if(_sfcc_curl_type STREQUAL "STATIC_LIBRARY" OR SFCC_VCPKG_STATIC)
      target_compile_definitions(CURL::libcurl INTERFACE CURL_STATICLIB)
    endif()
  endif()
endif()

# --- warnings ---------------------------------------------------------------
if(MSVC)
  set(SFCC_WARNINGS /W4 /permissive-)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
else()
  set(SFCC_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wvla -Wcast-qual
                    -Wwrite-strings -Wformat=2 -Wundef)
endif()
if(SFCC_WERROR)
  list(APPEND SFCC_WARNINGS $<IF:$<BOOL:${MSVC}>,/WX,-Werror>)
endif()

# --- vendored cJSON ---------------------------------------------------------
#
# Vendored rather than found, on purpose. cJSON is two files under a permissive
# licence, and making it a package dependency would mean every platform needs a
# separate "install cjson" step before anything builds. Pinning the tag in
# third_party/cjson/README.md means the version is auditable.
add_library(sfcc_cjson STATIC third_party/cjson/cJSON.c)
target_include_directories(sfcc_cjson PUBLIC third_party/cjson)
target_link_libraries(sfcc_cjson PUBLIC m)
if(NOT MSVC)
  # cJSON is third-party code we do not control the style of; warning flags on
  # it produce noise that would drown out warnings about ours.
  target_compile_options(sfcc_cjson PRIVATE ${SFCC_WARNINGS})
  set_target_properties(sfcc_cjson PROPERTIES C_CLANG_TIDY "")
endif()

# --- the library ------------------------------------------------------------
add_library(sfcc STATIC
  src/sfcc_util.c
  src/sfcc_json.c
  src/sfcc_http.c
  src/sfcc_auth.c
  src/sfcc_client.c
  src/sfcc_deploy.c
  src/sfcc_rest.c)

target_include_directories(sfcc
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
          $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(sfcc PUBLIC ${SFCC_CURL_TARGET} sfcc_cjson)
target_compile_definitions(sfcc PRIVATE SFCC_VERSION="${PROJECT_VERSION}")
target_compile_options(sfcc PRIVATE ${SFCC_WARNINGS})

# --- the executable ---------------------------------------------------------
add_executable(sfcc_cli src/main.c)
set_target_properties(sfcc_cli PROPERTIES OUTPUT_NAME sfcc)
target_link_libraries(sfcc_cli PRIVATE sfcc)
target_compile_options(sfcc_cli PRIVATE ${SFCC_WARNINGS})

# --- tests ------------------------------------------------------------------
#
# Deliberately offline. A test that needs a live Salesforce org cannot run on a
# contributor's machine or in CI without secrets, so the suite covers what is
# testable without one: argument handling, validation, and the encoding and
# buffering that silently corrupt requests when they are wrong.
include(CTest)
if(SFCC_BUILD_TESTS AND BUILD_TESTING)
  add_subdirectory(tests)
endif()

# --- install ----------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS sfcc sfcc_cli
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/sfcc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

message(STATUS "")
message(STATUS "  ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  build type ....... ${CMAKE_BUILD_TYPE}")
message(STATUS "  libcurl .......... ${CURL_VERSION_STRING}")
message(STATUS "  executables ...... bin/sfcc")
message(STATUS "")