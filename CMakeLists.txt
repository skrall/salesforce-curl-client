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
#     vcpkg install curl:x64-windows
#     cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#
# Prefer the default dynamic triplet over x64-windows-static-md. The static one
# produces a self-contained sfcc.exe with no libcurl.dll to ship, which is a real
# advantage -- but it renames zlib's library to zs.lib, which CMake's FindZLIB
# does not search for unless told to, and it needs CURL_STATICLIB defined for
# libcurl's headers to link statically rather than as __declspec(dllimport).
# Both are handled below. CI builds the dynamic triplet anyway: it is the
# path vcpkg supports most directly, and it keeps the Windows job testing
# something we can actually keep green.

# vcpkg's zlib, built as a static library on Windows, installs zs.lib and
# zsd.lib. Those are the names zlib's own CMake build produces when only a
# static library is requested, and FindZLIB only searches for them when
# ZLIB_USE_STATIC_LIBS is set -- otherwise it looks for zlib.lib, does not find
# it, and reports "missing: ZLIB_LIBRARY" having already found the header and
# read its version. That reads like a broken install rather than a naming
# difference.
#
# Gated on vcpkg rather than applied unconditionally: a system zlib on Linux is
# libz.so and must keep the default search. vcpkg's toolchain exports
# VCPKG_TARGET_TRIPLET but not VCPKG_LIBRARY_LINKAGE, so the triplet name is
# what we key on.
set(SFCC_VCPKG_STATIC OFF)
if(DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static")
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
  # _CRT_SECURE_NO_WARNINGS silences the "use the _s variants" advice. Nothing
  # else is needed: the two POSIX spellings this code uses, strncasecmp and
  # strdup, are wrapped in sfcc_strncasecmp and sfcc_strdup rather than borrowed
  # from the CRT, which does not declare them under _CRT_DECLARE_NONSTDC_NAMES.
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
# libm only exists as a separate library on ELF and Mach-O platforms. On
# Windows the math functions are part of the CRT, and asking for it fails the
# link with "cannot open input file 'm.lib'".
if(NOT MSVC)
  target_link_libraries(sfcc_cjson PUBLIC m)
endif()
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
  src/sfcc_cache_crypto.c
  src/sfcc_client.c
  src/sfcc_deploy.c
  src/sfcc_rest.c
  src/sfcc_soap.c)

# --- token-cache encryption -------------------------------------------------
#
# SFCC_CACHE_PASSPHRASE turns the cache file into an SFCCENC1 frame
# (AES-256-GCM, key from PBKDF2-HMAC-SHA256; layout in sfcc_cache_crypto.c).
# Its value depends entirely on the key not living on the same disk as the
# ciphertext, which is why there is no key file and no --passphrase flag --
# the same reasons secrets get their env-only rule generally.
#
# The backend, and with it the dependency picture, differs by platform:
#
#   Windows  CNG            in the OS, nothing to find or link but bcrypt
#   macOS    CommonCrypto   in the OS, nothing to find or link
#   Linux    OpenSSL        POSIX has no standard crypto; libcrypto fills it
#
# Linux is a real build-time requirement (headers and -lcrypto), but not a
# new runtime package in practice: libcurl, already required, pulls libcrypto
# in on every distro that can run this binary at all. That is also why the
# requirement is worded as a package-name comment below rather than a
# vendored tree.
#
# If none is found, the feature collapses to a no (everything reports
# SFCC_ERR_CRYPTO_UNAVAILABLE, the cache layer refuses to encrypt and says so
# on stderr) and the build stays green rather than broken. Docker and CI both
# pass libcrypto-dependent libcurl packages today; the package names are
# given where they are installed.
if(WIN32)
  set(SFCC_CACHE_CRYPTO_BACKEND "CNG")
  target_compile_definitions(sfcc PRIVATE SFCC_CRYPTO_BACKEND_CNG)
  # bcrypt.lib holds BCryptEncrypt/Decrypt/GenRandom for the AES-GCM and RNG
  # primitives; PBKDF2 comes through the same header. advapi32 permissions
  # are not involved here despite the name overlap with the old Crypt* API.
  target_link_libraries(sfcc PUBLIC bcrypt)
elseif(APPLE)
  set(SFCC_CACHE_CRYPTO_BACKEND "corecrypto/CommonCrypto")
  target_compile_definitions(sfcc PRIVATE SFCC_CRYPTO_BACKEND_CC)
  # CommonCrypto supplies KDF and RNG from libSystem. The raw GCM primitive
  # lives in corecrypto, a separate dylib the SDK headers describe -- see the
  # note in sfcc_cache_crypto.c about why not CommonCrypto's own GCM calls.
  target_link_libraries(sfcc PUBLIC corecrypto)
else()
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    set(SFCC_CACHE_CRYPTO_BACKEND "OpenSSL")
    target_compile_definitions(sfcc PRIVATE SFCC_CRYPTO_BACKEND_OPENSSL)
    target_link_libraries(sfcc PUBLIC OpenSSL::Crypto)
  else()
    set(SFCC_CACHE_CRYPTO_BACKEND "none")
    target_compile_definitions(sfcc PRIVATE SFCC_CRYPTO_BACKEND_NONE)
    message(STATUS "  cache encryption . none (install libssl-dev / openssl-devel for it)")
  endif()
endif()

target_include_directories(sfcc
  PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
          $<INSTALL_INTERFACE:include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(sfcc PUBLIC ${SFCC_CURL_TARGET} sfcc_cjson)
target_compile_definitions(sfcc PRIVATE SFCC_VERSION="${PROJECT_VERSION}")
target_compile_options(sfcc PRIVATE ${SFCC_WARNINGS})

# --- the executable ---------------------------------------------------------
add_executable(sfcc_cli src/main.c)
# The binary is named sfcc, the same as the static library, because that is what
# both are called everywhere else and the library is an implementation detail of
# it.
set_target_properties(sfcc_cli PROPERTIES OUTPUT_NAME sfcc)
# MSVC's linker emits an import library alongside any executable whose output
# name it knows, and places it in the target's ARCHIVE directory -- which for a
# multi-config generator is <build>/<config>/sfcc.lib, exactly where the static
# library above already is. The link then fails with "LNK1149: output filename
# matches input filename". A command-line tool exports nothing, so the import
# library is of no use to anyone; give it a directory of its own and the clash
# disappears. No effect on single-config generators, which do not produce one.
set_target_properties(sfcc_cli PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/import")
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
message(STATUS "  cache crypto ..... ${SFCC_CACHE_CRYPTO_BACKEND}")
message(STATUS "  executables ...... bin/sfcc")
message(STATUS "")