# Unit tests, plus smoke tests for the CLI that need no network.

add_executable(sfcc_tests test_units.c)
target_link_libraries(sfcc_tests PRIVATE sfcc)
target_include_directories(sfcc_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_compile_options(sfcc_tests PRIVATE ${SFCC_WARNINGS})

add_test(NAME units COMMAND sfcc_tests)

# The CLI checks below run the real binary and assert on its exit status and
# output. They are deliberately credential-free: they cover argument handling
# and the "no credentials" path, which is where a CLI most often gets its
# exit codes wrong.

add_test(NAME cli_help COMMAND sfcc_cli --help)
add_test(NAME cli_version COMMAND sfcc_cli --version)
add_test(NAME cli_version_short COMMAND sfcc_cli -V)

# No arguments at all is a usage error, not a crash: expect exit 2.
add_test(NAME cli_no_args COMMAND sfcc_cli)
set_tests_properties(cli_no_args PROPERTIES WILL_FAIL TRUE)

# An unknown command is also exit 2.
add_test(NAME cli_unknown_command COMMAND sfcc_cli frobnicate)
set_tests_properties(cli_unknown_command PROPERTIES WILL_FAIL TRUE)

# An unknown option must be reported, not silently ignored.
add_test(NAME cli_unknown_option COMMAND sfcc_cli --nonsense auth)
set_tests_properties(cli_unknown_option PROPERTIES WILL_FAIL TRUE)

# An option that needs a value and does not get one.
add_test(NAME cli_missing_value COMMAND sfcc_cli --instance)
set_tests_properties(cli_missing_value PROPERTIES WILL_FAIL TRUE)

# With no credentials in the environment, the tool must say so and exit 2
# rather than attempting a request. The environment is cleared so the developer's
# own exported variables cannot make this pass or fail by accident.
add_test(NAME cli_no_credentials COMMAND sfcc_cli auth)
set_tests_properties(cli_no_credentials PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A malformed record id must be rejected before any network call. This is the
# check that keeps a bad argument from becoming a confusing 404.
add_test(NAME cli_rejects_bad_id COMMAND sfcc_cli get Account not-an-id)
set_tests_properties(cli_rejects_bad_id PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# Options must be accepted anywhere on the command line, not only before the
# command. These assert the position does not matter, which is the case that
# used to silently swallow the flags and then blame missing credentials.
add_test(NAME cli_flags_after_command
  COMMAND sfcc_cli query "SELECT Id FROM Account" --instance https://x.invalid --token t)
set_tests_properties(cli_flags_after_command PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli_flags_interleaved
  COMMAND sfcc_cli --instance https://x.invalid query "SELECT Id FROM Account" --token t)
set_tests_properties(cli_flags_interleaved PROPERTIES WILL_FAIL TRUE)

# "--" must end option processing, so an argument may begin with a dash.
add_test(NAME cli_double_dash
  COMMAND sfcc_cli get -- --not-an-object 001000000000000AAA)
set_tests_properties(cli_double_dash PROPERTIES WILL_FAIL TRUE)

# Supplying one half of the instance/token pair must name the missing half,
# rather than falling back to a generic "no credentials".
add_test(NAME cli_instance_without_token COMMAND sfcc_cli --instance https://x.invalid auth)
set_tests_properties(cli_instance_without_token PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

add_test(NAME cli_token_without_instance COMMAND sfcc_cli --token some-token auth)
set_tests_properties(cli_token_without_instance PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# --- deploy ---------------------------------------------------------------
# These cover argument handling only. The full upload/poll/report path is
# exercised end-to-end against the mock, since it needs a server.

# deploy with no --zip must say so rather than reaching the network.
add_test(NAME cli_deploy_needs_zip COMMAND sfcc_cli deploy)
set_tests_properties(cli_deploy_needs_zip PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A zip that is not there, and one that is not a zip, both fail locally.
add_test(NAME cli_deploy_missing_zip COMMAND sfcc_cli deploy --zip /nonexistent/pkg.zip)
set_tests_properties(cli_deploy_missing_zip PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# --test-level specified without a list is a usage error, caught before the
# request: running it with no tests would silently mean "run nothing".
add_test(NAME cli_deploy_specified_needs_tests
  COMMAND sfcc_cli deploy --zip /nonexistent/pkg.zip --test-level specified)
set_tests_properties(cli_deploy_specified_needs_tests PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# An unrecognised test level must be rejected, not silently treated as none.
add_test(NAME cli_deploy_bad_test_level
  COMMAND sfcc_cli deploy --zip /nonexistent/pkg.zip --test-level bogus)
set_tests_properties(cli_deploy_bad_test_level PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# --- rest -----------------------------------------------------------------
add_test(NAME cli_rest_needs_path COMMAND sfcc_cli rest)
set_tests_properties(cli_rest_needs_path PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A raw space is refused before any request, naming the fix.
add_test(NAME cli_rest_rejects_raw_space COMMAND sfcc_cli rest "query?q=SELECT Id")
set_tests_properties(cli_rest_rejects_raw_space PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# An unsupported verb is rejected rather than passed through.
add_test(NAME cli_rest_bad_method COMMAND sfcc_cli rest limits -X TRACE)
set_tests_properties(cli_rest_bad_method PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A verb that needs a body, given none.
add_test(NAME cli_rest_patch_no_body COMMAND sfcc_cli rest limits -X PATCH)
set_tests_properties(cli_rest_patch_no_body PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# -d and --data-file are mutually exclusive.
add_test(NAME cli_rest_two_bodies
  COMMAND sfcc_cli rest limits -d "{}" --data-file /etc/hostname)
set_tests_properties(cli_rest_two_bodies PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A header with no colon would be silently dropped by libcurl, so it is caught.
add_test(NAME cli_rest_colonless_header COMMAND sfcc_cli rest limits -H NoColonHere)
set_tests_properties(cli_rest_colonless_header PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A bare "@" is caught before anything is opened.
add_test(NAME cli_rest_bare_at COMMAND sfcc_cli rest limits -X POST -d "@")
set_tests_properties(cli_rest_bare_at PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# "@file" naming a file that is not there.
add_test(NAME cli_rest_missing_at_file
  COMMAND sfcc_cli rest limits -X POST -d @/nonexistent/body.json)
set_tests_properties(cli_rest_missing_at_file PROPERTIES
  WILL_FAIL TRUE
  ENVIRONMENT "SFCC_CLIENT_ID=;SFCC_CLIENT_SECRET=;SFCC_ACCESS_TOKEN=;SFCC_INSTANCE_URL=")

# A custom request header must not crash the process.
#
# Regression test for an unterminated header array: the -H list is handed to the
# API as a NULL-terminated `const char* const*` and walked to the sentinel, so a
# missing terminator meant reading past the end of a stack array and
# dereferencing whatever was there. Harmless at -O0, where the slot happens to
# be zero; a segfault at -O2. ASan does not see it either, since the memory was
# still valid -- just not ours.
#
# PASS_REGULAR_EXPRESSION rather than an exit code, because a crash and a clean
# failure both exit non-zero. The assertion is that we reach the transport and
# report its refusal; a segfault produces no such output, so the test still
# fails while the bug is present.
#
# 127.0.0.1:1 refuses instantly, so no server or network is needed. The instance
# and token are supplied directly so this gets as far as building the request.
add_test(NAME cli_rest_custom_header_no_crash
  COMMAND sfcc_cli rest limits -H "X-Test: 1"
          --instance http://127.0.0.1:1 --token dummy)
set_tests_properties(cli_rest_custom_header_no_crash PROPERTIES
  PASS_REGULAR_EXPRESSION "could not reach")

# Several headers, so the walk gets past the first terminator slot.
add_test(NAME cli_rest_many_headers_no_crash
  COMMAND sfcc_cli rest limits -H "X-A: 1" -H "X-B: 2" -H "X-C: 3"
          --instance http://127.0.0.1:1 --token dummy)
set_tests_properties(cli_rest_many_headers_no_crash PROPERTIES
  PASS_REGULAR_EXPRESSION "could not reach")

# A query with no statement.
add_test(NAME cli_query_needs_soql COMMAND sfcc_cli query)
set_tests_properties(cli_query_needs_soql PROPERTIES WILL_FAIL TRUE)

# --- end-to-end -------------------------------------------------------------
#
# The tests above cover units and CLI argument handling with no server. This one
# drives the real binary against a mock Salesforce endpoint and checks the bytes
# on the wire -- which is the only reason the missing "Authorization: " prefix
# was ever caught. A unit test on the string constant would have passed while
# every request went out unauthenticated.
#
# Registered only where Python is present, so a machine without it still gets
# the rest of the suite. Skipped on Windows: these assert on POSIX file modes and
# lean on a background server's timing, and they are worth far more running
# properly on one platform than half-broken on three.

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND AND NOT WIN32)
  # Always run against the binary as built, which may be optimised. A
  # release-only crash was hiding in exactly this path.
  add_test(NAME e2e
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/e2e/e2e.py"
            "$<TARGET_FILE:sfcc_cli>")
  set_tests_properties(e2e PROPERTIES TIMEOUT 300)
endif()
