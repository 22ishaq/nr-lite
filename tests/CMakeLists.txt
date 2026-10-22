include(FetchContent)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(googletest)

file(GLOB_RECURSE NRLITE_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*_test.cpp)
add_executable(nrlite_tests ${NRLITE_TEST_SOURCES})
target_include_directories(nrlite_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(nrlite_tests PRIVATE nrlite GTest::gtest_main)
# The library uses the strict warning set (incl. -Wconversion). Tests use -Wall -Wextra minus the two
# warnings that GoogleTest macros and brace-initialised messages trigger by design.
if(NOT MSVC)
  target_compile_options(nrlite_tests PRIVATE -Wall -Wextra -Wno-conversion -Wno-missing-field-initializers)
  if(NRLITE_WERROR)
    target_compile_options(nrlite_tests PRIVATE -Werror)
  endif()
endif()

include(GoogleTest)
gtest_discover_tests(nrlite_tests DISCOVERY_TIMEOUT 60)

# Wireshark cross-check: decode a generated trace with tshark and fail on any malformed packet.
find_program(TSHARK_EXECUTABLE tshark)
if(TSHARK_EXECUTABLE AND TARGET nrlite-sim)
  add_test(NAME wireshark_decodes_trace
    COMMAND ${CMAKE_COMMAND}
      -DSIM=$<TARGET_FILE:nrlite-sim>
      -DTSHARK=${TSHARK_EXECUTABLE}
      -DWORKDIR=${CMAKE_CURRENT_BINARY_DIR}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/wireshark/check_trace.cmake)
  set_tests_properties(wireshark_decodes_trace PROPERTIES LABELS wireshark)
endif()
