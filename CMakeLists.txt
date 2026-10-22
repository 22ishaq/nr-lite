cmake_minimum_required(VERSION 3.20)

project(nrlite
  VERSION 0.1.0
  DESCRIPTION "Simplified 5G NR RRC/NAS protocol stack simulator"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# The library is also linked into a Python extension (Verdict), so build it position independent.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(NRLITE_IS_TOP_LEVEL ON)
else()
  set(NRLITE_IS_TOP_LEVEL OFF)
endif()

option(NRLITE_BUILD_TESTS "Build the GoogleTest suite" ${NRLITE_IS_TOP_LEVEL})
option(NRLITE_BUILD_APPS "Build the nrlite-sim command line tool" ${NRLITE_IS_TOP_LEVEL})
option(NRLITE_WERROR "Treat compiler warnings as errors" OFF)
option(NRLITE_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

add_library(nrlite_warnings INTERFACE)
if(MSVC)
  target_compile_options(nrlite_warnings INTERFACE /W4)
else()
  target_compile_options(nrlite_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
    -Wno-sign-conversion)
  if(NRLITE_WERROR)
    target_compile_options(nrlite_warnings INTERFACE -Werror)
  endif()
endif()

if(NRLITE_SANITIZE AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

file(GLOB_RECURSE NRLITE_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_library(nrlite STATIC ${NRLITE_SOURCES})
add_library(nrlite::nrlite ALIAS nrlite)
target_include_directories(nrlite PUBLIC
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(nrlite PUBLIC cxx_std_17)
target_link_libraries(nrlite PRIVATE nrlite_warnings)

if(NRLITE_BUILD_APPS)
  add_executable(nrlite-sim apps/nrlite_sim.cpp)
  target_link_libraries(nrlite-sim PRIVATE nrlite nrlite_warnings)
endif()

if(NRLITE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
