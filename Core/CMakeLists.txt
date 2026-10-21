cmake_minimum_required(VERSION 3.16)
project(vectorsstryke_engine VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VS_ENGINE_BUILD_TESTS "Build unit tests" ON)
option(VS_ENGINE_BUILD_CLI "Build vs-engine CLI" ON)
option(VS_ENGINE_USE_ASM "Enable optional x86_64 ASM pattern search stub" OFF)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

set(VS_ENGINE_SOURCES
  src/core/config.cpp
  src/core/engine.cpp
  src/api/vs_engine.cpp
  src/detect/detect.cpp
  src/scan/scan.cpp
  src/sig/signature.cpp
  src/sig/pattern_search.cpp
)

if(VS_ENGINE_USE_ASM AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
  enable_language(ASM)
  list(APPEND VS_ENGINE_SOURCES src/sig/pattern_search_amd64.S)
  add_compile_definitions(VS_ENGINE_USE_ASM=1)
endif()

add_library(vs_engine ${VS_ENGINE_SOURCES})
target_include_directories(vs_engine
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_definitions(vs_engine PRIVATE VS_ENGINE_BUILD=1)

if(VS_ENGINE_BUILD_CLI)
  add_executable(vs-engine cli/vs_engine_cli.cpp)
  target_link_libraries(vs-engine PRIVATE vs_engine)
endif()

if(VS_ENGINE_BUILD_TESTS)
  enable_testing()
  add_executable(test_mode tests/test_mode.cpp)
  target_link_libraries(test_mode PRIVATE vs_engine)
  add_test(NAME test_mode COMMAND test_mode)
  add_executable(test_detect_scan tests/test_detect_scan.cpp)
  target_link_libraries(test_detect_scan PRIVATE vs_engine)
  add_test(NAME test_detect_scan COMMAND test_detect_scan)
endif()

install(TARGETS vs_engine ARCHIVE DESTINATION lib LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
install(DIRECTORY include/vs_engine DESTINATION include)
