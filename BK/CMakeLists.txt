cmake_minimum_required(VERSION 3.16)
project(vectorsstrykebk VERSION 0.3.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VSBK_BUILD_TESTS "Build unit tests" ON)
option(VSBK_USE_OPENSSL "Use OpenSSL for SHA-256 if available" ON)

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(OpenSSL QUIET)
if(VSBK_USE_OPENSSL AND OpenSSL_FOUND)
  add_compile_definitions(VSBK_HAS_OPENSSL=1)
  set(VSBK_CRYPTO_LIBS OpenSSL::Crypto)
else()
  add_compile_definitions(VSBK_HAS_OPENSSL=0)
  set(VSBK_CRYPTO_LIBS "")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

add_library(vsbk_core STATIC
  src/common/util.c
  src/common/config.c
  src/storage/sal_local.c
  src/engine/pipeline.c
  src/engine/sha256_portable.c
)
target_link_libraries(vsbk_core PUBLIC ${VSBK_CRYPTO_LIBS})

add_executable(vsbk-agent src/agent/main.c)
target_link_libraries(vsbk-agent PRIVATE vsbk_core)

add_executable(vsbk-control-plane src/control_plane/main.c)
target_link_libraries(vsbk-control-plane PRIVATE vsbk_core)
if(WIN32)
  target_link_libraries(vsbk-control-plane PRIVATE ws2_32)
endif()

if(VSBK_BUILD_TESTS)
  enable_testing()
  add_executable(vsbk_test_sal tests/test_sal.c)
  target_link_libraries(vsbk_test_sal PRIVATE vsbk_core)
  add_test(NAME sal_local COMMAND vsbk_test_sal)
  add_executable(vsbk_test_pipeline tests/test_pipeline.c)
  target_link_libraries(vsbk_test_pipeline PRIVATE vsbk_core)
  add_test(NAME pipeline_hybrid COMMAND vsbk_test_pipeline)
endif()

install(TARGETS vsbk-agent vsbk-control-plane RUNTIME DESTINATION bin)
install(DIRECTORY include/vsbk DESTINATION include)
