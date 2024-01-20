cmake_minimum_required(VERSION 3.14)
project(GameServer VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG main
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_compile_options(-Wall -Wextra -pedantic -Werror)

include_directories(lib)
include_directories(include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

enable_testing()

add_subdirectory(lib)
add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(tests)