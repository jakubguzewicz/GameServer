cmake_minimum_required(VERSION 3.14)
project(GameServer VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.74.0)
if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
endif()

add_compile_options(-Wall -Wextra -pedantic -Werror)

include_directories(lib)
include_directories(include)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/include/proto)

enable_testing()

add_subdirectory(lib)
add_subdirectory(src)
add_subdirectory(include)