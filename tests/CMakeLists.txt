add_executable(
  sanity_check
  sanity_check.cpp
)
target_link_libraries(
  sanity_check
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(sanity_check)