cmake_minimum_required(VERSION 2.8.12)
enable_testing()

project(libicloud C)
include(CTest)

find_package(CURL REQUIRED)
find_package(json-c REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(SQLite3)
pkg_check_modules(UUID REQUIRED uuid)

find_package(cmocka)

option(CURL_VERBOSE "Enable curl verbosity" OFF)

include_directories(src ${CMAKE_CURRENT_BINARY_DIR})
include_directories(SYSTEM
	${CURL_INCLUDE_DIR}
	${UUID_INCLUDE_DIRS})

configure_file(src/config.h.in config.h)

add_library(icloud src/icloud.c)
target_link_libraries(icloud 
		${CURL_LIBRARIES}
		json-c::json-c 
		${UUID_LIBRARIES})

if (cmocka_FOUND)
  add_executable(test_icloud tests/test_icloud.c)
  target_link_libraries(test_icloud icloud cmocka)
  
  add_test(test_icloud test_icloud)
else()
  message(STATUS "Unable to find cmocka. Tests are disabled.")
endif()
