cmake_minimum_required(VERSION 3.10)
project(ELFPP) 
include(cmake/CBuildKit.cmake)
option(ELFPP_INSTALL "Install ELFPP" ON)
add_subdirectory(vendor)

add_library_ns(elfpp elfpp INTERFACE)
target_include_dir_iface(elfpp-elfpp INTERFACE ${CMAKE_SOURCE_DIR}/include include)
add_subdirectory(tests)

if(ELFPP_INSTALL)
	install_target_and_headers(elfpp elfpp)
	install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)
	install(FILES cmake/ELFPPConfig.cmake DESTINATION lib/cmake/elfpp)
endif()
