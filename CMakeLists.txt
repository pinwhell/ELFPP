cmake_minimum_required(VERSION 3.10)

project(ELFPP) 

option(ELFPP_INSTALL "Install ELFPP" OFF)

add_library(ELFPP INTERFACE)

target_include_directories(ELFPP INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

if(ELFPP_INSTALL)
    install(FILES include/ELFPP.hpp DESTINATION include)
    install(TARGETS ELFPP EXPORT ELFPPTargets)
    export(EXPORT ELFPPTargets FILE ELFPPConfig.cmake) 
    install(EXPORT ELFPPTargets FILE ELFPPConfig.cmake DESTINATION cmake)
endif()