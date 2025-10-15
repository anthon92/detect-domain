cmake_minimum_required(VERSION 3.16)

project(detect-domain LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Network)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Network)

if (WIN32)
    # Set PCAP SDK path relative to project root
    set(NPCAP_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk")
    message(STATUS "PCAP SDK directory: ${NPCAP_SDK_DIR}")

    include_directories(${NPCAP_SDK_DIR}/Include)
    link_directories(${NPCAP_SDK_DIR}/Lib/x64)  # or x86 if 32-bit
endif()

add_executable(detect-domain
  main.cpp
  domainsniffer.h domainsniffer.cpp
)

target_link_libraries(detect-domain
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::Network
  wpcap
  Packet
  ws2_32
)

set_target_properties(${PROJECT_NAME} PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

include(GNUInstallDirs)
install(TARGETS detect-domain
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
