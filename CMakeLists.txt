cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Shared source files (everything except main files)
set(SHARED_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/dpi_engine.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Basic packet analyzer
add_executable(packet_analyzer src/main.cpp ${SHARED_SOURCES})

# DPI engine application (main_dpi.cpp)
add_executable(dpi_engine_app src/main_dpi.cpp ${SHARED_SOURCES})

# Simple analyzer
add_executable(simple_analyzer src/main_simple.cpp ${SHARED_SOURCES})

# Multithreaded DPI
add_executable(dpi_mt src/dpi_mt.cpp ${SHARED_SOURCES})

# Threading support
find_package(Threads REQUIRED)
target_link_libraries(packet_analyzer Threads::Threads)
target_link_libraries(dpi_engine_app Threads::Threads)
target_link_libraries(simple_analyzer Threads::Threads)
target_link_libraries(dpi_mt Threads::Threads)

# For macOS, we might need to link against system libraries later
if(APPLE)
    # Add any macOS-specific settings here
endif()
