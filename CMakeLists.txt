cmake_minimum_required(VERSION 3.5)
project(HostDiscoverer
        VERSION 0.0.1
        DESCRIPTION "Scan local networks"
        LANGUAGES CXX)  

add_executable(HostDiscoverer src/main.cpp src/Kping.cpp)
target_compile_features(HostDiscoverer PRIVATE cxx_std_20)
target_include_directories(HostDiscoverer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)