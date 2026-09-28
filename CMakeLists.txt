cmake_minimum_required(VERSION 3.15)
project(NatPuncher LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Opus + OpenSSL come from vcpkg (see README / build steps).
# miniaudio.h is header-only and lives next to NatPuncher.cpp.
find_package(Opus CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(NatPuncher NatPuncher.cpp)

target_include_directories(NatPuncher PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(NatPuncher PRIVATE
    Opus::opus
    OpenSSL::Crypto
    ws2_32)