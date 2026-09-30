# Built as part of the analyzer project (x64), or standalone for other architectures:
#   cmake -S fixtures/app -B build/fixture-x86 -A Win32 && cmake --build build/fixture-x86 --config RelWithDebInfo
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.21)
    project(ttdscape_fixture LANGUAGES CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(ttdscape-fixture fixture.cpp)
target_compile_options(ttdscape-fixture PRIVATE /Zi /O2 /GS- /EHsc)
target_link_options(ttdscape-fixture PRIVATE /DEBUG:FULL /INCREMENTAL:NO)
