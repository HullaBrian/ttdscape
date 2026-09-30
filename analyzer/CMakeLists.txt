cmake_minimum_required(VERSION 3.21)
project(ttdscape_analyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "TTDscape analyzer must be built with MSVC for x64 (the TTD replay host).")
endif()

# --- TTD Replay SDK (NuGet Microsoft.TimeTravelDebugging.Apis) ------------------------------------
set(TTD_API_VERSION "0.9.5" CACHE STRING "Microsoft.TimeTravelDebugging.Apis version")
set(TTD_SDK_DIR "$ENV{USERPROFILE}/.nuget/packages/microsoft.timetraveldebugging.apis/${TTD_API_VERSION}"
    CACHE PATH "Root of the restored Microsoft.TimeTravelDebugging.Apis package")
list(APPEND CMAKE_PREFIX_PATH "${TTD_SDK_DIR}/CMake")
find_package(Microsoft.TimeTravelDebugging.Apis REQUIRED)

include(cmake/TtdRuntime.cmake)

add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)

# --- Core library (everything except main), shared with unit tests -------------------------------
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS src/*.cpp src/*.h)
list(FILTER CORE_SOURCES EXCLUDE REGEX "src/main\\.cpp$")
# API argument decoding vendored from ttd-capa-cpp (third_party/ttdcapa/README.md). Its headers
# include the TTD SDK directly, so ttd.h is forced in first for DBG_ASSERT.
file(GLOB TTDCAPA_SOURCES CONFIGURE_DEPENDS third_party/ttdcapa/*.cpp third_party/ttdcapa/*.hpp)
set_source_files_properties(${TTDCAPA_SOURCES} PROPERTIES COMPILE_OPTIONS "/W3;/FIttd.h")
add_library(ttdscape_core STATIC ${CORE_SOURCES} ${TTDCAPA_SOURCES})
target_include_directories(ttdscape_core PUBLIC src third_party/ttdcapa)
set(TTDCAPA_INDEXES ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ttdcapa/data/win32-index.bin
                    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ttdcapa/data/phnt-index.bin)
function(deploy_arg_indexes target)
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${TTDCAPA_INDEXES} $<TARGET_FILE_DIR:${target}>)
endfunction()
target_link_libraries(ttdscape_core PUBLIC Microsoft.TimeTravelDebugging.Apis::TTDReplay dbghelp)

add_executable(ttdscape-analyzer src/main.cpp)
target_link_libraries(ttdscape-analyzer PRIVATE ttdscape_core)
ttd_deploy_runtime(ttdscape-analyzer)
deploy_arg_indexes(ttdscape-analyzer)

# --- Test fixture (recorded with ttd.exe) ----------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../fixtures/app/CMakeLists.txt")
    add_subdirectory(../fixtures/app fixtures)
endif()

# --- Unit tests -------------------------------------------------------------------------------------
enable_testing()
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS tests/test_*.cpp)
foreach(src ${TEST_SOURCES})
    get_filename_component(t ${src} NAME_WE)
    string(REGEX REPLACE "^test_" "" t ${t})
    add_executable(test_${t} ${src})
    target_link_libraries(test_${t} PRIVATE ttdscape_core)
    ttd_deploy_runtime(test_${t})
    deploy_arg_indexes(test_${t})
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
