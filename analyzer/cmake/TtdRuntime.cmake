# Locates TTDReplay.dll / TTDReplayCPU.dll (from the installed TTD package) and a recent
# dbghelp.dll / symsrv.dll (from the Windows SDK Debuggers kit), and copies them next to targets.
# TTDReplay.lib is a load-time import library, so the DLLs must be beside the exe (ReplayAPI.md §0).

set(TTD_RUNTIME_DIR "" CACHE PATH "Directory containing TTDReplay.dll and TTDReplayCPU.dll")
if(NOT TTD_RUNTIME_DIR)
    execute_process(
        COMMAND powershell -NoProfile -Command "(Get-AppxPackage Microsoft.TimeTravelDebugging | Sort-Object Version | Select-Object -Last 1).InstallLocation"
        OUTPUT_VARIABLE _ttd_dir OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(_ttd_dir AND EXISTS "${_ttd_dir}/TTDReplay.dll")
        set(TTD_RUNTIME_DIR "${_ttd_dir}" CACHE PATH "" FORCE)
    endif()
endif()
if(NOT EXISTS "${TTD_RUNTIME_DIR}/TTDReplay.dll")
    message(FATAL_ERROR "TTDReplay.dll not found. Install TTD (winget install Microsoft.TimeTravelDebugging) or set -DTTD_RUNTIME_DIR=...")
endif()
message(STATUS "TTD runtime: ${TTD_RUNTIME_DIR}")

set(DBGHELP_DIR "" CACHE PATH "Directory with a recent dbghelp.dll + symsrv.dll (optional)")
if(NOT DBGHELP_DIR)
    foreach(_c "$ENV{ProgramFiles\(x86\)}/Windows Kits/10/Debuggers/x64" "$ENV{ProgramFiles}/Windows Kits/10/Debuggers/x64")
        if(EXISTS "${_c}/dbghelp.dll" AND EXISTS "${_c}/symsrv.dll")
            set(DBGHELP_DIR "${_c}" CACHE PATH "" FORCE)
            break()
        endif()
    endforeach()
endif()

set(TTD_RUNTIME_FILES "${TTD_RUNTIME_DIR}/TTDReplay.dll" "${TTD_RUNTIME_DIR}/TTDReplayCPU.dll")
if(DBGHELP_DIR)
    message(STATUS "DbgHelp: ${DBGHELP_DIR}")
    list(APPEND TTD_RUNTIME_FILES "${DBGHELP_DIR}/dbghelp.dll" "${DBGHELP_DIR}/symsrv.dll")
else()
    message(WARNING "Debuggers kit dbghelp.dll not found; the system dbghelp (no symbol server) will be used.")
endif()

function(ttd_deploy_runtime target)
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${TTD_RUNTIME_FILES} "$<TARGET_FILE_DIR:${target}>"
        COMMAND_EXPAND_LISTS)
endfunction()
