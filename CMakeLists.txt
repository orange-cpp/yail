cmake_minimum_required(VERSION 3.28)
project(yail VERSION 0.0.1 LANGUAGES CXX)

if (PROJECT_IS_TOP_LEVEL)
    include(CTest)
endif()

file(GLOB_RECURSE YAIL_HEADERS "include/*.hpp" "include/*.h")
file(GLOB_RECURSE YAIL_SOURCES "source/*.cpp")


add_library(${PROJECT_NAME} STATIC ${YAIL_HEADERS} ${YAIL_SOURCES})
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 23)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(${PROJECT_NAME} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror>
)

find_package(omath CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE omath::omath)

option(YAIL_USE_PDB "Resolve private ntdll symbols from Microsoft PDBs" ON)

if (YAIL_USE_PDB)
    target_link_libraries(${PROJECT_NAME} PRIVATE winhttp)
    target_compile_definitions(${PROJECT_NAME} PRIVATE YAIL_USE_PDB)
endif()

add_executable(generate_shellcode tools/generate_shellcode.cpp)
set_target_properties(generate_shellcode PROPERTIES CXX_STANDARD 23)
target_compile_definitions(generate_shellcode PRIVATE YAIL_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
find_package(zydis CONFIG REQUIRED)
target_link_libraries(generate_shellcode PRIVATE Zydis::Zydis)

option(YAIL_BUILD_EXAMPLES "Build yail examples" ON)

if (YAIL_BUILD_EXAMPLES)
    add_executable(loader examples/loader.cpp)
    set_target_properties(loader PROPERTIES CXX_STANDARD 23)
    target_link_libraries(loader PRIVATE yail)

    add_executable(remote_loader examples/remote_loader.cpp)
    set_target_properties(remote_loader PROPERTIES CXX_STANDARD 23)
    target_link_libraries(remote_loader PRIVATE yail)

    add_library(test_dll MODULE examples/test_dll.cpp)
    set_target_properties(test_dll PROPERTIES CXX_STANDARD 23)
    target_link_libraries(test_dll PRIVATE yail dbghelp winmm delayimp)
    target_link_options(test_dll PRIVATE /DELAYLOAD:dbghelp.dll /DELAYLOAD:winmm.dll)

    add_executable(test_exe examples/test_exe.cpp)
    set_target_properties(test_exe PROPERTIES CXX_STANDARD 23)
    target_link_libraries(test_exe PRIVATE dbghelp winmm delayimp)
    target_link_options(test_exe PRIVATE /DELAYLOAD:dbghelp.dll /DELAYLOAD:winmm.dll)

    add_executable(test_winexe examples/test_winexe.cpp)
    set_target_properties(test_winexe PROPERTIES CXX_STANDARD 23)
    target_link_libraries(test_winexe PRIVATE dbghelp delayimp)
    # /SUBSYSTEM:WINDOWS makes the linker pick WinMainCRTStartup as the entry,
    # which the CRT uses to dispatch to WinMain (instead of main).
    target_link_options(test_winexe PRIVATE /SUBSYSTEM:WINDOWS /DELAYLOAD:dbghelp.dll)

    if (PROJECT_IS_TOP_LEVEL AND BUILD_TESTING)
        add_test(NAME yail.test_dll COMMAND loader $<TARGET_FILE:test_dll>)
    endif()
endif()


include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

configure_package_config_file(
    cmake/${PROJECT_NAME}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)
