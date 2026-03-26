cmake_minimum_required(VERSION 3.28)
project(yail VERSION 0.0.1 LANGUAGES CXX)

file(GLOB_RECURSE YAIL_HEADERS "include/*.hpp")
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