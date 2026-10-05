# Headless simulator for native MeowKit ELF apps.
# Implements the mk_app ABI over an off-screen LovyanGFX sprite (the same
# MK_TUI helpers app_sdk.cpp uses on device) and runs the app's real app_main().
#
#   cmake -S sim -B sim/build -DFERALCAT_ROOT=/path/to/FeralCat -DAPP_SRC=app/app_main.c
#   cmake --build sim/build
cmake_minimum_required(VERSION 3.16)
project(meowkit-app CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Path to a FeralCat firmware checkout — it supplies LovyanGFX, MK_TUI and the
# mk_app ABI header. Pass -DFERALCAT_ROOT=/path/to/FeralCat.
if(NOT DEFINED FERALCAT_ROOT)
    message(FATAL_ERROR "pass -DFERALCAT_ROOT=<path to a FeralCat checkout>")
endif()
set(FW_ROOT ${FERALCAT_ROOT})
set(LGFX ${FW_ROOT}/lib/LovyanGFX/src)

if(NOT DEFINED APP_SRC)
    message(FATAL_ERROR "pass -DAPP_SRC=<path to the app's app_main.c> (relative to the repo root)")
endif()
if(IS_ABSOLUTE "${APP_SRC}")
    set(APP_SRC_ABS "${APP_SRC}")
else()
    set(APP_SRC_ABS "${CMAKE_CURRENT_SOURCE_DIR}/../${APP_SRC}")
endif()
if(NOT EXISTS "${APP_SRC_ABS}")
    message(FATAL_ERROR "APP_SRC not found: ${APP_SRC_ABS}")
endif()
message(STATUS "native-app sim: building ${APP_SRC_ABS}")

add_definitions(-DLGFX_SDL)

file(GLOB_RECURSE LGFX_SRC CONFIGURE_DEPENDS
    ${LGFX}/lgfx/Fonts/efont/*.c
    ${LGFX}/lgfx/Fonts/IPA/*.c
    ${LGFX}/lgfx/utility/*.c
    ${LGFX}/lgfx/v1/*.cpp
    ${LGFX}/lgfx/v1/misc/*.cpp
    ${LGFX}/lgfx/v1/panel/Panel_Device.cpp
    ${LGFX}/lgfx/v1/panel/Panel_FrameBufferBase.cpp
    ${LGFX}/lgfx/v1/platforms/sdl/*.cpp)

add_executable(meowkit-app main.cpp "${APP_SRC_ABS}" ${LGFX_SRC})
target_include_directories(meowkit-app PRIVATE
    ${LGFX}
    ${FW_ROOT}/src/app
    ${FW_ROOT}/src/app/app_common
    ${FW_ROOT}/src/system)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
target_include_directories(meowkit-app PRIVATE ${SDL2_INCLUDE_DIRS})
target_link_libraries(meowkit-app PRIVATE ${SDL2_LIBRARIES} pthread)
target_compile_options(meowkit-app PRIVATE ${SDL2_CFLAGS_OTHER})
