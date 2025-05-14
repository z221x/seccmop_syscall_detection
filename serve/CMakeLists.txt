# Minimum CMake version required
cmake_minimum_required(VERSION 3.14)

# Enable compile commands export
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set Android-specific variables
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-31)

# Ensure ANDROID_NDK_ROOT is set
if(NOT DEFINED ENV{ANDROID_NDK_ROOT} OR "$ENV{ANDROID_NDK_ROOT}" STREQUAL "")
    message(FATAL_ERROR "ANDROID_NDK_ROOT environment variable is not set or empty. Please set it to the path of your Android NDK.")
else()
    message(STATUS "Using NDK: $ENV{ANDROID_NDK_ROOT}")
endif()

# Set toolchain file
set(CMAKE_TOOLCHAIN_FILE "$ENV{ANDROID_NDK_ROOT}/build/cmake/android.toolchain.cmake")

# Set project name
project(detection_serve)

# Add source files
set(SOURCE_FILES
    detection_serve.cpp
)

# Add shared library
add_library(detection_serve SHARED ${SOURCE_FILES})

# Link necessary libraries
target_link_libraries(detection_serve
    log
    android
)