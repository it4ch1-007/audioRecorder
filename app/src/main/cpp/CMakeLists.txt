# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

project("audiorecorder")

# --- Dobby Setup ---
add_library(dobby STATIC IMPORTED)
set_target_properties(dobby PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/dobby/libdobby.a)

# --- Build the Hook Library ---
add_library(${CMAKE_PROJECT_NAME} SHARED hook.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/dobby)
target_link_libraries(${CMAKE_PROJECT_NAME}
        dobby
        android
        log)

# --- Build the Injector Executable ---
add_executable(injector injector.cpp)

# Link the 'injector' executable (NOT audiorecorder) to the log library.
target_link_libraries(injector
        android
        log)