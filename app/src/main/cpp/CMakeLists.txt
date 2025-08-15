cmake_minimum_required(VERSION 3.22.1)
project("audiorecorder")

# 1. Add the Dobby source code as a sub-project.
# This will automatically find and build Dobby, creating a target
# named 'dobby_static'.
#add_subdirectory(dobby)

# Find the Android log library.
find_library(log-lib log)

# --- Build the Hook Library ---
add_library(hook SHARED hook.cpp)

# 2. Link your 'hook' library against the 'dobby_static' target
# that was created by the add_subdirectory command.
target_link_libraries(hook

        ${log-lib})

# --- Build the Injector Executable ---
add_executable(injector injector.cpp)
target_link_libraries(injector ${log-lib})