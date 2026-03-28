cmake_minimum_required(VERSION 3.16)
project(dis_wasm LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Root of the main project (one level up from this wasm/ subdir)
set(DIS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Capstone static lib compiled for WASM (built by build_wasm.sh)
set(CAPSTONE_WASM_LIB "${DIS_ROOT}/wasm_deps/lib/libcapstone.a"
    CACHE PATH "Path to capstone static lib built for WASM")
set(CAPSTONE_WASM_INC "${DIS_ROOT}/wasm_deps/include"
    CACHE PATH "Path to capstone headers")

add_executable(dis_wasm "${DIS_ROOT}/src/wasm_api.cpp")

target_include_directories(dis_wasm PRIVATE "${DIS_ROOT}/src" ${CAPSTONE_WASM_INC})

target_link_libraries(dis_wasm PRIVATE ${CAPSTONE_WASM_LIB})

# Emscripten settings
target_link_options(dis_wasm PRIVATE
    # Embind for C++/JS bindings
    "--bind"
    # 256 MB heap (large binaries + decompilation can be memory-hungry)
    "-sINITIAL_MEMORY=268435456"
    "-sALLOW_MEMORY_GROWTH=1"
    # Virtual filesystem (for /tmp writes)
    "-sFORCE_FILESYSTEM=1"
    # Export a factory function so the module is easy to load
    "-sMODULARIZE=1"
    "-sEXPORT_NAME=createDisModule"
    # Export malloc/free so JS can allocate WASM memory for binary data
    "-sEXPORTED_FUNCTIONS=['_malloc','_free']"
    # Optimise for size/speed
    "-O2"
)

# Output to web/ directory alongside index.html
set_target_properties(dis_wasm PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${DIS_ROOT}/web"
    OUTPUT_NAME "dis"
    SUFFIX ".js"
)
