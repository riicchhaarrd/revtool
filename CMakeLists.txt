cmake_minimum_required(VERSION 3.16)
project(dis LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

add_executable(dis
    src/main.cpp
    src/mainwindow.cpp
    src/hexwidget.cpp
    src/disasmwidget.cpp
    src/infowidget.cpp
    src/csyntax.cpp
)

target_include_directories(dis PRIVATE src ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(dis PRIVATE Qt6::Widgets ${CAPSTONE_LIBRARIES})
target_link_directories(dis PRIVATE ${CAPSTONE_LIBRARY_DIRS})
