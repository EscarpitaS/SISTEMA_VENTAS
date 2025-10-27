cmake_minimum_required(VERSION 3.16)
project(SQL_LOGIN)

set(CMAKE_CXX_STANDARD 20)

# Habilitar procesamiento automático de Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Buscar Qt6 con Widgets y Sql
find_package(Qt6 REQUIRED COMPONENTS Widgets Sql)

# Crear ejecutable
add_executable(SQL_LOGIN
        main.cpp
        login_window.cpp
        login_window.h
)

# Linkear librerías (SOLO Qt)
target_link_libraries(SQL_LOGIN
        Qt6::Widgets
        Qt6::Sql
)