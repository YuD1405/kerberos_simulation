cmake_minimum_required(VERSION 3.15)
project(Kerberos-Simulation)

# Sử dụng vcpkg (nếu có)
set(CMAKE_TOOLCHAIN_FILE "C:/Users/p14s/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Chọn C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Thêm thư viện
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread asio)

# Thêm source code
add_executable(kerberos_sim
    src/main.cpp
    src/authentication_server.cpp include/authentication_server.h
    src/ticket_granting_server.cpp include/ticket_granting_server.h
    src/service_server.cpp include/service_server.h
    src/encryption.cpp include/encryption.h
    src/client.cpp include/client.h
    src/kerberos_protocol.cpp include/kerberos_protocol.h
)

# Link thư viện
target_include_directories(kerberos_sim PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(kerberos_sim PRIVATE ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
