cmake_minimum_required(VERSION 3.15)
project(Kerberos-Simulation)

# Sử dụng vcpkg (nếu có)
set(CMAKE_TOOLCHAIN_FILE "C:/Users/quang/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Chọn C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Thêm thư viện
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread asio)

# Thêm source code
add_executable(kerberos_sim
    src/main.cpp
    src/kerberos_auth.cpp src/kerberos_auth.h
    src/kerberos_tgs.cpp src/kerberos_tgs.h
    src/kerberos_service.cpp src/kerberos_service.h
    src/encryption.cpp src/encryption.h
)

# Link thư viện
target_include_directories(kerberos_sim PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(kerberos_sim PRIVATE ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
