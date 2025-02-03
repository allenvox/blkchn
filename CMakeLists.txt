cmake_minimum_required(VERSION 3.12)
project(blkchn)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)

add_executable(server server.cpp)
target_link_libraries(server Boost::system Boost::thread OpenSSL::Crypto)

add_executable(client client.cpp)
target_link_libraries(client Boost::system Boost::thread)
