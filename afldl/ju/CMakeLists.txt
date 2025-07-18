cmake_minimum_required(VERSION 3.10)

project(ju VERSION 1.0)

# find_package(Python3 COMPONENTS Development) 


# compile options
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_STANDARD 17)


# package
find_package(OpenCV REQUIRED)
find_package(Torch REQUIRED PATHS "/usr/local/lib/libtorch")


include_directories(include)


add_library(ju SHARED src/ju.cpp)


# add_library(ju STATIC src/ju.cpp)


add_executable(main main.c)
target_link_libraries(main PRIVATE ju)

target_link_libraries(ju ${TORCH_LIBRARIES})
target_link_libraries(ju ${OpenCV_LIBS})

# install(TARGETS ju DESTINATION lib)
# install(DIRECTORY include/ DESTINATION include)