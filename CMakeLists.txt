cmake_minimum_required(VERSION 3.13.4)
project(paillier_test)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -pipe")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast -ffunction-sections -Wl,-gc-sections,--strip-all -mtune=native -flto -ffinite-math-only -march=native -fno-signed-zeros -fno-signaling-nans -fno-trapping-math -fassociative-math -freciprocal-math") #Quitar el -Ofast si falla
#Static linking
#set(CMAKE_EXE_LINKER_FLAGS "-static")
#set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc")
#set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

find_library(MPPP_LIB mp++)
find_library(GMP_LIB gmp)

add_executable(paillier_test test.cpp utils.h)

target_link_libraries(paillier_test ${MPPP_LIB} ${GMP_LIB})
