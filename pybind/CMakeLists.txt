
find_package(pybind11 REQUIRED)


pybind11_add_module(pycryptonote
  src/cryptography.cpp
  src/varint.cpp
  module.cpp
)

target_include_directories(pycryptonote PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pycryptonote PUBLIC cncrypto)
