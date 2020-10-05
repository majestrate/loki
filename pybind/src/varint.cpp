#include "common.hpp"
#include <string_view>

namespace pyvarint
{

  const auto msb = py::int_{0b1000'0000};
  const auto lower7 = py::int_{0b0111'1111};
  const auto seven = py::int_{7};
  const auto zero = py::int_{0};

  std::string
  write_varint(py::int_ varint)
  {
    std::string data;
    while(varint > lower7)
    {
      const py::int_ ch = (varint & lower7) | msb;
      data += ch;
      varint = varint >> seven;
    }
    data += varint;
    return data;
  }

  std::tuple<py::int_, std::size_t>
  read_varint(std::string_view data)
  {
    py::int_ result = 0;
    const auto datalen = data.size();
    const auto ptr = data.data();
    if(datalen == 0)
      throw std::invalid_argument("cannot read empty bytes");
    std::size_t idx = 0;
    bool more = true;
    for(py::int_ shift = 0; more && idx != datalen; shift = shift + seven)
    {
      const py::int_ byte = ptr[idx++];
      if(byte.is(zero) and shift > zero)
        throw std::invalid_argument("byte is all zeros and isn't the first byte");
      more = not (byte & msb).is(zero);
      py::int_ tmp = byte & lower7;
      tmp = tmp << shift;
      result = tmp | result;
    }
    return std::tuple{result, idx};
  }
  
  void
  PyBind_Init(py::module mod)
  {
    mod.doc() = "cryptonote varint serialization";

    mod.def(
      "write",
      [](py::int_ varint) { return py::bytes(write_varint(varint)); },
      "write a monero varint to bytes");
    
    mod.def(
      "read",
      [](py::bytes data)
      {
        char * ptr = nullptr;
        Py_ssize_t size = 0;
        PyBytes_AsStringAndSize(data.ptr(), &ptr, &size);
        std::size_t sz = size;
        return read_varint(std::string_view{ptr, sz});
      },
      "read a monero varint from a bytes, return (int, bytes read)");
  }
}
