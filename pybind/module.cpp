#include "common.hpp"


PYBIND11_MODULE(pycryptonote, mod)
{
  crypto::PyBind_Init(mod.def_submodule("crypto"));
  pyvarint::PyBind_Init(mod.def_submodule("varint"));
}
