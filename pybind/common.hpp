#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>

namespace py = pybind11;

namespace crypto
{
  void
  PyBind_Init(py::module mod);
};

namespace pyvarint
{
  void
  PyBind_Init(py::module mod);
};
