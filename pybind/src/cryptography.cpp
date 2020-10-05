#include "common.hpp"
#include "crypto/crypto.h"
#include "lokimq/hex.h"

namespace pytools
{
  template<typename T>
  std::string
  to_hex(T t)
  {
    return lokimq::to_hex(std::string_view{reinterpret_cast<const char *>(&t), sizeof(t)});
  }

  template<typename T>
  bool
  from_hex(T & t, std::string_view hex)
  {
    if(not lokimq::is_hex(hex))
      return false;
    if(hex.size() != 2*sizeof(T))
      return false;
    lokimq::from_hex(hex.begin(), hex.end(), reinterpret_cast<char*>(&t));
    return true;
  }

  template<typename Left, typename Right>
  bool
  equals(Left lhs, Right rhs)
  {
    if(sizeof(lhs) != sizeof(rhs))
      return false;
    return std::memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
  }
}

namespace crypto
{
  
  void
  PyBind_Init(py::module mod)
  {
    mod.doc() = "cryptonote cryptography";
    
    py::class_<ec_scalar>(mod, "ECScalar")
      .def("__eq__",
           [](const ec_scalar & self, const ec_scalar & other) -> bool
           { return pytools::equals(self, other); },
           "test equality")
      
      .def("from_hex",
           [](ec_scalar & k, std::string_view hex)
           {
             return pytools::from_hex(k, hex);
           },
           "read in from hex, returns false on failure")

      .def("to_hex",
           [](ec_scalar k)
           { return pytools::to_hex(std::move(k)); },
           "render this to hex")
      ;
    py::class_<ec_point>(mod, "ECPoint")
      .def("__eq__",
           [](const ec_point & self, const ec_point & other) -> bool
           { return pytools::equals(self, other); },
           "test equality")
      
      .def("from_hex",
           [](ec_point & k, std::string_view hex)
           {
             return pytools::from_hex(k, hex);
           },
           "read in from hex, returns false on failure")

      .def("to_hex",
           [](ec_point k)
           { return pytools::to_hex(std::move(k)); },
           "render this to hex")
      ;

    py::class_<key_derivation, ec_point>(mod, "KeyDerivation")
      .def("derive_secret_key",
           [](key_derivation self, secret_key sk, std::size_t outputIndex) -> secret_key
           {
             secret_key derived;
             derive_secret_key(self, outputIndex, sk, derived);
             return derived;
           },
           "derive secret key on output index")
      
      .def("derive_public_key",
           [](key_derivation self, public_key pk, std::size_t outputIndex) -> public_key
           {
             public_key derived;
             derive_public_key(self, outputIndex, pk, derived);
             return derived;
           },
           "derive public key on output index")
           
      .def("derive_subaddress_pubkey",
           [](key_derivation self, public_key pubkey, std::size_t outputIndex) -> public_key
           {
             public_key derived;
             if(not derive_subaddress_public_key(pubkey, self, outputIndex, derived))
               throw std::runtime_error("failed to derive sub address public key at index " + std::to_string(outputIndex));
             return derived;
           },
           "derive sub address public key on output index")
        
      .def("to_scalar",
           [](key_derivation kd, size_t outputIndex) -> ec_scalar
           {
             ec_scalar scalar;
             derivation_to_scalar(kd, outputIndex, scalar);
             return scalar;
           },
           "derivation to scalar")
      ;
    
    py::class_<public_key, ec_point>(mod, "PublicKey")
      .def(py::init(
          [](std::string key) -> public_key {
            public_key k;
            if(not pytools::from_hex(k, key))
              throw std::invalid_argument("key not hex");
             if(not check_key(k))
               throw std::invalid_argument("key is invalid");
             return k;
          }
             ))
      .def("check",
           [](public_key k)
           { return check_key(k); },
           "return true if a key is valid")
      
      .def("verify_signature",
           [](public_key pub, hash prefix_hash, signature sig)
           { return check_signature(prefix_hash, pub, sig); },
           "return true if a signature is valid")

      .def("derive_subaddress_pubkey",
           [](public_key k, key_derivation derivation, std::size_t outputIndex) -> public_key
           {
             public_key subaddress;
             if(not derive_subaddress_public_key(k, derivation, outputIndex, subaddress))
               throw std::runtime_error("failed to derive subaddress at index " + std::to_string(outputIndex));
             return subaddress;
           },
           "derivate a subaddress public key at an output index")
      
      .def("derive_public_key",
           [](public_key k, std::size_t outputIndex, key_derivation d) -> public_key
           {
             public_key derivedKey;
             if(not derive_public_key(d, outputIndex, k, derivedKey))
               throw std::runtime_error("could not derive public key at index "+ std::to_string(outputIndex));
             return derivedKey;
           },
           "derive a sub public key")
      ;

    py::class_<secret_key>(mod, "SecretKey")
      .def("to_public",
           [](const secret_key & sk) -> public_key
           {
             public_key pk;
             if(not secret_key_to_public_key(sk, pk))
               throw std::invalid_argument("to_public() called on invalid secret key");
             return pk;
           },
           "get public key from secret key")
      
      .def("generate_key_image",
           [](const secret_key & sk, public_key pk) -> key_image
           {
             key_image img;
             generate_key_image(pk, sk, img);
             return img;
           },
           "generate a key image")
      
      .def("generate_tx_proof",
           [](const secret_key & sk, hash prefixHash, public_key txPublicKey, public_key recipViewKey, key_derivation derivation, std::optional<public_key> recipSpendKey=std::nullopt) -> signature
           {
             signature sig;
             generate_tx_proof(prefixHash, txPublicKey, recipViewKey, recipSpendKey, public_key{derivation}, sk, sig);
             return sig;
           },
           "generate a tx proof")
      .def("xmrsign",
           [](const secret_key & sk, hash prefix_hash) -> signature
           {
             signature sig;
             public_key pk;
             if(not secret_key_to_public_key(sk, pk))
               throw std::runtime_error("failed to generate public key while signing");
             generate_signature(prefix_hash, pk, sk, sig);
             return sig;
           },
           "generate an xmr ('standard') signature")
      .def("generate_key_derivation",
           [](const secret_key & sk, public_key pk) -> key_derivation
           {
             key_derivation kd;
             if(not generate_key_derivation(pk, sk, kd))
               throw std::runtime_error("cannot generate key derivation");
             return kd;
           },
           "generate key derivation against another public key")
      ;

    py::class_<key_image>(mod, "KeyImage")
      .def("from_hex",
           [](key_image & image, std::string_view hex)
           { return pytools::from_hex(image, hex); },
           "read key image from hex")
      .def("to_hex",
           [](key_image image)
           { return pytools::to_hex(std::move(image)); },
           "render key image to hex string")
      .def("generate_ring_signature",
           [](key_image img, hash prefix_hash, std::vector<public_key> pubs, secret_key sk, std::size_t skIndex) -> std::vector<signature>
           {
             std::vector<signature> ringSig;
             std::vector<const public_key *> _pubs;
             for(const auto & k : pubs)
             {
               _pubs.emplace_back(&k);
               ringSig.emplace_back();
             }
             
             generate_ring_signature(prefix_hash, img, _pubs, sk, skIndex, ringSig.data());
             return ringSig;
           },
           "generate ring signature using this key image")
      ;

    py::class_<signature>(mod, "Signature")
      .def("from_hex",
           [](signature & sig, std::string_view hex)
           { return pytools::from_hex(sig, hex); },
           "read signature from hex string")
      .def("to_hex",
           [](signature sig)
           { return pytools::to_hex(std::move(sig)); },
           "render signature to hex string")
           
      .def("verify_tx_proof",
           [](signature sig, hash prefixHash, public_key txPubKey, public_key recipViewKey, key_derivation derivation, std::optional<public_key> recipSpendKey=std::nullopt) -> bool
           { return check_tx_proof(prefixHash, txPubKey, recipViewKey, recipSpendKey, public_key{derivation}, sig); },
           "verify a tx proof signature")
           
      .def_readwrite("c", &signature::c)
      .def_readwrite("r", &signature::r)
           
      ;

    py::class_<hash>(mod, "Hash")
      .def("__eq__",
           [](const hash & self, const hash & other) -> bool
           { return pytools::equals(self, other); },
           "test equality")
      
      .def("from_hex",
           [](hash & h, std::string_view hex)
           { return pytools::from_hex(h, hex); },
           "read hash from hex string")
      
      .def("to_hex",
           [](hash h)
           { return pytools::to_hex(std::move(h)); },
           "render hash as hex")
      ;

    mod.def("cn_fast_hash",
            [](std::string_view data) -> hash
            { return cn_fast_hash(data.data(), data.size()); },
            "this does the fast hash in cryptonote, TODO: what is that?");

    mod.def("cn_fast_hash",
            [](ec_scalar data) -> hash
            { return cn_fast_hash(&data, sizeof(data)); },
            "this does the fast hash in cryptonote, TODO: what is that?");

    mod.def("cn_fast_hash",
            [](ec_point data) -> hash
            { return cn_fast_hash(&data, sizeof(data)); },
            "this does the fast hash in cryptonote, TODO: what is that?");

    mod.def("generate_keys",
            []() -> std::pair<secret_key, public_key>
            {
              public_key pk;
              secret_key sk;
              generate_keys(pk, sk);
              return {sk, pk};
            });
    mod.def("verify_ring_signature",
            [](std::vector<signature> sig, hash prefixHash, key_image img, std::vector<public_key> pubs)
            {
             std::vector<const public_key *> _pubs;
             for(const auto & k : pubs)
               _pubs.emplace_back(&k);
             return check_ring_signature(prefixHash, img, _pubs, sig.data());
            },
            "verify a ring signature");
    
  }
}
