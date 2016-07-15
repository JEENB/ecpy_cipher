#pragma once
#include <array>
#include <string>
#include <random>
#include <vector>
#include <sstream>
#include <iostream>

#include <gmp.h>
#include <gmpxx.h>

#define __EXPORT__ extern "C"

struct ZZ {
  mpz_class x;
};

struct FF {
  ZZ *x;
  ZZ *p;
};
__EXPORT__ {
  ZZ *ZZ_create(const char*);
  void ZZ_destroy(const ZZ*);
  ZZ *ZZ_add(const ZZ*, const ZZ*);
  ZZ *ZZ_neg(const ZZ*);
  ZZ *ZZ_mul(const ZZ*, const ZZ*);
  ZZ *ZZ_div(const ZZ*, const ZZ*);
  ZZ *ZZ_mod(const ZZ*, const ZZ*);
  ZZ *ZZ_modinv(const ZZ*, const ZZ*);
  bool ZZ_to_string(const ZZ *zz, char *p, int maxlen);
  bool ZZ_is_equals(const ZZ*, const ZZ*);
}

ZZ *ZZ_create_from_mpz_class(mpz_class);
std::string ZZ_to_string_as_std_string(const ZZ *zz);
ZZ *ZZ_copy(ZZ*);

__EXPORT__ {
  FF *FF_create(const char*, const char*);
  void FF_destroy(const FF*);
  FF *FF_add(const FF*, const FF*);
  FF *FF_neg(const FF*);
  FF *FF_mul(const FF*, const FF*);
  FF *FF_div(const FF*, const FF*);
  FF *FF_mod(const FF*, const FF*);
  bool FF_is_equals(const FF*, const FF*);
  bool FF_to_string(const FF*, char*, int);
  bool FF_to_raw_string(const FF*, char*, int);
}
FF *FF_create_from_mpz_class(mpz_class, mpz_class);
std::string FF_to_string_as_std_string(const FF*);
std::string FF_to_raw_string_as_std_string(const FF*);
