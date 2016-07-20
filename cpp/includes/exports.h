#pragma once
#include "ecpy_native.h"

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
  int ZZ_jacobi(const ZZ*, const ZZ*);
  int ZZ_legendre(const ZZ*, const ZZ*);

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

  EF *EF_create(const char*, const char*, const char*, const char*);
  void EF_destroy(const EF*);
  bool EF_to_string(const EF*, char*, int);
  bool EF_is_equals(const EF*, const EF*);
  EF *EF_add(const EF*, const EF*);
  EF *EF_neg(const EF*);
  EF *EF_mul(const EF*, const EF*);
  EF *EF_inv(const EF*);

  EC *EC_create(const char*, const char*, const char*);
  void EC_destroy(const EC*);
  bool EC_is_equals(const EC*, const EC*);
}
