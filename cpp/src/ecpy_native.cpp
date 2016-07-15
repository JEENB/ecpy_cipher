#include "ecpy_native.h"

using namespace std;

__EXPORT__ FF *FF_create_from_mpz_class(mpz_class x, mpz_class p) {
  FF *ff = new FF;
  ff->p = ZZ_create_from_mpz_class(p);
  ff->x = ZZ_create_from_mpz_class(x % p);
  return ff;
}

__EXPORT__ FF *FF_create(const char *x, const char *p) {
  FF *ff = new FF;
  ff->p = ZZ_create(p);
  auto t = ZZ_create(x);
  ff->x = ZZ_mod(t, ff->p);
  ZZ_destroy(t);
  return ff;
}

__EXPORT__ void FF_destroy(FF *ff) {
  ZZ_destroy(ff->x);
  ZZ_destroy(ff->p);
  delete ff;
}

__EXPORT__ FF *FF_add(FF *a, FF *b) {
  FF *ret = new FF;
  ret->p = ZZ_copy(a->p);
  if (ZZ_is_equals(a->p, b->p)) {
    auto t = ZZ_add(a->x, b->x);
    ret->x = ZZ_mod(t, a->p);
    ZZ_destroy(t);
  } else {
    ret->x = ZZ_create_from_mpz_class(-1);
    ret->p = ZZ_create_from_mpz_class(-1);
  }
  return ret;
}

__EXPORT__ FF *FF_neg(FF *a) {
  FF *ret = new FF;
  auto t = ZZ_neg(a->x);
  ret->x = ZZ_add(t, a->p);
  ret->p = ZZ_copy(a->p);
  ZZ_destroy(t);
  return ret;
}

__EXPORT__ FF *FF_mul(FF *a, FF *b) {
  FF *ret = new FF;
  ret->p = ZZ_copy(a->p);
  if (ZZ_is_equals(a->p, b->p)) {
    auto t = ZZ_mul(a->x, b->x);
    ret->x = ZZ_mod(t, a->p);
    ZZ_destroy(t);
  } else {
    ret->x = ZZ_create_from_mpz_class(-1);
    ret->p = ZZ_create_from_mpz_class(-1);
  }
  return ret;
}

__EXPORT__ FF *FF_div(FF *a, FF *b) {
  FF *ret = new FF;
  ret->p = ZZ_copy(a->p);
  if (ZZ_is_equals(a->p, b->p)) {
    auto t = ZZ_modinv(b->x, a->p);
    auto u = ZZ_mul(a->x, t);
    ret->x = ZZ_mod(u, a->p);
    ZZ_destroy(t);
    ZZ_destroy(u);
  } else {
    ret->x = ZZ_create_from_mpz_class(-1);
    ret->p = ZZ_create_from_mpz_class(-1);
  }
  return ret;
}

__EXPORT__ FF *FF_mod(FF *a, FF *b) {
  FF *ret = new FF;
  ret->p = ZZ_copy(a->p);
  ret->x = ZZ_mod(a->x, b->x);
  return ret;
}

__EXPORT__ bool FF_to_raw_string(const FF *ff, char *p, int maxlen) {
  auto c = FF_to_raw_string_as_std_string(ff);
  if (c.size() < maxlen) {
    strcpy(p, c.c_str());
    return true;
  }
  return false;
}

__EXPORT__ bool FF_to_string(const FF *ff, char *p, int maxlen) {
  auto c = FF_to_string_as_std_string(ff);
  if (c.size() < maxlen) {
    strcpy(p, c.c_str());
    return true;
  }
  return false;
}

string FF_to_raw_string_as_std_string(const FF *ff) {
  stringstream ss;
  ss << "FF_Native('" << ZZ_to_string_as_std_string(ff->x) << "', '" << ZZ_to_string_as_std_string(ff->p) << "')";
  return ss.str();
}

string FF_to_string_as_std_string(const FF *ff) {
  stringstream ss;
  ss << ZZ_to_string_as_std_string(ff->x) << " modulo " << ZZ_to_string_as_std_string(ff->p);
  return ss.str();
}

__EXPORT__ bool FF_is_equals(FF *ee, FF *ff) {
  return ZZ_is_equals(ee->x, ff->x) && ZZ_is_equals(ee->p, ff->p);
}
