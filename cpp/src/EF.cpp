#include "ecpy_native.h"

using namespace std;

IrreduciblePolynomialType EF_Detect_Polynomial(const ZZ *n) {
  if (n->x % 4 == 3) {
    return IrreduciblePolynomialType::X2_1;
  } else if (n->x % 3 == 2 && n->x % 6 == 5 && is_prime((n->x + 1) / 6)) {
    return IrreduciblePolynomialType::X2_X_1;
  }
  throw invalid_argument("cannot determine irreducible polynomial");
}

IrreduciblePolynomialType EF_Get_Polynomial(const char *poly_str) {
  auto poly_ = string(poly_str);
  transform(poly_.begin(), poly_.end(), poly_.begin(), ::tolower);
  auto poly = accumulate(poly_.begin(), poly_.end(), string(), [](string a, char b) {
        if (b != ' ') {
          a += b;
        }
        return a;
      });
  if (poly == "x^2+1") {
    return IrreduciblePolynomialType::X2_1;
  } else if (poly == "x^2+x+1") {
    return IrreduciblePolynomialType::X2_X_1;
  }
  throw invalid_argument("invalid irreducible polynomial");
}

EF *EF_create_from_mpz_class(mpz_class x, mpz_class y, mpz_class n, IrreduciblePolynomialType type) {
  EF *ef = new EF;
  ef->modulo = ZZ_create_from_mpz_class(n);
  ef->poly = type;
  ef->x = ZZ_create_from_mpz_class(x % n);
  ef->y = ZZ_create_from_mpz_class(y % n);
  return ef;
}

__EXPORT__ EF *EF_create(const char *x, const char *y, const char *n, const char *poly) {
  EF *ef = new EF;
  ef->modulo = ZZ_create(n);
  {
    auto t = ZZ_create(x);
    ef->x = ZZ_mod(t, ef->modulo);
    ZZ_destroy(t);
  }
  {
    auto t = ZZ_create(y);
    ef->y = ZZ_mod(t, ef->modulo);
    ZZ_destroy(t);
  }
  ef->poly = EF_Get_Polynomial(poly);
  return ef;
}

__EXPORT__ void EF_destroy(const EF *ef) {
  ZZ_destroy(ef->modulo);
  ZZ_destroy(ef->x);
  ZZ_destroy(ef->y);
  delete ef;
}

__EXPORT__ EF *EF_add(const EF *a, const EF *b) {
  EF *ret = new EF;
  if (a->poly == b->poly && ZZ_is_equals(a->modulo, b->modulo)) {
    switch (a->poly) { // addition is same operation
    case IrreduciblePolynomialType::X2_1:
    case IrreduciblePolynomialType::X2_X_1:
      {
        auto t = ZZ_add(a->x, b->x);
        ret->x = ZZ_mod(t, a->modulo);
        ZZ_destroy(t);
      }
      {
        auto t = ZZ_add(a->y, b->y);
        ret->y = ZZ_mod(t, a->modulo);
        ZZ_destroy(t);
      }
    }
    ret->modulo = ZZ_copy(a->modulo);
    ret->poly = a->poly;
  } else {
    ret->x = ZZ_create_from_mpz_class(-1);
    ret->y = ZZ_create_from_mpz_class(-1);
    ret->modulo = ZZ_create_from_mpz_class(-1);
    ret->poly = IrreduciblePolynomialType::X2_1;
  }
  return ret;
}

__EXPORT__ bool EF_is_equals(const EF *a, const EF *b) {
  return (a->poly == b->poly) &&
    ZZ_is_equals(a->modulo, b->modulo) &&
    ZZ_is_equals(a->x, b->x) &&
    ZZ_is_equals(a->y, b->y);
}

__EXPORT__ bool EF_to_string(const EF *ef, char *p, int maxlen) {
  auto c = EF_to_string_as_std_string(ef);
  if (c.size() < maxlen) {
    strcpy(p, c.c_str());
    return true;
  }
  return false;
}

string EF_to_string_as_std_string(const EF *ef) {
  stringstream ss;
  ss << "(" << ZZ_to_string_as_std_string(ef->x)
     << ", " << ZZ_to_string_as_std_string(ef->y)
     << ") over Extended Field GF("
     << ZZ_to_string_as_std_string(ef->modulo)
     << "^2), Irreducible Polynomial: ";
  switch (ef->poly) {
  case IrreduciblePolynomialType::X2_1:
    ss << "x^2 + 1";
    break;
  case IrreduciblePolynomialType::X2_X_1:
    ss << "x^2 + x + 1";
    break;
  }
  return ss.str();
}
