#pragma once
#include <array>
#include <string>
#include <random>
#include <vector>
#include <sstream>
#include <numeric>
#include <iostream>
#include <stdexcept>
#include <algorithm>

#include <gmp.h>
#include <gmpxx.h>

#define __EXPORT__ extern "C"

struct FF_elem;

struct FF {
  mpz_class p;

  FF() = default;
  ~FF() = default;
  FF(const mpz_class& p) : p(p) {}
  FF(const FF& t) : p(t.p) {}
  FF(FF&& t) : p(std::move(t.p)) {};

  FF& operator=(const FF&);
  FF& operator=(FF&&);

  // common functions
  FF *clone(void) const;
  std::string to_string(void) const;

  // structure class member functions
  void add(FF_elem&, const FF_elem&, const FF_elem&) const;
  void sub(FF_elem&, const FF_elem&, const FF_elem&) const;
  void mul(FF_elem&, const FF_elem&, const FF_elem&) const;
  void div(FF_elem&, const FF_elem&, const FF_elem&) const;
  void pow(FF_elem&, const FF_elem&, const FF_elem&) const;
};

struct FF_elem {
  mpz_class v;

  FF_elem() = default;
  ~FF_elem() = default;
  FF_elem(const mpz_class& v) : v(v) {};
  FF_elem(mpz_class&& v) : v(std::move(v)) {};
  FF_elem(const FF_elem& t) : v(t.v) {};
  FF_elem(FF_elem&& t) : v(std::move(t.v)) {};

  FF_elem& operator=(const FF_elem&);
  FF_elem& operator=(FF_elem&&);

  // common functions
  FF_elem *clone(void) const;
  std::string to_string(void) const;
};

// FF
__EXPORT__ {
  // create FF instance
  FF *FF_create(const char *p);
  // delete FF instance
  void FF_delete(const FF*);
  // ret = a + b
  void FF_add(FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a - b
  void FF_sub(FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a * b
  void FF_mul(FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a / b
  void FF_div(FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // ret = a ^ b
  void FF_pow(FF *obj, FF_elem *ret, const FF_elem *a, const FF_elem *b);
  // to python __str__ function
  void FF_to_string(FF *obj, char *ptr, int len);
};

// FF_elem
__EXPORT__ {
  // create FF_elem instance
  FF_elem *FF_elem_create(const char *v);
  // delete FF_elem instance
  void FF_elem_delete(const FF_elem*);
  // to python __str__ function
  void FF_elem_to_string(FF_elem *obj, char *ptr, int len);
};


template <class T>
void write_to_python_string(const T *x, char *ptr, int len) {
  std::stringstream ss;
  ss << x->to_string();
  std::string r = ss.str();
  if (r.size() < len) {
    strcpy(ptr, r.c_str());
  }
}
