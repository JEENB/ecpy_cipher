#pragma once
#include "field.h"

class FiniteField;

class FiniteFieldElement {
  private:
    FiniteField *f;
  public:
    mpz_class x;
    friend FiniteField;

    FiniteFieldElement() : f(nullptr), x(-1) {}
    FiniteFieldElement(FiniteFieldElement&& rhs) : f(std::move(rhs.f)), x(std::move(rhs.x)) {}
    FiniteFieldElement(const FiniteFieldElement& rhs) : f(rhs.f), x(rhs.x) {}
    ~FiniteFieldElement() = default;
    FiniteFieldElement(FiniteField *, mpz_class);

    template <class T>
    FiniteFieldElement operator+(const T& rhs) const;
    template <class T>
    FiniteFieldElement operator-(const T& rhs) const;
    template <class T>
    FiniteFieldElement operator*(const T& rhs) const;
    template <class T>
    FiniteFieldElement operator/(const T& rhs) const;
    template <class T>
    FiniteFieldElement operator^(const T& rhs) const;

    FiniteFieldElement& operator=(const FiniteFieldElement&& rhs);

    FiniteFieldElement operator-() const;

    mpz_class get_mpz_class() const;

    template <class T>
    bool operator==(const T& rhs) const;

    template <class T>
    friend FiniteFieldElement operator+(const T& lhs, const FiniteFieldElement& rhs);
    template <class T>
    friend FiniteFieldElement operator-(const T& lhs, const FiniteFieldElement& rhs);
    template <class T>
    friend FiniteFieldElement operator*(const T& lhs, const FiniteFieldElement& rhs);
    template <class T>
    friend FiniteFieldElement operator/(const T& lhs, const FiniteFieldElement& rhs);

    friend std::ostream& operator<<(std::ostream& os, const FiniteFieldElement& x);
};

class FiniteField : public Field<FiniteFieldElement> {
  public:
    const mpz_class p;

    FiniteField(const mpz_class&);

    template <class T>
    Element operator()(const T& x) {
      return Element(this, mpz_class(x));
    }

    friend std::ostream& operator<<(std::ostream& os, const FiniteField& field);

    template <class T, class U>
    static void add(Element& ret, FiniteField *f, const T& b, const U& c) {
      ret.f = f;
      ret.x = (to_mpz_cls(b) + to_mpz_cls(c)) % f->p;
    }

    template <class T, class U>
    static void sub(Element& ret, FiniteField *f, const T& b, const U& c) {
      ret.f = f;
      ret.x = (to_mpz_cls(b) + (f->p - to_mpz_cls(c))) % f->p;
    }

    template <class T, class U>
    static void mul(Element& ret, FiniteField *f, const T& b, const U& c) {
      ret.f = f;
      ret.x = (to_mpz_cls(b) * to_mpz_cls(c)) % f->p;
    }

    template <class T, class U>
    static void div(Element& ret, FiniteField *f, const T& b, const U& c) {
      mpz_class t;
      ret.f = f;
      mpz_invert(MPZ_T(t), MPZ_T(to_mpz_cls(c)), MPZ_T(f->p));
      ret.x = (t * to_mpz_cls(b)) % f->p;
    }
};

template <class T>
FiniteFieldElement operator+(const T& lhs, const FiniteFieldElement& rhs) {
  auto r = FiniteFieldElement();
  FiniteField::add(r, rhs.f, lhs, rhs);
  return r;
}

template <class T>
FiniteFieldElement operator-(const T& lhs, const FiniteFieldElement& rhs) {
  auto r = FiniteFieldElement();
  FiniteField::sub(r, rhs.f, lhs, rhs);
  return r;
}

template <class T>
FiniteFieldElement operator*(const T& lhs, const FiniteFieldElement& rhs) {
  auto r = FiniteFieldElement();
  FiniteField::mul(r, rhs.f, lhs, rhs);
  return r;
}

template <class T>
FiniteFieldElement operator/(const T& lhs, const FiniteFieldElement& rhs) {
  auto r = FiniteFieldElement();
  FiniteField::div(r, rhs.f, lhs, rhs);
  return r;
}

template <class T>
FiniteFieldElement FiniteFieldElement::operator+(const T& rhs) const {
  auto r = FiniteFieldElement();
  FiniteField::add(r, f, static_cast<const FiniteFieldElement&>(*this), rhs);
  return r;
}

template <class T>
FiniteFieldElement FiniteFieldElement::operator-(const T& rhs) const {
  auto r = FiniteFieldElement();
  FiniteField::sub(r, f, static_cast<const FiniteFieldElement&>(*this), rhs);
  return r;
}

template <class T>
FiniteFieldElement FiniteFieldElement::operator*(const T& rhs) const {
  auto r = FiniteFieldElement();
  FiniteField::mul(r, f, static_cast<const FiniteFieldElement&>(*this), rhs);
  return r;
}

template <class T>
FiniteFieldElement FiniteFieldElement::operator/(const T& rhs) const {
  auto r = FiniteFieldElement();
  FiniteField::div(r, f, static_cast<const FiniteFieldElement&>(*this), rhs);
  return r;
}

template <class T>
FiniteFieldElement FiniteFieldElement::operator^(const T& rhs) const {
  FiniteFieldElement res(f, 0);
  mpz_powm(MPZ_T(res.x), MPZ_T(x), MPZ_T(to_mpz_cls(rhs)), MPZ_T(f->p));
  return res;
}

template <class T>
bool FiniteFieldElement::operator==(const T& rhs) const {
  return to_mpz_cls(rhs) == x;
}

template <>
inline mpz_class to_mpz_cls<FiniteFieldElement>(const FiniteFieldElement& t) {
  return t.x;
}
