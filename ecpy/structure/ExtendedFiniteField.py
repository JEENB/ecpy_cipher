from ..abstract.Field import Field, FieldElement
from .RationalField import QQ
from .FiniteField import FiniteField, FiniteFieldElement
from .Zmod import Zmod, ZmodElement
from ..util import is_prime, modinv
import math

class ExtendedFiniteField(FiniteField):
  def __init__(s, p, poly="x^2+1"):
    if poly == "x^2+1":
      assert p % 4 == 3
      s.t = 1
    elif poly == "x^2+x+1":
      assert p % 3 == 2 and (p+1)%6 == 0 and is_prime((p+1)/6)
      s.t = 2
    else:
      raise ValueError("Invalid Polynomial: %s" % poly)
    FiniteField.__init__(s, p)
    s.element_class = ExtendedFiniteFieldElement

  def __str__(s):
    if s.t == 1:
      return Zmod.__str__(s, "p^%d" % s.degree()) + " : Polynomial is i^2+1 = 0"
    elif s.t == 2:
      return Zmod.__str__(s, "p^%d" % s.degree()) + " : Polynomial is w^2+w+1 = 0"

  def __repr__(s):
    res = "%s(%s, " % (s.__class__.__name__, s.n)
    if s.t == 1:
      res += '"x^2+1"'
    elif s.t == 2:
      res += '"x^2+x+1"'
    res += ")"
    return res

  #@profile
  def _add(s, a, b):
    if s.t == 1 or s.t == 2:
      return s.element_class(s, a[0] + b[0], a[1] + b[1])

  def _neg(s, a):
    if s.t == 1 or s.t == 2:
      return s.element_class(s, s.p-a[0], s.p-a[1])

  #@profile
  def _mul(s, a, b):
    if s.t == 1:
      return s.element_class(s, a[0] * b[0] - a[1] * b[1], a[0]*b[1] + a[1] * b[0])
    elif s.t == 2:
      a, _b = a
      c, d = b
      b = _b
      return s.element_class(s, a*c - b*d, a*d + b*c - b*d)

  def _equ(s, a, b):
    if s.degree() == 2:
      if len(b) == 1:
        return a[0] == b[0] and a[1] == 0
      return a[0] == b[0] and a[1] == b[1]
    return x

  def _div(s, z, w):
    r = s._inv(w) * z
    return r

  def _inv(s, a):
    if len(a) == 1:
      return Zmod._inv(s, a)
    a, b = map(int, a)
    if s.t == 1:
      u = a*a + b*b
      u = modinv(u, s.n)
      return s.element_class(s, a * u, -b * u)
    elif s.t == 2:
      u = a*a-a*b+b*b
      u = modinv(u, s.n)
      return s.element_class(s, (a-b) * u, (-b) * u)

  def degree(s):
    if s.t == 1 or s.t == 2:
      return 2

class ExtendedFiniteFieldElement(FiniteFieldElement):
  #@profile
  def __init__(s, field, x, y=0):
    if isinstance(x, s.__class__):
      x, y = x.x, x.y
    s.field = field
    s.x = x % s.field.p
    s.y = y % s.field.p

  def __repr__(s):
    if s.field.t == 1 or s.field.t == 2:
      return "%r(%r, %r)" % (s.field, s.x, s.y)

  def __str__(s):
    res = None
    if s == 0:
      return "0"
    if s.field.t == 1:
      res = ""
      if s.x != 0:
        res += "%r" % s.x
      if s.y != 0:
        if s.x != 0:
          res += " + "
        if s.y != 1:
          res += "%r" % s.y
        res += "i"
    elif s.field.t == 2:
      res = ""
      if s.x != 0:
        res += "%r" % s.x
      if s.y != 0:
        if s.x != 0:
          res += " + "
        if s.y != 1:
          res += "%r" % s.y
        res += "w"
    return res

  def __iter__(s):
    if s.field.t == 1 or s.field.t == 2:
      return (s.x, s.y).__iter__()

  def _to_tuple(s, d):
    if isinstance(d, s.__class__):
      return tuple(d)
    elif isinstance(d, tuple):
      return d
    else:
      if s.field.t == 1 or s.field.t == 2:
        return (d, 0)

  def __hash__(s):
    return s.x * s.y * s.field.p
