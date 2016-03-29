from ..util import modinv, is_prime
from ..abstract.Field import Field, FieldElement
import FiniteField


class Zmod(Field):
  def __init__(s, n):
    if is_prime(n):
      Field.__init__(s, FiniteField.FiniteFieldElement)
    else:
      Field.__init__(s, ZmodElement)
    s.n = n

  def __repr__(s):
    return "%s(%s)" % (s.__class__.__name__, s.n)

  def __str__(s, var="n"):
    return "%s : %s = %d" % (s.__class__.__name__, var, s.n)

  def order(s):
    return s.n - 1

  def _ord(s, a):
    a = a[0]
    i = 1
    while i <= s.order():
      if s.element_class(s, a)**i == 1:
        return i
      i += 1
    return 0

  def _add(s, a, b):
    return s.element_class(s, a[0] + b[0])

  def _mul(s, a, b):
    return s.element_class(s, a[0] * b[0])

  def _inv(s, a):
    return s.element_class(s, modinv(a[0], s.n ** s.degree()))

  def _neg(s, a):
    return s.element_class(s, s.n - a[0])

  def _equ(s, a, b):
    return a[0] == b[0]

  def _mod(s, a, b):
    return s.element_class(s, a[0] % b[0])


class ZmodElement(FieldElement):
  def __init__(s, field, x):
    s.field = field
    if isinstance(x, s.__class__):
      s.x = x.x % (field.n)
    else:
      s.x = x % (field.n)

  def __repr__(s):
    return "%r(%s)" % (s.field, s.x)

  def __str__(s):
    return "%s" % s.x
