from ..abstract.AdditiveGroup import AdditiveGroup, AdditiveGroupElement
from ..util import modinv,ModinvNotFoundError,legendre_symbol, gcd
from random import randint
from RealField import RR

class EllipticCurve(AdditiveGroup):
  def __init__(s, field, a, b):
    AdditiveGroup.__init__(s, EllipticCurvePoint)
    s.field = field
    s.a = a
    s.b = b
    s.O = s.element_class(s, 0, 1, 0)
    s.O.infinity = True

  def is_on_curve(s, point):
    return s._is_on_curve(point.x, point.y, point.z)

  def _is_on_curve(s, x, y, z=1):
    return s.field(y) ** 2 == s.field(x) ** 3 + s.field(s.a) * s.field(x) + s.field(s.b)

  def determinant(s):
    return -16*(4*s.a**3 + 27*s.b**2)

  def j_invariant(s):
    return -1728*((4*s.a**3) / s.determinant())

  def __repr__(s):
    return "EllipticCurve(%r, %r, %r)" % (s.field, s.a, s.b)

  def __str__(s):
    res = "Elliptic Curve y^2 = x^3"
    if s.a != 0:
      if s.a == 1:
        res += " + x"
      else:
        res += " + %rx" % s.a
    if s.b != 0:
      res += " + %r" % s.b
    res += " over %r" % s.field
    return res

  def _add(s, P, Q):
    Px, Py, Pz = map(int, P)
    Qx, Qy, Qz = map(int, Q)
    Rx, Ry, Rz = (0, 1, 0)
    try:
      if Px != Qx:
        u = Qy*Pz - Py*Qz
        v = Qx*Pz - Px*Qz
        w = u**2 * Pz * Qz - v**2 * (v + 2*Px*Qz)
        Rx = v*w
        Ry = u * (v**2 * Px * Qz - w) - v**3 * Py * Qz
        Rz = v**3 * Pz * Qz
      else:
        u = 3*Px**2 + s.a * Pz**2
        v = Py * Pz
        w = u**2 - 8*Px*Py*v
        Rx = 2*v*w
        Ry = u * (4 * Px * Py * v - w) - 8 * (Py * v) ** 2
        Rz = 8*v**3
      z = s.field._inv([Rz])
      Rx = Rx * z
      Ry = Ry * z
      Rz = Rz * z
      return s.element_class(s, int(Rx), int(Ry), int(Rz))
    except ModinvNotFoundError:
      return s.O

  def _equ(s, P, Q):
    return (P[0] == Q[0]) and (P[1] == Q[1]) and (P[2] == Q[2])

  def _neg(s, P):
    return s.element_class(s, P[0], -P[1])

  def random_point(s):
    while True:
      x = randint(0, s.field.order())
      y = randint(0, s.field.order())
      if s._is_on_curve(x, y):
        return s.element_class(s, x, y)

  def embedding_degree(s, m):
    k = 1
    while True:
      if (s.field.p ** k - 1) % m == 0:
        return k
      k += 1

class EllipticCurvePoint(AdditiveGroupElement):
  def __init__(s, group, x, y, z = 1):
    AdditiveGroupElement.__init__(s, group, x)
    s.y = y
    s.z = z
    s.infinity = (x, y, z) == (0, 1, 0)
    if not (s.infinity or s.group.is_on_curve(s)):
      raise ArithmeticError("Invalid Point: (%s, %s)" % (s.x, s.y))

  def is_infinity(s):
    return s.infinity

  def order(s):
    i = 1
    #while i <= s.order():
    while i <= s.group.field.order():
      if (s*i).is_infinity():
        return i
      i += 1
    return 0

  def change_group(s, _group):
    return s.__class__(_group, *tuple(s))

  def line_coeff(s, Q):
    P = s
    F = s.group.field
    x1, y1, z1 = map(F, tuple(P))
    x2, y2, z2 = map(F, tuple(Q))
    if x1 == x2:
      l = (3*x1**2 + s.group.a) / (2*y1)
    else:
      l = (y2*z1-y1*z2) / (x2*z1-x1*z2)
    return l

  def __add__(s, rhs):
    if isinstance(rhs, EllipticCurvePoint) and rhs.is_infinity():
        return s
    d = s._to_tuple(rhs)
    if s.is_infinity():
      return s.__class__(s.group, d[0], d[1])
    else:
      return s.group._add(tuple(s), d)

  def __sub__(s, rhs):
    return s.group._add(tuple(s), s._to_tuple(-rhs))

  def __mul__(s, rhs):
    if rhs == 0:
      return s.group.O
    d = int(rhs)
    bits = map(lambda x: x == "1", bin(d)[2:])[::-1]
    x = s
    if bits[0]:
      res = x
    else:
      res = s.group.O
    for cur in bits[1:]:
      x += x
      if cur:
        res += x
    return res

  def __neg__(s):
    return s.group._neg(tuple(s))

  def __radd__(s, lhs):
    return s + lhs

  def __rmul__(s, lhs):
    return s * lhs

  def __rsub__(s, lhs):
    return -s + lhs

  def __ne__(s, rhs):
    return not (s == rhs)

  def __eq__(s, rhs):
    if rhs == None:
      return False
    return s.group._equ(tuple(s), s._to_tuple(rhs))

  def _to_tuple(s, d):
    if isinstance(d, s.__class__):
      return tuple(d)
    elif isinstance(d, tuple):
      return d
    else:
      raise ArithmeticError("Invalid Parameter")

  def __iter__(s):
    return (s.x, s.y, s.z).__iter__()

  def __repr__(s):
    if s.infinity:
      return "%r.O" % s.group
    return "%r(%r, %r, %r)" % (s.group, s.x, s.y, s.z)

  def __str__(s):
    if s.infinity:
      return "Infinity Point (0 : 1 : 0) on %s" % s.group
    return "Point (%s : %s : %s) on %s" % (s.x, s.y, s.z, s.group)
