import math

def h2a(v):
    return [ int('0x%s' % str(v[i * 2:(i + 1) * 2]), 16) for i in range(int(math.ceil(len(v) / 2.0)))]

def a2h(a):
    return ''.join(['%02X' % a[i] for i in range(len(a))])
