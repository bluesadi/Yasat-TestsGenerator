from ctypes import *

def add32(a, b):
    return c_uint32(a + b).value

def sub32(a, b):
    return c_uint32(a - b).value

def mul32(a, b):
    return c_uint32(a * b).value

bin_ops = [
    (add32, '+', 'int32_t'),
    (sub32, '-', 'int32_t'),
    (mul32, '*', 'int32_t')
]