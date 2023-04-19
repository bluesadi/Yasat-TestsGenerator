from ctypes import *
import os

import claripy

from generators.tests_generator import TestsGenerator, TestFunction, TestCase
from util import rand32


def add32(a, b):
    return c_uint32(a + b).value


def sub32(a, b):
    return c_uint32(a - b).value


def mul32(a, b):
    return c_uint32(a * b).value


def shr32(a, b):
    return c_uint32(a >> b).value


def sar32(a, b):
    return c_uint32((claripy.BVV(a, 32) >> b)._model_concrete.value).value


def shl32(a, b):
    return c_uint32(a << b).value


def and32(a, b):
    return c_uint32(a & b).value


def or32(a, b):
    return c_uint32(a | b).value


def xor32(a, b):
    return c_uint32(a ^ b).value


def land32(a, b):
    return c_bool(a and b).value


def lor32(a, b):
    return c_bool(a or b).value


def eq32(a, b):
    return c_bool(a == b).value


def ne32(a, b):
    return c_bool(a != b).value


def le32(a, b):
    return c_bool(a <= b).value


def lt32(a, b):
    return c_bool(a < b).value


def ge32(a, b):
    return c_bool(a >= b).value


def gt32(a, b):
    return c_bool(a > b).value


bin_ops = [
    (add32, "+", "int32_t"),
    (sub32, "-", "int32_t"),
    (mul32, "*", "int32_t"),
    (shr32, ">>", "uint32_t"),
    (sar32, ">>", "int32_t"),
    (shl32, "<<", "int32_t"),
    (and32, "&", "int32_t"),
    (or32, "|", "int32_t"),
    (xor32, "^", "int32_t"),
    (land32, "&&", "int32_t"),
    (lor32, "||", "int32_t"),
    (eq32, "==", "int32_t"),
    (ne32, "!=", "int32_t"),
    (le32, "<=", "int32_t"),
    (lt32, "<", "int32_t"),
    (ge32, ">=", "int32_t"),
    (gt32, ">", "int32_t"),
]


class BinaryOperationsTestsGenerator(TestsGenerator):
    def _generate_test_cases(self):
        test_cases = []
        for func, op_name, var_type in bin_ops:
            func_name = func.__name__
            test_case = (
                TestCase(f"{func_name}.c")
                .add_includes("stdint.h")
                .add_function(TestFunction("sink", args=[f"{var_type} a"]))
                .add_function(TestFunction(func_name, args=[f"{var_type} a", f"{var_type} b"], return_type=var_type)
                              .create_line(f"return a {op_name} b;"))
            )
            for _ in range(self.num_sinks):
                a = rand32()
                b = rand32()
                if func in [sar32, shr32, shl32]:
                    b = b % 32
                elif func in [land32, lor32]:
                    if rand32() % 2:
                        b = 0
                elif func in [eq32, ne32]:
                    if rand32() % 2:
                        b = a
                test_case.expected_results.append(func(a, b))
                test_case.main.create_call("sink", args=[f"{func_name}({a}, {b})"])
            test_cases.append(test_case)
        return test_cases


TestsGenerator.register_generator("binary_operations", BinaryOperationsTestsGenerator)
