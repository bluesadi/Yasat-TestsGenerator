from ctypes import *
import os

import claripy

from generators.tests_generator import TestsGenerator
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
        src_files = []
        correct_results = []
        for func, op_name, var_type in bin_ops:
            correct_result = []
            func_name = func.__name__
            src_file = os.path.join(self.src_dir, f"{func_name}.c")
            src_files.append(src_file)
            with open(src_file, "w") as fd:
                fd.write(
                    f"#include <stdint.h>\n\n"
                    f"void sink({var_type} a){{ }}\n\n"
                    f"{var_type} {func_name}({var_type} a, {var_type} b){{\n\treturn a {op_name} b;\n}}\n\n"
                    "int main(){\n"
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
                    correct_result.append(func(a, b))
                    fd.write(f"\tsink({func_name}({a}, {b}));\n")
                fd.write("}")
            correct_results.append(correct_result)
        return src_files, correct_results


TestsGenerator.register_generator("binary_operations", BinaryOperationsTestsGenerator)
