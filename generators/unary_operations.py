from ctypes import *
import os

from generators.tests_generator import TestsGenerator, TestCase, TestFunction
from util import rand32


def not32(a):
    return c_uint32(~a).value


def neg32(a):
    return c_uint32(-a).value


unary_ops = [
    (not32, "~", "int32_t"),
    (neg32, "-", "int32_t"),
]


class UnaryOperationsTestsGenerator(TestsGenerator):
    def _generate_test_cases(self):
        test_cases = []
        for func, op_name, var_type in unary_ops:
            func_name = func.__name__
            test_case = (
                TestCase(f"{func_name}.c")
                .add_includes("stdint.h")
                .add_function(TestFunction("sink", args=[f"{var_type} a"]))
                .add_function(TestFunction(func_name, args=[f"{var_type} a"], return_type=var_type)
                              .create_line(f"return {op_name}a;"))
            )
            for _ in range(self.num_sinks):
                a = rand32()
                test_case.expected_results.append(func(a))
                test_case.main.create_call("sink", args=[f"{func_name}({a})"])
            test_cases.append(test_case)
        return test_cases


TestsGenerator.register_generator("unary_operations", UnaryOperationsTestsGenerator)
