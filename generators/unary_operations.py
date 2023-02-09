from ctypes import *
import os

from generators.tests_generator import TestsGenerator
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
        src_files = []
        correct_results = []
        for func, op_name, var_type in unary_ops:
            correct_result = []
            func_name = func.__name__
            src_file = os.path.join(self.src_dir, f"{func_name}.c")
            src_files.append(src_file)
            with open(src_file, "w") as fd:
                fd.write(
                    f"#include <stdint.h>\n\n"
                    f"void sink({var_type} a){{ }}\n\n"
                    f"{var_type} {func_name}({var_type} a){{\n\treturn {op_name}a;\n}}\n\n"
                    "int main(){\n"
                )
                for _ in range(self.num_sinks):
                    a = rand32()
                    correct_result.append(func(a))
                    fd.write(f"\tsink({func_name}({a}));\n")
                fd.write("}")
            correct_results.append(correct_result)
        return src_files, correct_results


TestsGenerator.register_generator("unary_operations", UnaryOperationsTestsGenerator)
