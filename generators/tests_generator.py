from __future__ import annotations
import os
from typing import Type, List, Any, Tuple

from util import root_dir, basename, splitext, mkdirs


class TestFunction:
    def __init__(self, name, args=[], return_type="void"):
        self.name = name
        self.args = args
        self.return_type = return_type
        self.lines = []

    def create_line(self, line):
        self.lines.append(f"\t{line}\n")
        return self

    def create_call(self, func_name, args):
        args = [str(arg) for arg in args]
        call_line = f"{func_name}({', '.join(args)});"
        self.create_line(call_line)
        return self
    
    def apply(self, func):
        func(self)
        return self

    def __str__(self) -> str:
        args = [str(arg) for arg in self.args]
        return f"{self.return_type} {self.name}({', '.join(args)}){{\n" + f"".join(self.lines) + "}\n"


class TestCase:
    def __init__(self, src_name, sink_name="sink", sink_idx=0):
        self.src_name = src_name
        self.sink_name = sink_name
        self.sink_idx = sink_idx
        self.expected_results = []
        self._includes = []
        self._functions = []
        self.main = TestFunction("main", return_type="int")

    def add_includes(self, *includes):
        for include in includes:
            self._includes.append(f'#include "{include}"\n')
        return self

    def add_function(self, func):
        self._functions.append(func)
        return self

    def write(self, dir):
        self.add_function(self.main)
        src_file = os.path.join(dir, self.src_name)
        with open(src_file, "w") as fd:
            fd.writelines(self._includes)
            fd.write("\n")
            for function in self._functions:
                fd.write(str(function))
                fd.write("\n")


class TestsGenerator:
    registered_generators = {}

    _compilers = {"arm": "arm-linux-gnueabihf-gcc", "mips": "mipsel-linux-gnu-gcc"}

    def __init__(self, module_name, tests_dir, num_sinks):
        self._module_name = module_name
        self._tests_dir = tests_dir
        self._src_dir = f"{root_dir}/tests_src/{self._module_name}"
        self._bin_dir = f"{tests_dir}/binaries/{self._module_name}"

        mkdirs(self._src_dir)
        mkdirs(self._bin_dir)

        self.num_sinks = num_sinks
        self.compiler_options = ""

    def generate(self):
        test_cases = self._generate_test_cases()
        src_files = []
        expected_results = []
        sinks = []
        for test_case in test_cases:
            test_case.write(self._src_dir)
            src_files.append(os.path.join(self._src_dir, test_case.src_name))
            expected_results.append(test_case.expected_results)
            sinks.append((test_case.sink_name, test_case.sink_idx))
        bin_files = self._generate_bin_files(src_files)
        self._generate_py_files(bin_files, expected_results, sinks)

    def _generate_test_cases(self) -> List[TestCase]:
        """
        Generate a list of source files and their corresponding ground truth.
        """
        raise NotImplementedError("_generate_test_cases() is not implemented.")

    def _generate_bin_files(self, src_files: List[str]) -> List[str]:
        bin_files = []
        for src_file in src_files:
            bin_file = os.path.join(self._bin_dir, splitext(basename(src_file))[0])
            bin_files.append(bin_file)
            for arch, compiler in self._compilers.items():
                os.system(
                    f"{compiler} {src_file} -o {bin_file}_{arch} {self.compiler_options}"
                )
        return bin_files

    def _generate_py_files(self, bin_files: List[str], expected_results: List[Any], sinks: List[Tuple[str, int]]):
        with open(f"{self._tests_dir}/test_{self._module_name}.py", "w") as fd:
            fd.write("from .common import run_backward_slicing_on_binary\n\n")
            for bin_file, correct_result, (sink_name, sink_idx) in zip(bin_files, expected_results, sinks):
                bin_name = basename(bin_file)
                for arch in self._compilers:
                    fd.write(
                        f"def test_{bin_name}_{arch}():\n"
                        f"\tassert run_backward_slicing_on_binary('binaries/{self._module_name}/"
                        f"{bin_name}_{arch}', '{sink_name}', {sink_idx}, "
                        f"cast_to={type(correct_result[0]).__name__})"
                        f" == {correct_result}\n\n"
                    )

    @staticmethod
    def register_generator(module_name, generator: Type[TestsGenerator]):
        TestsGenerator.registered_generators[module_name] = generator
