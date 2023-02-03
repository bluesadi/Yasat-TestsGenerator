#!/usr/bin/env python3
import sys
import shutil
import os
import random
import argparse

from binary_operations import *

compilers = {
    'arm': 'arm-linux-gnueabihf-gcc',
    'mips': 'mipsel-linux-gnu-gcc'
}

def rand32():
    return random.randint(0, 0xFFFFFFFF)

def mkdirs(name):
    os.makedirs(name, exist_ok=True)

def gen_tests_for_binary_operations(tests_dir, n):
    mkdirs(f'{tests_dir}/binaries_src')
    mkdirs(f'{tests_dir}/binaries')
    shutil.copyfile(f'{os.path.dirname(__file__)}/templates/common.py', f'{tests_dir}/common.py')
    
    for func, op_name, var_type in bin_ops:
        correct_results = []
        func_name = func.__name__
        with open(f'{tests_dir}/binaries_src/{func_name}.c', 'w') as fd:
                fd.write(f'#include <stdint.h>\n\n'
                         f'void sink({var_type} a){{ }}\n\n'
                         f'{var_type} {func_name}({var_type} a, {var_type} b){{\n\treturn a {op_name} b;\n}}\n\n'
                         'int main(){\n')
                for _ in range(n):
                    a = rand32()
                    b = rand32()
                    correct_results.append(func(a, b))
                    fd.write(f'\tsink({func_name}({a}, {b}));\n')
                fd.write('}')
            
        for arch, compiler in compilers.items():
            os.system(f'{compiler} {tests_dir}/binaries_src/{func_name}.c -o {tests_dir}/binaries/{func_name}_{arch}')    
            
        with open(f'{tests_dir}/test_{func_name}.py', 'w') as fd:
            fd.write('from .common import run_backward_slicing_on_binary\n\n'
                     f'def test_{func_name}():\n')
            for arch in compilers:
                fd.write(f'\tassert run_backward_slicing_on_binary(\'binaries/{func_name}_{arch}\')' 
                         f' == {correct_results}\n')
            fd.write('\n')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--tests-dir', 
                        help='Install generated tests into this directory',
                        default='tests')
    parser.add_argument('-n', '--number', 
                        help='The number of calls to sink function inserted in a single test',
                        default=100)
    args = parser.parse_args()
    tests_dir = args.tests_dir
    mkdirs(tests_dir)
    gen_tests_for_binary_operations(tests_dir, args.number)