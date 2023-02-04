from __future__ import annotations
import os
from typing import Type, List, Any, Tuple

from util import basename, splitext

class TestsGenerator:
    
    registered_generators = []
    
    _compilers = {
        'arm': 'arm-linux-gnueabihf-gcc',
        'mips': 'mipsel-linux-gnu-gcc'
    }
    
    def __init__(self, tests_dir, src_dir, bin_dir, num_sinks):
        self.tests_dir = tests_dir
        self.src_dir = src_dir
        self.bin_dir = bin_dir
        self.num_sinks = num_sinks
        self.addtional_options = ''
        
        self._generate()
       
    def _generate(self):
        src_files, correct_results = self._generate_test_cases()
        bin_files = self._generate_bin_files(src_files)
        self._generate_py_files(bin_files, correct_results)
        
    def _generate_test_cases(self) -> Tuple[List[str], List[List[Any]]]:
        raise NotImplementedError('_generate_test_cases() is not implemented.')
    
    def _generate_bin_files(self, src_files: List[str]) -> List[str]:
        bin_files = []
        for src_file in src_files:
            bin_file = os.path.join(self.bin_dir, splitext(basename(src_file))[0])
            bin_files.append(bin_file)
            for arch, compiler in self._compilers.items():
                os.system(f'{compiler} {self.addtional_options} {src_file} -o {bin_file}_{arch}')
        return bin_files
    
    def _generate_py_files(self, bin_files: List[str], correct_results: List[Any]):
        for bin_file, correct_result in zip(bin_files, correct_results):
            bin_name = basename(bin_file)
            with open(f'{self.tests_dir}/test_{bin_name}.py', 'w') as fd:
                fd.write('from .common import run_backward_slicing_on_binary\n\n')
                for arch in self._compilers:
                    fd.write(f'def test_{basename(bin_name)}_{arch}():\n'
                             f'\tassert run_backward_slicing_on_binary(\'binaries/{bin_name}_{arch}\')' 
                             f' == {correct_result}\n\n')
    
    @staticmethod
    def register_generator(generator: Type[TestsGenerator]):
        TestsGenerator.registered_generators.append(generator)