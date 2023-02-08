#!/usr/bin/env python3
import shutil
import argparse

from generators.tests_generator import TestsGenerator
from util import root_dir, mkdirs

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--tests-dir', 
                        help='Install generated tests into this directory',
                        default='tests')
    parser.add_argument('-n', '--number', 
                        help='The number of calls to sink function inserted in a single test',
                        default=50)
    args = parser.parse_args()
    
    tests_dir = args.tests_dir
    num_sinks = int(args.number)
    
    mkdirs(tests_dir)
    
    for template in ['common.py', '__init__.py']: 
        shutil.copyfile(f'{root_dir}/templates/{template}', f'{tests_dir}/{template}')
    
    for module_name, generator in TestsGenerator.registered_generators.items():
        generator(module_name, tests_dir, num_sinks)