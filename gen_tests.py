#!/usr/bin/env python3
import shutil
import os
import argparse

from generators.tests_generator import TestsGenerator
from util import mkdirs

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
    root_dir = os.path.dirname(__file__)
    src_dir = os.path.join(root_dir, 'tests_src')
    bin_dir = os.path.join(tests_dir, 'binaries')
    num_sinks = args.number
    
    for dir in [tests_dir, src_dir, bin_dir]:
        mkdirs(dir)
    
    shutil.copyfile(f'{root_dir}/templates/common.py', f'{tests_dir}/common.py')
    
    for generator in TestsGenerator.registered_generators:
        generator(tests_dir, src_dir, bin_dir, num_sinks)