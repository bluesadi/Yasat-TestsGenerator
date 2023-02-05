import random
import os
from os.path import basename, splitext

root_dir = os.path.dirname(__file__)

def rand32():
    return random.randint(0, 0xFFFFFFFF)

def mkdirs(dir):
    return os.makedirs(dir, exist_ok=True)