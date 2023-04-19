from typing import Tuple, List, Any
import os

from generators.tests_generator import TestsGenerator, TestCase, TestFunction
from util import rand32, root_dir

class OpenSSLTestsGenerator(TestsGenerator):
    
    def __init__(self, module_name, tests_dir, num_sinks):
        super().__init__(module_name, tests_dir, num_sinks)
        self.compiler_options = f"-L{root_dir}/extra/lib/mips -L{root_dir}/extra/lib/arm -lcrypto -I{root_dir}/extra/include"
            
    def _generate_test_cases(self) -> List[TestCase]:
        test_cases = []
        test_case = (
            TestCase("EVP_BytesToKey.c", sink_name="EVP_BytesToKey", sink_idx=5)
            .add_includes("unistd.h", "common.h", "openssl/evp.h")
        )
        for _ in range(self.num_sinks):
            random_iterations = rand32() % 2000
            test_case.main.create_call("EVP_BytesToKey", args=["EVP_aes_128_cbc()", "EVP_sha256()", "rand_bytes(8)",
                                                               "(unsigned char *)rand_bytes(8)", 8, random_iterations, 
                                                               "NULL", "NULL"])
            test_case.expected_results.append(random_iterations)
        test_cases.append(test_case)
        return test_cases
    
TestsGenerator.register_generator("openssl", OpenSSLTestsGenerator)