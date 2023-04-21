from typing import Tuple, List, Any

from generators.tests_generator import TestsGenerator, TestCase, TestFunction
from util import rand32, root_dir

class OpenSSLTestsGenerator(TestsGenerator):
    
    def __init__(self, module_name, tests_dir, num_sinks):
        super().__init__(module_name, tests_dir, num_sinks)
        self.compiler_options = f"-L{root_dir}/extra/lib/mips -L{root_dir}/extra/lib/arm -lcrypto -lssl -I{root_dir}/extra/include"
            
    def _generate_test_cases(self) -> List[TestCase]:
        test_cases = []
        test_case = (
            TestCase("EVP_BytesToKey.c", sink_name="EVP_BytesToKey", sink_idx=5)
            .add_includes("unistd.h", "common.h", "openssl/evp.h")
        )
        # EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 760, NULL, NULL);
        for _ in range(self.num_sinks):
            random_iterations = rand32() % 2000
            test_case.main.create_call("EVP_BytesToKey", args=("EVP_aes_128_cbc()", "EVP_sha256()", "rand_bytes(8)",
                                                               "(unsigned char *)rand_bytes(8)", 8, random_iterations, 
                                                               "NULL", "NULL"))
            test_case.expected_results.append(random_iterations)
        test_cases.append(test_case)
        test_case = (
            TestCase("RSA_generate_key.c", sink_name="RSA_generate_key", sink_idx=0)
            .add_includes("unistd.h", "common.h", "openssl/evp.h", "openssl/rsa.h")
        )
        for _ in range(self.num_sinks):
            rand_bits = rand32() % 2048
            if rand32() % 2 == 1:
                rand_bits += 2048
            test_case.main.create_call("RSA_generate_key", args=(rand_bits, 0, 0 , 0))
            test_case.expected_results.append(rand_bits)
        test_cases.append(test_case)
        return test_cases
    
TestsGenerator.register_generator("openssl", OpenSSLTestsGenerator)