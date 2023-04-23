#include "unistd.h"
#include "common.h"
#include "openssl/evp.h"

int main(){
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1405, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 673, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 367, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1670, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1679, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1405, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 473, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 258, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 356, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1506, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1019, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 402, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1006, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 213, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1143, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 972, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1866, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1469, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1953, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 112, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 340, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1036, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1096, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 569, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 436, NULL, NULL);
}

