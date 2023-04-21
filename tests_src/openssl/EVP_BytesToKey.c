#include "unistd.h"
#include "common.h"
#include "openssl/evp.h"

int main(){
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 954, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1050, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 120, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1686, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1102, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1835, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 719, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 61, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1123, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 105, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 820, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 727, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1882, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 777, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1408, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1738, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 807, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 162, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1683, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 336, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 1672, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 555, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 669, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 301, NULL, NULL);
	EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha256(), rand_bytes(8), (unsigned char *)rand_bytes(8), 8, 187, NULL, NULL);
}

