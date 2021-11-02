#pragma once
#include <string>
#include <vector>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>

//https://blog.csdn.net/u011029517/article/details/79392522

namespace YEncrypt {
	//PKCS1_PADDING PKCS1填充
	static int PKCS1_PADDING = RSA_PKCS1_PADDING;

	//1024最大加密长度
	static int rsa_block = 1024 / 8 - 11;

	std::string Sha256(std::string buff);

	std::string private_sign_sha256(unsigned char* key, std::string sha256);

	bool public_verifysign_sha256(unsigned char* key, std::string sign, std::string sha256);

	RSA* CreateRsa(unsigned char* key, bool isbublickey);

	void printLastError(const char* msg);

	int public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted);

	int private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted);

	int private_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted);

	int public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted);

	std::string base64Encode(const char* buffer, int length, bool newLine);

	std::string base64Decode(char* input, int length, bool newLine);

#define PLAINBUFFLEN 0x1000

	std::string RsaLongEncrypt(std::string rawbody, unsigned char* key, int block_len, bool isbublickey);

	std::string RsaLongDecrypt(std::string rawbody, unsigned char* key, int block_len, bool isbublickey);

	std::string Md5(std::string buff);
}
