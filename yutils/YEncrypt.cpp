#include "YEncrypt.h"
#include "YCppDefer.hpp"
#include <windows.h>

RSA* YEncrypt::CreateRsa(unsigned char* key, bool isbublickey)
{
	RSA* rsa = NULL;
	BIO* keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	if (isbublickey)
	{
		rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	}
	else
	{
		rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	}
	if (rsa == NULL)
	{
		printf("Failed to create RSA");
	}
	return rsa;
}

void  YEncrypt::printLastError(const char* msg)
{
	char* err = (char*)malloc(130);;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}

int  YEncrypt::public_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted)
{
	RSA* rsa = CreateRsa(key, 1);
	int result = RSA_public_encrypt(data_len, data, encrypted, rsa, PKCS1_PADDING);
	return result;
}

int  YEncrypt::private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
	RSA* rsa = CreateRsa(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, PKCS1_PADDING);
	return result;
}

int  YEncrypt::private_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted)
{
	RSA* rsa = CreateRsa(key, 0);
	int result = RSA_private_encrypt(data_len, data, encrypted, rsa, PKCS1_PADDING);
	return result;
}

int  YEncrypt::public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
	RSA* rsa = CreateRsa(key, 1);
	int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, PKCS1_PADDING);
	return result;
}

std::string YEncrypt::base64Encode(const char* buffer, int length, bool newLine)
{
	auto b64 = BIO_new(BIO_f_base64());
	if (!b64)
	{
		return "";
	}
	defer(BIO_free_all(b64));

	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	auto bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, buffer, length);
	BIO_flush(b64);

	BUF_MEM* bptr;
	BIO_get_mem_ptr(b64, &bptr);
	BIO_set_close(b64, BIO_NOCLOSE);

	std::string result(bptr->length, 0);
	memcpy((void*)result.data(), bptr->data, bptr->length);
	return result;
}

std::string YEncrypt::base64Decode(char* input, int length, bool newLine)
{
	std::string result;
	result.resize(length + 1, 0);

	auto b64 = BIO_new(BIO_f_base64());
	if (!b64)
	{
		return "";
	}
	defer(BIO_free_all(b64));

	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	auto bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	auto len = BIO_read(bmem, (void*)result.data(), length);
	result.resize(len);
	return result;
}

std::string  YEncrypt::RsaLongEncrypt(std::string rawbody, unsigned char* publicKey, int block_len)
{
	unsigned char* plainBuff = new unsigned char[PLAINBUFFLEN];
	defer(if (plainBuff) {
		delete[] plainBuff;
		plainBuff = nullptr;
	});

	std::vector <std::string > encplain;
	for (size_t i = 0; i < rawbody.length(); i += block_len)
	{
		ZeroMemory(plainBuff, PLAINBUFFLEN);
		auto plainText = rawbody.substr(i, block_len);

		int encrypted_length = public_encrypt((unsigned char*)plainText.data(), plainText.length(), publicKey, plainBuff);
		if (encrypted_length <= 0)
		{
			printLastError((char*)"public_encrypt failed ");
			return "";
		}
		encplain.push_back(base64Encode((const char*)plainBuff, encrypted_length, false));
	}
	std::string result;
	for (auto& item : encplain) {
		result += item + "$$";
	}
	return result.substr(0, result.length() - 2);
}

std::string  YEncrypt::RsaLongDecrypt(std::string rawbody, unsigned char* privateKey, int block_len)
{
	std::vector <std::string > encplain;

	while (true)
	{
		int lastindex = rawbody.find("$");
		if (lastindex == -1)
		{
			break;
		}

		encplain.push_back(rawbody.substr(0, lastindex));
		rawbody = rawbody.substr(lastindex + 2, rawbody.length());
	}
	if (rawbody != "")
	{
		encplain.push_back(rawbody);
	}

	std::string result;
	unsigned char* plainBuff = new unsigned char[PLAINBUFFLEN];
	defer(if (plainBuff) {
		delete[] plainBuff;
		plainBuff = nullptr;
	});
	for (auto& item : encplain) {
		ZeroMemory(plainBuff, PLAINBUFFLEN);
		auto plain = base64Decode((char*)item.data(), item.length(), false);
		if (private_decrypt((unsigned char*)plain.data(), plain.length(), privateKey, plainBuff) == -1)
		{
			printLastError("private_decrypt");
			return "";
		}

		result += (char*)plainBuff;
	}

	return result;
}