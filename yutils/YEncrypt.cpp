#include "YEncrypt.h"
#include "YCppDefer.hpp"
#include <windows.h>

std::vector<unsigned char> YEncrypt::Sha256(std::string buff)
{
	std::vector<unsigned char> ptr(SHA256_DIGEST_LENGTH, 0);
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buff.data(), buff.length());
	SHA256_Final(ptr.data(), &ctx);

	return ptr;
}

std::string YEncrypt::private_sign_sha256(unsigned char* key, std::vector<unsigned char> sha256)
{
	RSA* rsa = CreateRsa(key, 0);
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});

	unsigned char* plainBuff = new unsigned char[PLAINBUFFLEN] {0};
	defer(if (plainBuff) {
		delete[] plainBuff;
		plainBuff = nullptr;
	});
	unsigned int sign_length = 0;

	auto sign_res = RSA_sign(NID_sha256, sha256.data(), sha256.size(), plainBuff, &sign_length, rsa);
	if (sign_res == -1)
	{
		printLastError("private_decrypt");
		return "";
	}

	return base64Encode((const char*)plainBuff, sign_length);
}

bool YEncrypt::public_verifysign_sha256(unsigned char* key, std::string data, std::string sign)
{
	RSA* rsa = CreateRsa(key, 1);
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});
	auto udata = Sha256(base64Decode(data.data(), data.length()));
	sign = base64Decode((char*)sign.data(), sign.length());
	int ret = RSA_verify(NID_sha256, udata.data(), udata.size(), (const unsigned char*)sign.data(), sign.length(), rsa);
	if (ret != 1) {
		printLastError("public_verifysign_sha256");
		return false;
	}
	return true;
}

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
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});
	return RSA_public_encrypt(data_len, data, encrypted, rsa, PKCS1_PADDING);
}

int  YEncrypt::private_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
	RSA* rsa = CreateRsa(key, 0);
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});
	return RSA_private_decrypt(data_len, enc_data, decrypted, rsa, PKCS1_PADDING);
}

int  YEncrypt::private_encrypt(unsigned char* data, int data_len, unsigned char* key, unsigned char* encrypted)
{
	RSA* rsa = CreateRsa(key, 0);
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});
	return RSA_private_encrypt(data_len, data, encrypted, rsa, PKCS1_PADDING);
}

int  YEncrypt::public_decrypt(unsigned char* enc_data, int data_len, unsigned char* key, unsigned char* decrypted)
{
	RSA* rsa = CreateRsa(key, 1);
	defer(if (rsa) {
		RSA_free(rsa);	rsa = nullptr;
	});
	return  RSA_public_decrypt(data_len, enc_data, decrypted, rsa, PKCS1_PADDING);
}

std::string YEncrypt::base64Encode(const char* buffer, int length)
{
	auto b64 = BIO_new(BIO_f_base64());
	if (!b64)
	{
		return "";
	}
	defer(BIO_free_all(b64));

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	auto bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, buffer, length);
	BIO_flush(b64);

	BUF_MEM* bptr;
	BIO_get_mem_ptr(b64, &bptr);
	BIO_set_close(b64, BIO_NOCLOSE);

	std::string result(bptr->length + 1, 0);
	memcpy((void*)result.data(), bptr->data, bptr->length);
	return result;
}

std::string YEncrypt::base64Decode(char* input, int length)
{
	std::string result;
	result.resize(length + 1, 0);

	auto b64 = BIO_new(BIO_f_base64());
	if (!b64)
	{
		return "";
	}
	defer(BIO_free_all(b64));

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	auto bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	auto len = BIO_read(bmem, (void*)result.data(), length);
	result.resize(len);
	return result;
}

std::string  YEncrypt::RsaLongEncrypt(std::string rawbody, unsigned char* key, int block_len, bool isbublickey)
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

		int encrypted_length = -1;
		if (isbublickey)
		{
			encrypted_length = public_encrypt((unsigned char*)plainText.data(), plainText.length(), key, plainBuff);
		}
		else {
			encrypted_length = private_encrypt((unsigned char*)plainText.data(), plainText.length(), key, plainBuff);
		}

		if (encrypted_length <= 0)
		{
			printLastError((char*)"public_encrypt failed ");
			return "";
		}
		encplain.push_back(base64Encode((const char*)plainBuff, encrypted_length));
	}
	std::string result;
	for (auto& item : encplain) {
		result += item + ".";
	}
	return result.substr(0, result.length() - 1);
}

std::string  YEncrypt::RsaLongDecrypt(std::string rawbody, unsigned char* key, int block_len, bool isbublickey)
{
	std::vector <std::string > encplain;

	while (true)
	{
		int lastindex = rawbody.find(".");
		if (lastindex == -1)
		{
			break;
		}

		encplain.push_back(rawbody.substr(0, lastindex));
		rawbody = rawbody.substr(lastindex + 1, rawbody.length());
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
		auto plain = base64Decode((char*)item.data(), item.length());
		int decrypt_length = -1;
		if (isbublickey) {
			decrypt_length = public_decrypt((unsigned char*)plain.data(), plain.length(), key, plainBuff);
		}
		else {
			decrypt_length = private_decrypt((unsigned char*)plain.data(), plain.length(), key, plainBuff);
		}

		if (decrypt_length == -1)
		{
			printLastError("private_decrypt");
			return "";
		}

		result += (char*)plainBuff;
	}

	return result;
}

std::vector<unsigned char> YEncrypt::Md5(std::string buff)
{
	std::vector<unsigned char> ptr(MD5_DIGEST_LENGTH, 0);

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, buff.data(), buff.length());
	MD5_Final(ptr.data(), &ctx);

	return ptr;
}

std::string YEncrypt::ByteToString(std::vector<unsigned char> ptr)
{
	std::string result;
	for (size_t i = 0; i < ptr.size(); i++)
	{
		char tmp[4]{ 0 };
		sprintf_s(tmp, "%02X", ptr[i]);
		result += tmp;
	}
	return result;
}