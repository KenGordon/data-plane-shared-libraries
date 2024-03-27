/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "azure_private_key_fetcher_provider_utils.h"

#include <memory>

#include "azure/attestation/src/attestation.h"

using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::Uri;

namespace google::scp::cpio::client_providers {

bool AzurePrivateKeyFetchingClientUtils::isPrivate(EVP_PKEY* pkey) {
  // Determine if the key is private or public
  int key_type = EVP_PKEY_type(pkey->type);
  bool is_private = false;
  if (key_type == EVP_PKEY_RSA) {
    const RSA* rsa_key = EVP_PKEY_get1_RSA(pkey);
    is_private =
        (rsa_key->e != NULL && rsa_key->n != NULL && rsa_key->d != NULL);
  }
  return is_private;
}

void
AzurePrivateKeyFetchingClientUtils::CreateHttpRequest(
    const PrivateKeyFetchingRequest& request, HttpRequest& http_request) {
  const auto& base_uri =
      request.key_vending_endpoint->private_key_vending_service_endpoint;
  http_request.method = HttpMethod::POST;

  http_request.path = std::make_shared<Uri>(base_uri);

  // Generate attestation report
  const auto report =
      hasSnp() ? fetchSnpAttestation() : fetchFakeSnpAttestation();
  CHECK(report.has_value()) << "Failed to get attestation report";

  nlohmann::json json_obj;
  json_obj["attestation"] = report.value();

  http_request.body = core::BytesBuffer(json_obj.dump());
}

/**
 * @brief Generate a new wrapping key
 */
std::pair<EVP_PKEY*, EVP_PKEY*>
AzurePrivateKeyFetchingClientUtils::GenerateWrappingKey() {
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();

  BN_set_word(e, RSA_F4);
  RSA_generate_key_ex(rsa, 4096, e, NULL);

  EVP_PKEY* private_key = EVP_PKEY_new();
  if (private_key == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("New EVP_PKEY failed: ") +
                             error_string);
  }

  if (EVP_PKEY_set1_RSA(private_key, rsa) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Set RSA key failed: ") +
                             error_string);
  }

  // Create a new EVP_PKEY for the public key
  EVP_PKEY* public_key = EVP_PKEY_new();
  if (public_key == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("New EVP_PKEY (public) failed: ") +
                             error_string);
  }

  // Get the RSA public key structure
  const RSA* rsa_pub = EVP_PKEY_get1_RSA(private_key);
  if (rsa_pub == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Get RSA public key failed: ") +
                             error_string);
  }

  // Duplicate the RSA public key structure
  RSA* rsa_pub_dup = RSA_new();
  if (rsa_pub_dup == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(
        std::string("Create RSA public key duplicate failed: ") + error_string);
  }

  if (!RSA_set0_key(rsa_pub_dup, rsa_pub->n, rsa_pub->e, NULL)) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(
        std::string("Set RSA public key duplicate values failed: ") +
        error_string);
  }

  RSA_up_ref(rsa_pub_dup);

  // Set the duplicated RSA public key structure to the public_key EVP_PKEY
  if (EVP_PKEY_set1_RSA(public_key, rsa_pub_dup) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Set RSA public key failed: ") +
                             error_string);
  }

  BN_free(e);
  RSA_free(rsa);  // Free the RSA structure if we're done with it

  return std::make_pair(private_key, public_key);
}

/**
 * @brief Convert a PEM wrapping key to pkey
 *
 * @param wrappingPemKey RSA PEM key used to wrap a key.
 */
EVP_PKEY* AzurePrivateKeyFetchingClientUtils::PemToEvpPkey(
    std::string wrappingPemKey) {
  BIO* bio = BIO_new_mem_buf(wrappingPemKey.c_str(), -1);
  if (bio == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Failed to create BIO: ") +
                             error_string);
  }

  EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  if (pkey == NULL) {
    BIO_reset(bio); 
    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  } 

  if (pkey == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    BIO_free(bio);
    throw std::runtime_error(std::string("Failed to read PEM: ") +
                             error_string);
  }
  BIO_free(bio);
  return pkey;
}

/**
 * @brief Convert a wrapping key to PEM
 *
 * @param wrappingKey RSA public key used to wrap a key.
 */
std::string AzurePrivateKeyFetchingClientUtils::EvpPkeyToPem(EVP_PKEY* pkey) {
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Failed to create BIO: ") +
                             error_string);
  }

  // Determine if the key is private or public
  bool is_private = isPrivate(pkey);

  // Write the key to the BIO as PEM
  int write_result;
  if (is_private) {
    write_result =
        PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
  } else {
    write_result = PEM_write_bio_PUBKEY(bio, pkey);
  }

  if (write_result != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    BIO_free(bio);
    throw std::runtime_error(std::string("Failed to write PEM: ") +
                             error_string);
  }

  // Get the PEM string from the BIO
  BUF_MEM* bio_mem;
  BIO_get_mem_ptr(bio, &bio_mem);
  std::string pem_str(bio_mem->data, bio_mem->length);

  BIO_free(bio);
  return pem_str;
}

/**
 * @brief Wrap a key using RSA OAEP
 *
 * @param wrappingKey RSA public key used to wrap a key.
 * @param key         Key  wrap.
 */
std::vector<unsigned char> AzurePrivateKeyFetchingClientUtils::KeyWrap(
    EVP_PKEY* wrappingKey, const std::string& data) {
  // Print out the wrapping key type and size
  int key_type = EVP_PKEY_base_id(wrappingKey);
  int key_size = EVP_PKEY_size(wrappingKey);
  std::cout << "Wrap key type: " << key_type << ", size: " << key_size
            << std::endl;

  bool is_private = isPrivate(wrappingKey);
  if (is_private) {
    throw std::runtime_error("Use public key for KeyWrap");
  }

  // Create an EVP_PKEY_CTX for the wrapping key
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(wrappingKey, NULL);
  if (ctx == NULL) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  // Initialize the context for encryption
  if (EVP_PKEY_encrypt_init(ctx) != 1) {
    throw std::runtime_error("Failed to initialize encryption context");
  }

  // Set the OAEP padding
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
    throw std::runtime_error("Failed to set OAEP padding");
  }

  // Set the OAEP parameters
  const EVP_MD* md = EVP_sha256();
  int md_size = EVP_MD_size(md);
  std::cout << "OAEP digest: " << md_size << " bytes" << std::endl;
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1) {
    unsigned long err_code = ERR_get_error();
    char err_str[120];
    ERR_error_string_n(err_code, err_str, sizeof(err_str));
    throw std::runtime_error("Failed to set OAEP digest: " +
                             std::string(err_str));
  }

  // Get the maximum encrypted data size
  size_t encrypted_len;
  if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(
        std::string("Failed to get maximum encrypted data size: ") +
        error_string);
  }

  // Allocate space for the encrypted data
  std::vector<unsigned char> encrypted(encrypted_len);

  // Encrypt the data
  if (EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_len,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Encryption failed: ") + error_string);
  }

  // Clean up the EVP_PKEY_CTX
  EVP_PKEY_CTX_free(ctx);

  // Resize the encrypted data vector
  encrypted.resize(encrypted_len);
  return encrypted;
}

/**
 * @brief Unwrap a key using RSA OAEP
 *
 * @param wrappingKey RSA private key used to unwrap a key.
 * @param encrypted   Wrapped key to unwrap.
 */
std::string AzurePrivateKeyFetchingClientUtils::KeyUnwrap(
    EVP_PKEY* wrappingKey, const std::vector<unsigned char>& encrypted) {
  // Print out the wrapping key type and size
  int key_type = EVP_PKEY_base_id(wrappingKey);
  int key_size = EVP_PKEY_size(wrappingKey);
  std::cout << "Unwrap key type: " << key_type << ", size: " << key_size
            << std::endl;

  bool is_private = isPrivate(wrappingKey);
  if (!is_private) {
    throw std::runtime_error("Use private key for KeyUnwrap");
  }

  // Create an EVP_PKEY_CTX for the wrapping key
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(wrappingKey, NULL);
  if (ctx == NULL) {
    throw std::runtime_error("Failed to create EVP_PKEY_CTX");
  }

  // Initialize the context for decryption
  if (EVP_PKEY_decrypt_init(ctx) != 1) {
    throw std::runtime_error("Failed to initialize decryption context");
  }

  // Set the OAEP padding
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) {
    throw std::runtime_error("Failed to set OAEP padding");
  }

  // Set the OAEP parameters
  const EVP_MD* md = EVP_sha256();
  int md_size = EVP_MD_size(md);
  std::cout << "OAEP digest: " << md_size << " bytes" << std::endl;
  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) != 1) {
    unsigned long err_code = ERR_get_error();
    char err_str[120];
    ERR_error_string_n(err_code, err_str, sizeof(err_str));
    throw std::runtime_error("Failed to set OAEP digest: " +
                             std::string(err_str));
  }

  // Get the maximum decrypted data size
  size_t decrypted_len;
  if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, encrypted.data(),
                       encrypted.size()) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(
        std::string("Failed to get maximum decrypted data size: ") +
        error_string);
  }

  // Allocate space for the decrypted data based on the maximum size
  std::vector<unsigned char> decrypted(decrypted_len);

  // Decrypt the data
  if (EVP_PKEY_decrypt(ctx, decrypted.data(), &decrypted_len, encrypted.data(),
                       encrypted.size()) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Decryption failed: ") + error_string);
  }

  // Clean up the EVP_PKEY_CTX
  EVP_PKEY_CTX_free(ctx);

  // Resize the decrypted data vector and convert to string
  decrypted.resize(decrypted_len);
  return std::string(decrypted.begin(), decrypted.end());
}

}  // namespace google::scp::cpio::client_providers
