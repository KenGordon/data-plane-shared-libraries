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

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "azure/attestation/src/attestation.h"

using google::scp::azure::attestation::fetchFakeSnpAttestation;
using google::scp::azure::attestation::fetchSnpAttestation;
using google::scp::azure::attestation::hasSnp;
using google::scp::core::HttpMethod;
using google::scp::core::HttpRequest;
using google::scp::core::Uri;

namespace google::scp::cpio::client_providers {

void AzurePrivateKeyFetchingClientUtils::CreateHttpRequest(
    const PrivateKeyFetchingRequest& request, HttpRequest& http_request) {
  const auto& base_uri =
      request.key_vending_endpoint->private_key_vending_service_endpoint;
  http_request.method = HttpMethod::POST;

  http_request.path = std::make_shared<Uri>(base_uri);

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
EVP_PKEY* AzurePrivateKeyFetchingClientUtils::GenerateWrappingKey() {
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();

  BN_set_word(e, RSA_F4);
  RSA_generate_key_ex(rsa, 2048, e, NULL);

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("New EVP_PKEY failed: ") +
                             error_string);
  }

  if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
    char* error_string = ERR_error_string(ERR_get_error(), NULL);
    throw std::runtime_error(std::string("Set RSA key failed: ") +
                             error_string);
  }

  BN_free(e);
  RSA_free(rsa);  // Free the RSA structure if we're done with it

  return pkey;
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
