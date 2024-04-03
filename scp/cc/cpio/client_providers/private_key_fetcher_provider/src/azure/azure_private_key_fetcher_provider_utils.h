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

#ifndef CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_UTILS_H_
#define CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "cpio/client_providers/private_key_fetcher_provider/src/private_key_fetcher_provider.h"

namespace google::scp::cpio::client_providers {

// Define properties of API calls
constexpr char kWrappedKid[] = "wrappedKid";
constexpr char kWrapped[] = "wrapped";
constexpr char kWrappingKey[] = "wrappingKey";
constexpr char kAttestation[] = "attestation";

// Define RAII memory allocation/deallocation classes
class RsaWrapper {
 public:
  RsaWrapper() : rsa_(RSA_new()) {}

  ~RsaWrapper() { RSA_free(rsa_); }

  RSA* get() { return rsa_; }

 private:
  RSA* rsa_;
};

class BnWrapper {
 public:
  BnWrapper() : bn_(BN_new()) {}

  ~BnWrapper() { BN_free(bn_); }

  BIGNUM* get() { return bn_; }

 private:
  BIGNUM* bn_;
};

class EvpPkeyWrapper {
 public:
  EvpPkeyWrapper() : pkey_(EVP_PKEY_new()) {}
  EvpPkeyWrapper(EVP_PKEY *pkey) : pkey_(pkey) {}

  ~EvpPkeyWrapper() { EVP_PKEY_free(pkey_); }

  EVP_PKEY* get() { return pkey_; }

 private:
  EVP_PKEY* pkey_;
};

class BIOWrapper {
 public:
  explicit BIOWrapper(BIO_METHOD* method) : bio_(BIO_new(method)) {}

  ~BIOWrapper() { BIO_free(bio_); }

  BIO* get() { return bio_; }

 private:
  BIO* bio_;
};

class EVPKeyCtxWrapper {
 public:
  explicit EVPKeyCtxWrapper(EVP_PKEY_CTX* ctx) : ctx_(ctx) {}

  ~EVPKeyCtxWrapper() {
    if (ctx_) {
      EVP_PKEY_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }

  EVP_PKEY_CTX* get() const { return ctx_; }

 private:
  EVP_PKEY_CTX* ctx_;
};


class AzurePrivateKeyFetchingClientUtils {
 public:
  /**
   * @brief Create a Http Request object to query private key vending endpoint.
   *
   * @param private_key_fetching_request request to query private key.
   * @param http_request returned http request.
   */
  static void CreateHttpRequest(
      const PrivateKeyFetchingRequest& private_key_fetching_request,
      core::HttpRequest& http_request);

  /**
   * @brief Generate a new wrapping key
   */
  static std::pair<std::shared_ptr<EvpPkeyWrapper>, std::shared_ptr<EvpPkeyWrapper>> GenerateWrappingKey();

  /**
   * @brief Convert a wrapping key in PEM
   *
   * @param wrappingKey RSA public key used to wrap a key.
   */
  static std::string EvpPkeyToPem(EVP_PKEY* wrappingKey);

  /**
   * @brief Convert a public PEM wrapping key to pkey
   *
   * @param wrappingPemKey RSA PEM key used to wrap a key.
   */
  static EVP_PKEY* GetPublicEvpPkey(
      std::string wrappingPemKey);
      
  /**
   * @brief Convert a private PEM wrapping key to pkey
   *
   * @param wrappingPemKey RSA PEM key used to wrap a key.
   */
  static EVP_PKEY* GetPrivateEvpPkey(
      std::string wrappingPemKey);

  /**
   * @brief Convert a PEM wrapping key to pkey
   *
   * @param wrappingPemKey RSA PEM key used to wrap a key.
   */
  static EVP_PKEY* PemToEvpPkey(
      std::string wrappingPemKey);

  /**
   * @brief Wrap a key using RSA OAEP
   *
   * @param wrappingKey RSA public key used to wrap a key.
   * @param key         Key in PEM format to wrap.
   */
  static std::vector<unsigned char> KeyWrap(EVP_PKEY* wrappingKey,
                                            const std::string& key);

  /**
   * @brief Unwrap a key using RSA OAEP
   *
   * @param wrappingKey RSA private key used to unwrap a key.
   * @param encrypted   Wrapped key to unwrap.
   */
  static std::string KeyUnwrap(EVP_PKEY* wrappingKey,
                               const std::vector<unsigned char>& encrypted);

 private:
  // Declare the isPrivate function as private
  static bool isPrivate(EVP_PKEY* pkey);
};
}  // namespace google::scp::cpio::client_providers

#endif  // CPIO_CLIENT_PROVIDERS_PRIVATE_KEY_FETCHER_PROVIDER_SRC_AZURE_AZURE_PRIVATE_KEY_FETCHER_PROVIDER_UTILS_H_
