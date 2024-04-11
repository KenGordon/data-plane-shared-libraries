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

// add test keys for non-SNP environment
static constexpr char kPemSeperator[] = "-----";
static constexpr char kPemEnd[] = "END ";
static constexpr char kPemToken[] = "PRIVATE ";
static constexpr char kPemKey[] = "KEY";
static constexpr char kPemBegin[] = "BEGIN ";
static std::string GetTestPemPublicWrapKey() {
  return R"(
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0L9FDBjydkdstv7OKqkw
dMiugRqlSHC9Lchfd7jh5uCzv602LhlBJQeEFYchvaEquISLQFoZxEkpGEbEb15v
N2dKwTCi0ioEGBidtFmuKiVZqf46Hbnw4OdinQHrlGO2PRsRE+DYPOy6xrZTKEnD
K+OnHDsZ0U2qNJ80IjbxcC83lQpaMx8Ij8AddGY9Msv0TMMgaVsrDaQYLC8tmJih
xVI2f5BHFbTy3pw4Sq9xp6se+S/ycOUF0M6RFArZcD9uR/NxJKFJJlGOKskgwLnT
lhPck4sGeLhHUydRdqw0+h8EDsTIUysNxMOYtZETaVuBS+ISMy8+WQgVPs12Ujr3
17kaHeZr8Lq0bwaFHruRBpNwqtUCBv57IBpe7hnEDDdvOvN/tPubf1dv3HxEt42T
qqfozS+a9+1hcI8hpNlEjh+qcy1BmhSOXvmRzlhauX4xv6OLCNkRxo6x2Q/1moDC
PgnaJJVIuESr07xnC8fk43i5qFzEXQO3hwNsjd7sqFBBTb6t5N6Nm37mMNTqsDky
niAeFG+1gK/UD+cMPfbUIDaCqpCDwrTX0gMqqUTDG6eNPmQaOa+slici3h9WLaNy
mEzfKqJMBggKib/+e4Eb/ENdvxeT1X2YXpZ3tjZE+bRoiDgN4FYqBzYtZ/ieRcsq
4fPqgZPbh+ivT2o7QutzWH0CAwEAAQ==
-----END PUBLIC KEY-----

)";
}
static constexpr char kWrappingKp[] = R"(
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
/Kg7pJF1e2hkk3vxtCSlu9HfZ4q17vg=
)";

static std::string GetTestPemPrivWrapKey() {
  std::string result = std::string(kPemSeperator) + kPemBegin + kPemToken +
                       kPemKey + kPemSeperator + "\n" + kWrappingKp +
                       kPemSeperator + kPemEnd + kPemToken + kPemKey +
                       kPemSeperator + "\n";
  return result;
}

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

  EvpPkeyWrapper(EVP_PKEY* pkey) : pkey_(pkey) {}

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
  static std::pair<std::shared_ptr<EvpPkeyWrapper>,
                   std::shared_ptr<EvpPkeyWrapper>>
  GenerateWrappingKey();

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
  static EVP_PKEY* GetPublicEvpPkey(std::string wrappingPemKey);

  /**
   * @brief Convert a private PEM wrapping key to pkey
   *
   * @param wrappingPemKey RSA PEM key used to wrap a key.
   */
  static EVP_PKEY* GetPrivateEvpPkey(std::string wrappingPemKey);

  /**
   * @brief Generate hex hash on wrapping key
   */
  static std::string CreateHexHashOnKey(EVP_PKEY* publicKey);

  /**
   * @brief Convert a PEM wrapping key to pkey
   *
   * @param wrappingPemKey RSA PEM key used to wrap a key.
   */
  static EVP_PKEY* PemToEvpPkey(std::string wrappingPemKey);

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
