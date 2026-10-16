#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>

import crypto.number_theory;
import crypto.rsa;
import std;

namespace {

using RSA = crypto::RSAService;

constexpr auto kTestPrimality = RSA::ProbabilisticPrimalityTest::MillerRabinPrimalityTest;
constexpr double kTestProbability = 0.9;
constexpr std::size_t kPrimeCandidateBits = 256;

TEST(RSAService, EncryptsAndDecryptsWithGeneratedKeyPair) {
    RSA rsa(kTestPrimality, kTestProbability, kPrimeCandidateBits);
    const RSA::KeyPair keys = rsa.GenerateKeys();
    const crypto::BigInt message = 1234567;

    const crypto::BigInt ciphertext = RSA::Encrypt(message, keys.public_key);
    const crypto::BigInt decrypted = RSA::Decrypt(ciphertext, keys.private_key);

    EXPECT_EQ(decrypted, message);
    EXPECT_LT(ciphertext, keys.public_key.n);
}

TEST(RSAService, CanGenerateMoreThanOneKeyPair) {
    RSA rsa(kTestPrimality, kTestProbability, kPrimeCandidateBits);

    const RSA::KeyPair first = rsa.GenerateKeys();
    const RSA::KeyPair second = rsa.GenerateKeys();

    EXPECT_GT(first.public_key.n, 0);
    EXPECT_GT(second.public_key.n, 0);
    EXPECT_NE(first.public_key.n, second.public_key.n);
}

TEST(RSAService, RejectsPlaintextOutsideModulusRange) {
    const RSA::PublicKey key{.n = 55, .e = 65537};

    EXPECT_THROW(RSA::Encrypt(-1, key), std::invalid_argument);
    EXPECT_THROW(RSA::Encrypt(55, key), std::invalid_argument);
}

TEST(RSAService, RejectsCiphertextOutsideModulusRange) {
    const RSA::PrivateKey key{.n = 55, .d = 3};

    EXPECT_THROW(RSA::Decrypt(-1, key), std::invalid_argument);
    EXPECT_THROW(RSA::Decrypt(55, key), std::invalid_argument);
}

TEST(RSAService, RejectsInvalidKeys) {
    const RSA::PublicKey invalid_public_key{.n = 1, .e = 65537};
    const RSA::PublicKey unsupported_public_exponent{.n = 55, .e = 1};
    const RSA::PrivateKey invalid_private_key{.n = 1, .d = 3};

    EXPECT_THROW(RSA::Encrypt(2, invalid_public_key), std::invalid_argument);
    EXPECT_THROW(RSA::Encrypt(2, unsupported_public_exponent), std::invalid_argument);
    EXPECT_THROW(RSA::Decrypt(2, invalid_private_key), std::invalid_argument);
}

TEST(RSAService, RejectsInvalidKeyGenerationParameters) {
    EXPECT_THROW(RSA(kTestPrimality, 0.49, kPrimeCandidateBits), std::invalid_argument);
    EXPECT_THROW(RSA(kTestPrimality, 1.0, kPrimeCandidateBits), std::invalid_argument);
    EXPECT_THROW(RSA(kTestPrimality, kTestProbability, 1), std::invalid_argument);
}

} // namespace
