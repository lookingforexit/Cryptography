#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>

import crypto.number_theory;
import crypto.rsa;
import crypto.wiener;
import std;

namespace {

using BigInt = crypto::BigInt;
using PublicKey = crypto::RSAService::PublicKey;

void ExpectRecoveredKey(
    const PublicKey& public_key,
    const BigInt& expected_d,
    const BigInt& expected_phi
) {
    const auto result = crypto::WienerAttackService::Attack(public_key);

    ASSERT_TRUE(result.Success());
    ASSERT_TRUE(result.d.has_value());
    ASSERT_TRUE(result.phi.has_value());
    EXPECT_EQ(*result.d, expected_d);
    EXPECT_EQ(*result.phi, expected_phi);
    EXPECT_FALSE(result.convergents.empty());

    const BigInt e_times_d = public_key.e * *result.d;
    EXPECT_EQ(e_times_d % *result.phi, 1);
}

bool ContainsConvergent(
    const std::vector<crypto::ContinuedFractionConvergent>& convergents,
    const BigInt& numerator,
    const BigInt& denominator
) {
    for (const auto& convergent : convergents) {
        if (convergent.numerator == numerator &&
            convergent.denominator == denominator) {
            return true;
        }
    }
    return false;
}

TEST(WienerAttack, RecoversKeyWithFactors137And131) {
    // p = 137, q = 131, phi = 17680, d = 3, e = 11787.
    ExpectRecoveredKey({.n = 17947, .e = 11787}, 3, 17680);
}

TEST(WienerAttack, RecoversKeyWithFactors167And179) {
    // p = 167, q = 179, phi = 29548, d = 3, e = 19699.
    ExpectRecoveredKey({.n = 29893, .e = 19699}, 3, 29548);
}

TEST(WienerAttack, RecoversKeyWithFactors101And113) {
    // p = 101, q = 113, phi = 11200, d = 3, e = 7467.
    ExpectRecoveredKey({.n = 11413, .e = 7467}, 3, 11200);
}

TEST(WienerAttack, StoresConvergentsComputedForThePublicKey) {
    const PublicKey public_key{.n = 17947, .e = 11787};

    const auto result = crypto::WienerAttackService::Attack(public_key);

    ASSERT_TRUE(result.Success());
    // 2/3 is a convergent of e/n and is the k/d candidate that recovers d=3.
    EXPECT_TRUE(ContainsConvergent(result.convergents, 2, 3));
}

TEST(WienerAttack, ReturnsNoKeyForAKeyNotVulnerableToTheAttack) {
    // n = 61 * 53, e = 17. The corresponding private exponent is not small.
    const PublicKey public_key{.n = 3233, .e = 17};

    const auto result = crypto::WienerAttackService::Attack(public_key);

    EXPECT_FALSE(result.Success());
    EXPECT_FALSE(result.d.has_value());
    EXPECT_FALSE(result.phi.has_value());
    EXPECT_FALSE(result.convergents.empty());
}

TEST(WienerAttack, RejectsModulusZero) {
    EXPECT_THROW(
        crypto::WienerAttackService::Attack({.n = 0, .e = 3}),
        std::invalid_argument
    );
}

TEST(WienerAttack, RejectsModulusOne) {
    EXPECT_THROW(
        crypto::WienerAttackService::Attack({.n = 1, .e = 3}),
        std::invalid_argument
    );
}

TEST(WienerAttack, RejectsZeroPublicExponent) {
    EXPECT_THROW(
        crypto::WienerAttackService::Attack({.n = 55, .e = 0}),
        std::invalid_argument
    );
}

TEST(WienerAttack, RejectsNegativePublicExponent) {
    EXPECT_THROW(
        crypto::WienerAttackService::Attack({.n = 55, .e = -3}),
        std::invalid_argument
    );
}

TEST(WienerKeyGen, GeneratesKeyRecoverableByWienerAttack) {
    using RSA = crypto::RSAService;

    crypto::WienerKeyGen key_gen(
        RSA::ProbabilisticPrimalityTest::MillerRabinPrimalityTest,
        0.999999,
        64
    );

    const RSA::KeyPair keys = key_gen.GenerateKeys();
    const auto result = crypto::WienerAttackService::Attack(keys.public_key);

    ASSERT_TRUE(result.Success());
    ASSERT_TRUE(result.d.has_value());
    ASSERT_TRUE(result.phi.has_value());

    EXPECT_EQ(keys.public_key.n, keys.private_key.n);
    EXPECT_EQ(*result.d, keys.private_key.d);
    EXPECT_EQ((keys.public_key.e * keys.private_key.d) % *result.phi, 1);
}

} // namespace
