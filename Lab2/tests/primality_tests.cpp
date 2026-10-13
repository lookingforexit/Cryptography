#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>

import crypto.primality_tests;
import crypto.number_theory;
import std;

namespace {

constexpr double kHighConfidence = 0.999999;

template <typename TestType>
void ExpectSmallAndEvenCases(TestType& test) {
    EXPECT_FALSE(test.Test(-17, kHighConfidence));
    EXPECT_FALSE(test.Test(0, kHighConfidence));
    EXPECT_FALSE(test.Test(1, kHighConfidence));

    EXPECT_TRUE(test.Test(2, kHighConfidence));
    EXPECT_TRUE(test.Test(3, kHighConfidence));
    EXPECT_TRUE(test.Test(5, kHighConfidence));
    EXPECT_TRUE(test.Test(7, kHighConfidence));

    EXPECT_FALSE(test.Test(4, kHighConfidence));
    EXPECT_FALSE(test.Test(100, kHighConfidence));
}

template <typename TestType>
void ExpectPrimeCandidates(TestType& test) {
    EXPECT_TRUE(test.Test(11, kHighConfidence));
    EXPECT_TRUE(test.Test(97, kHighConfidence));
    EXPECT_TRUE(test.Test(1'000'003, kHighConfidence));
}

template <typename TestType>
void ExpectCompositeCandidates(TestType& test) {
    EXPECT_FALSE(test.Test(9, kHighConfidence));
    EXPECT_FALSE(test.Test(15, kHighConfidence));
    EXPECT_FALSE(test.Test(21, kHighConfidence));
    EXPECT_FALSE(test.Test(25, kHighConfidence));
    EXPECT_FALSE(test.Test(341, kHighConfidence)); // 11 * 31, a base-2 Fermat pseudoprime
}

template <typename TestType>
void ExpectProbabilityValidation(TestType& test) {
    EXPECT_NO_THROW(test.Test(97, 0.5));
    EXPECT_NO_THROW(test.Test(97, std::nextafter(1.0, 0.0)));

    EXPECT_THROW(test.Test(97, 0.49), std::invalid_argument);
    EXPECT_THROW(test.Test(97, 1.0), std::invalid_argument);
    EXPECT_THROW(test.Test(97, -0.1), std::invalid_argument);
}

TEST(FermatPrimalityTest, HandlesSmallAndEvenNumbers) {
    crypto::FermatPrimalityTest test;
    ExpectSmallAndEvenCases(test);
}

TEST(FermatPrimalityTest, AcceptsPrimeCandidates) {
    crypto::FermatPrimalityTest test;
    ExpectPrimeCandidates(test);
}

TEST(FermatPrimalityTest, RejectsCompositeCandidatesWithHighConfidence) {
    crypto::FermatPrimalityTest test;
    ExpectCompositeCandidates(test);
}

TEST(FermatPrimalityTest, ValidatesRequestedProbabilityRange) {
    crypto::FermatPrimalityTest test;
    ExpectProbabilityValidation(test);
}

TEST(SolovayStrassenPrimalityTest, HandlesSmallAndEvenNumbers) {
    crypto::SolovayStrassenPrimalityTest test;
    ExpectSmallAndEvenCases(test);
}

TEST(SolovayStrassenPrimalityTest, AcceptsPrimeCandidates) {
    crypto::SolovayStrassenPrimalityTest test;
    ExpectPrimeCandidates(test);
}

TEST(SolovayStrassenPrimalityTest, RejectsCompositeCandidatesWithHighConfidence) {
    crypto::SolovayStrassenPrimalityTest test;
    ExpectCompositeCandidates(test);
}

TEST(SolovayStrassenPrimalityTest, ValidatesRequestedProbabilityRange) {
    crypto::SolovayStrassenPrimalityTest test;
    ExpectProbabilityValidation(test);
}

TEST(MillerRabinPrimalityTest, HandlesSmallAndEvenNumbers) {
    crypto::MillerRabinPrimalityTest test;
    ExpectSmallAndEvenCases(test);
}

TEST(MillerRabinPrimalityTest, AcceptsPrimeCandidates) {
    crypto::MillerRabinPrimalityTest test;
    ExpectPrimeCandidates(test);
}

TEST(MillerRabinPrimalityTest, RejectsCompositeCandidatesWithHighConfidence) {
    crypto::MillerRabinPrimalityTest test;
    ExpectCompositeCandidates(test);
}

TEST(MillerRabinPrimalityTest, ValidatesRequestedProbabilityRange) {
    crypto::MillerRabinPrimalityTest test;
    ExpectProbabilityValidation(test);
}

TEST(ProbabilisticPrimalityTests, HandlesLargeCppIntPrimeCandidate) {
    // 2^127 - 1 is prime; this also exercises random-base generation and
    // modular arithmetic when the input is larger than built-in integers.
    const crypto::BigInt mersenne_prime = (crypto::BigInt{1} << 127) - 1;

    crypto::FermatPrimalityTest fermat;
    crypto::SolovayStrassenPrimalityTest solovay_strassen;
    crypto::MillerRabinPrimalityTest miller_rabin;

    EXPECT_TRUE(fermat.Test(mersenne_prime, kHighConfidence));
    EXPECT_TRUE(solovay_strassen.Test(mersenne_prime, kHighConfidence));
    EXPECT_TRUE(miller_rabin.Test(mersenne_prime, kHighConfidence));
}

} // namespace
