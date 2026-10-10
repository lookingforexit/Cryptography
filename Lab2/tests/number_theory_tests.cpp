#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>

import crypto.number_theory;
import std;

namespace {

using crypto::BigInt;
using crypto::NumberTheoryService;

TEST(GCDClassicEuclid, FindsCommonDivisor) {
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(48, 18), 6);
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(17, 13), 1);
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(144, 60), 12);
}

TEST(GCDClassicEuclid, HandlesZeroArguments) {
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(0, 17), 17);
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(17, 0), 17);
}

TEST(GCDClassicEuclid, ReturnsNonnegativeResultForNegativeArguments) {
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(-42, 30), 6);
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(42, -30), 6);
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(-42, -30), 6);
}

TEST(GCDClassicEuclid, HandlesLargeOperands) {
    const BigInt common{"123456789012345678901234567890"};
    EXPECT_EQ(NumberTheoryService::GCDClassicEuclid(common * 21, common * 15), common * 3);
}

TEST(GCDClassicEuclid, RejectsTwoZeroArguments) {
    EXPECT_THROW(NumberTheoryService::GCDClassicEuclid(0, 0), std::invalid_argument);
}

TEST(GCDBinaryEuclid, FindsCommonDivisor) {
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(48, 18), 6);
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(17, 13), 1);
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(144, 60), 12);
}

TEST(GCDBinaryEuclid, HandlesZeroArguments) {
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(0, 17), 17);
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(17, 0), 17);
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(0, -17), 17);
}

TEST(GCDBinaryEuclid, HandlesLargeCommonPowersOfTwo) {
    const BigInt common = BigInt{1} << 150;
    EXPECT_EQ(NumberTheoryService::GCDBinaryEuclid(common * 45, common * 75), common * 15);
}

TEST(GCDBinaryEuclid, RejectsTwoZeroArguments) {
    EXPECT_THROW(NumberTheoryService::GCDBinaryEuclid(0, 0), std::invalid_argument);
}

TEST(GCDExtendedEuclid, ReturnsGCDAndBezoutCoefficients) {
    const auto result = NumberTheoryService::GCDExtendedEuclid(240, 46);
    EXPECT_EQ(result.gcd, 2);
    EXPECT_EQ(240 * result.x + 46 * result.y, result.gcd);
}

TEST(GCDExtendedEuclid, HandlesZeroArguments) {
    const auto lhs_zero = NumberTheoryService::GCDExtendedEuclid(0, 17);
    EXPECT_EQ(lhs_zero.gcd, 17);
    EXPECT_EQ(lhs_zero.x * 0 + lhs_zero.y * 17, lhs_zero.gcd);

    const auto rhs_zero = NumberTheoryService::GCDExtendedEuclid(17, 0);
    EXPECT_EQ(rhs_zero.gcd, 17);
    EXPECT_EQ(rhs_zero.x * 17 + rhs_zero.y * 0, rhs_zero.gcd);
}

TEST(GCDExtendedEuclid, HandlesAllSignCombinations) {
    for (const auto& [lhs, rhs] : std::array<std::pair<int, int>, 4>{
             std::pair{30, 21}, std::pair{-30, 21},
             std::pair{30, -21}, std::pair{-30, -21}}) {
        const auto result = NumberTheoryService::GCDExtendedEuclid(lhs, rhs);
        EXPECT_EQ(result.gcd, 3);
        EXPECT_EQ(lhs * result.x + rhs * result.y, result.gcd);
    }
}

TEST(GCDExtendedEuclid, HandlesLargeOperands) {
    const BigInt lhs{"123456789012345678901234567890"};
    const BigInt rhs{"98765432109876543210987654321"};
    const auto result = NumberTheoryService::GCDExtendedEuclid(lhs, rhs);
    EXPECT_EQ(lhs * result.x + rhs * result.y, result.gcd);
    EXPECT_EQ(result.gcd, NumberTheoryService::GCDClassicEuclid(lhs, rhs));
}

TEST(GCDExtendedEuclid, RejectsTwoZeroArguments) {
    EXPECT_THROW(NumberTheoryService::GCDExtendedEuclid(0, 0), std::invalid_argument);
}

TEST(PowMod, ComputesKnownPowers) {
    EXPECT_EQ(NumberTheoryService::PowMod(2, 10, 1000), 24);
    EXPECT_EQ(NumberTheoryService::PowMod(3, 5, 7), 5);
    EXPECT_EQ(NumberTheoryService::PowMod(7, 0, 13), 1);
}

TEST(PowMod, ReturnsResidueForModulusOne) {
    EXPECT_EQ(NumberTheoryService::PowMod(0, 0, 1), 0);
    EXPECT_EQ(NumberTheoryService::PowMod(7, 12, 1), 0);
}

TEST(PowMod, NormalizesNegativeBase) {
    EXPECT_EQ(NumberTheoryService::PowMod(-2, 5, 13), 7);
    EXPECT_EQ(NumberTheoryService::PowMod(-17, 3, 5), 2);
}

TEST(PowMod, HandlesBaseLargerThanModulus) {
    EXPECT_EQ(NumberTheoryService::PowMod(1234, 3, 17), 14);
}

TEST(PowMod, HandlesLargeExponentAndModulus) {
    const BigInt exponent{"123456789012345678901234567890"};
    const BigInt modulus{"100000000000000000000000000003"};
    const BigInt result = NumberTheoryService::PowMod(7, exponent, modulus);
    EXPECT_GE(result, 0);
    EXPECT_LT(result, modulus);
}

TEST(PowMod, RejectsNegativeExponent) {
    EXPECT_THROW(NumberTheoryService::PowMod(2, -1, 7), std::invalid_argument);
}

TEST(PowMod, RejectsNonpositiveModulus) {
    EXPECT_THROW(NumberTheoryService::PowMod(2, 5, 0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::PowMod(2, 5, -7), std::invalid_argument);
}

TEST(LegendreSymbol, ReturnsZeroForZeroResidue) {
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(0, 7), 0);
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(14, 7), 0);
}

TEST(LegendreSymbol, ReturnsOneForQuadraticResidues) {
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(1, 7), 1);
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(2, 7), 1);
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(4, 7), 1);
}

TEST(LegendreSymbol, ReturnsMinusOneForNonresidues) {
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(3, 7), -1);
    EXPECT_EQ(NumberTheoryService::LegendreSymbol(-1, 7), -1);
}

TEST(LegendreSymbol, RejectsInvalidModuli) {
    EXPECT_THROW(NumberTheoryService::LegendreSymbol(1, 2), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::LegendreSymbol(2, 9), std::invalid_argument);
}

TEST(JacobiSymbol, ComputesKnownSymbols) {
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(2, 7), 1);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(3, 7), -1);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(5, 11), 1);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(2, 15), 1);
}

TEST(JacobiSymbol, HandlesNegativeAndLargeNumerators) {
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(-1, 7), -1);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(100, 7), 1);
}

TEST(JacobiSymbol, ReturnsZeroWhenArgumentsAreNotCoprime) {
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(6, 15), 0);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(0, 9), 0);
}

TEST(JacobiSymbol, UsesOneAsTheUnitDenominator) {
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(0, 1), 1);
    EXPECT_EQ(NumberTheoryService::JacobiSymbol(123, 1), 1);
}

TEST(JacobiSymbol, IsMultiplicativeInTheNumerator) {
    const auto lhs = NumberTheoryService::JacobiSymbol(2 * 3, 11);
    const auto rhs = NumberTheoryService::JacobiSymbol(2, 11) *
                     NumberTheoryService::JacobiSymbol(3, 11);
    EXPECT_EQ(lhs, rhs);
}

TEST(JacobiSymbol, RejectsNonpositiveOrEvenDenominator) {
    EXPECT_THROW(NumberTheoryService::JacobiSymbol(1, 0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::JacobiSymbol(1, -7), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::JacobiSymbol(1, 10), std::invalid_argument);
}

TEST(EulerFuncByDefinition, MatchesKnownValues) {
    const std::array<int, 16> expected{
        0, 1, 1, 2, 2, 4, 2, 6, 4, 6, 4, 10, 4, 12, 6, 8
    };
    for (int n = 1; n < static_cast<int>(expected.size()); ++n) {
        EXPECT_EQ(NumberTheoryService::EulerFuncByDefinition(n), expected[n]) << "n=" << n;
    }
}

TEST(EulerFuncByDefinition, RejectsNonpositiveInput) {
    EXPECT_THROW(NumberTheoryService::EulerFuncByDefinition(0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::EulerFuncByDefinition(-5), std::invalid_argument);
}

TEST(EulerFuncByFactorization, MatchesKnownValues) {
    const std::array<int, 16> expected{
        0, 1, 1, 2, 2, 4, 2, 6, 4, 6, 4, 10, 4, 12, 6, 8
    };
    for (int n = 1; n < static_cast<int>(expected.size()); ++n) {
        EXPECT_EQ(NumberTheoryService::EulerFuncByFactorization(n), expected[n]) << "n=" << n;
    }
}

TEST(EulerFuncByFactorization, HandlesPrimePowersAndLargePrime) {
    EXPECT_EQ(NumberTheoryService::EulerFuncByFactorization(BigInt{2} * 2 * 2 * 2 * 2), 16);
    EXPECT_EQ(NumberTheoryService::EulerFuncByFactorization(1'000'003), 1'000'002);
}

TEST(EulerFuncByFactorization, RejectsNonpositiveInput) {
    EXPECT_THROW(NumberTheoryService::EulerFuncByFactorization(0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::EulerFuncByFactorization(-5), std::invalid_argument);
}

TEST(EulerFuncByDFT, MatchesKnownValuesForSmallInputs) {
    const std::array<int, 13> expected{
        0, 1, 1, 2, 2, 4, 2, 6, 4, 6, 4, 10, 4
    };
    for (int n = 1; n < static_cast<int>(expected.size()); ++n) {
        EXPECT_EQ(NumberTheoryService::EulerFuncByDFT(n), expected[n]) << "n=" << n;
    }
}

TEST(EulerFuncByDFT, RejectsNonpositiveInput) {
    EXPECT_THROW(NumberTheoryService::EulerFuncByDFT(0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::EulerFuncByDFT(-5), std::invalid_argument);
}

TEST(CarmichaelFuncByFactorization, MatchesKnownValues) {
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(1), 1);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(7), 6);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(9), 6);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(15), 4);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(24), 2);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(45), 12);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(561), 80);
}

TEST(CarmichaelFuncByFactorization, HandlesPowersOfTwo) {
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(2), 1);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(4), 2);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(8), 2);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(16), 4);
    EXPECT_EQ(NumberTheoryService::CarmichaelFuncByFactorization(32), 8);
}

TEST(CarmichaelFuncByFactorization, RejectsNonpositiveInput) {
    EXPECT_THROW(NumberTheoryService::CarmichaelFuncByFactorization(0), std::invalid_argument);
    EXPECT_THROW(NumberTheoryService::CarmichaelFuncByFactorization(-5), std::invalid_argument);
}

} // namespace
