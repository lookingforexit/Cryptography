module;

#include <boost/multiprecision/cpp_int.hpp>

export module crypto.number_theory;

import std;

export namespace crypto {
    using BigInt = boost::multiprecision::cpp_int;

    struct BezoutResult {
        BigInt gcd;
        BigInt x;
        BigInt y;
    };

    class NumberTheoryService final {
    public:
        NumberTheoryService() = delete;

        static std::int8_t LegendreSymbol(const BigInt& number, const BigInt& odd_prime);
        static std::int8_t JacobiSymbol(BigInt number, BigInt odd_positive);

        static BigInt GCDClassicEuclid(BigInt lhs, BigInt rhs);
        static BezoutResult GCDExtendedEuclid(const BigInt& lhs, const BigInt& rhs);
        static BigInt GCDBinaryEuclid(BigInt lhs, BigInt rhs);

        static BigInt PowMod(BigInt base, BigInt exp, const BigInt& mod);

        static BigInt EulerFuncByDefinition(const BigInt& number);
        static BigInt EulerFuncByFactorization(const BigInt& number);
        static BigInt EulerFuncByDFT(const BigInt& number);

        static BigInt CarmichaelFuncByFactorization(const BigInt& number);
    };
}