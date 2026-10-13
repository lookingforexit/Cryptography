module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

module crypto.primality_tests;

import std;
import crypto.number_theory;

namespace crypto {
    bool ProbabilisticPrimalityTest::Test(const BigInt &number, double min_probability) const {
        if (min_probability - 0.5 < -std::numeric_limits<double>::epsilon() ||
            min_probability - 1 >= 0) {
            throw std::invalid_argument("min_probability has to be in [0.5; 1)");
        }

        if (number < 2) {
            return false;
        }
        if (number == 2 || number == 3) {
            return true;
        }
        if ((number & 1) == 0) {
            return false;
        }

        const auto q = ErrorProbabilityPerRound();
        if (!std::isfinite(q) || q <= 0.0 || q >= 1.0) {
            throw std::logic_error("per-round probability error has to be in (0; 1)");
        }

        const auto rounds = static_cast<std::size_t>(std::ceil(std::log1p(-min_probability) / std::log(q)));
        std::mt19937_64 engine{std::random_device{}()};
        for (std::size_t round = 0; round < std::max(rounds, std::size_t{1}); ++round) {
            if (const BigInt base = RandomBase(number, engine); !TestOneRound(number, base)) {
                return false;
            }
        }

        return true;
    }

    BigInt ProbabilisticPrimalityTest::RandomBelow(const BigInt& upper_bound, std::mt19937_64& engine) {
        if (upper_bound <= 0) {
            throw std::invalid_argument("upper_bound has to be greater than zero");
        }

        std::size_t bit_count = 0;
        for (BigInt number = upper_bound - 1; number > 0; number >>= 1) {
            ++bit_count;
        }

        while (true) {
            BigInt number = 0;

            for (std::size_t bit = 0; bit < bit_count; ++bit) {
                if ((engine() & 1U) != 0) {
                    number |= BigInt{1} << bit;
                }
            }

            if (number < upper_bound) {
                return number;
            }
        }
    }

    BigInt ProbabilisticPrimalityTest::RandomBase(const BigInt &number, std::mt19937_64 &engine) {
        // 2, 3 cases checked manually in test, so next one possibly base is 5 (common case [2, number - 2])
        return 2 + RandomBelow(number - 3, engine);
    }

    bool FermatPrimalityTest::TestOneRound(const BigInt &number, const BigInt &base) const {
        // a^(n-1) = 1 mod n
        if (NumberTheoryService::GCDBinaryEuclid(number, base) != 1) {
            return false;
        }

        return NumberTheoryService::PowMod(base, number - 1, number) == 1;
    }

    double FermatPrimalityTest::ErrorProbabilityPerRound() const noexcept {
        // for many composite numbers it equals to 0.5, but if we have Carmichael number it approaches to 1
        return 0.5;
    }

    bool SolovayStrassenPrimalityTest::TestOneRound(const BigInt &number, const BigInt &base) const {
        // a^((n-1)/2) = (a/n) mod n
        if (NumberTheoryService::GCDBinaryEuclid(base, number) != 1) {
            return false;
        }

        const auto jacobi = NumberTheoryService::JacobiSymbol(base, number);
        const BigInt rhs = jacobi == 1 ? BigInt{1} : number - 1;
        const BigInt lhs = NumberTheoryService::PowMod(
            base,
            (number - 1) >> 1,
            number
        );

        return lhs == rhs;
    }

    double SolovayStrassenPrimalityTest::ErrorProbabilityPerRound() const noexcept {
        return 0.5;
    }

    bool MillerRabinPrimalityTest::TestOneRound(const BigInt &number, const BigInt &base) const {
        // n - 1 = d * 2^s
        // a^d = 1 mod n || r<s: a^(d * 2^r) = -1 mod n
        BigInt d = number - 1;
        std::size_t s = 0;
        while ((d & 1) == 0) {
            d >>= 1;
            ++s;
        }

        auto lhs = NumberTheoryService::PowMod(base, d, number);
        if (lhs == 1 || lhs == number - 1) {
            return true;
        }

        for (std::size_t r = 1; r < s; ++r) {
            lhs = lhs * lhs % number;

            if (lhs == number - 1) {
                return true;
            }

            if (lhs == 1) {
                return false;
            }
        }

        return false;
    }

    double MillerRabinPrimalityTest::ErrorProbabilityPerRound() const noexcept {
        return 0.25;
    }
}
