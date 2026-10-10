module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/math/constants/constants.hpp>

module crypto.number_theory;

import std;

namespace crypto {
    namespace {
        std::vector<std::pair<BigInt, std::size_t>> Factorization(BigInt number) {
            if (number < 1) {
                throw std::invalid_argument("argument is less than one");
            }

            std::vector<std::pair<BigInt, std::size_t>> factors;
            for (BigInt factor = 2; factor * factor <= number; ++factor) {
                std::size_t power = 0;

                while (number % factor == 0) {
                    ++power;
                    number /= factor;
                }

                if (power != 0) {
                    factors.emplace_back(factor, power);
                }
            }

            if (number > 1) {
                factors.emplace_back(number, 1);
            }

            return factors;
        }

        BigInt Pow(BigInt base, std::size_t exp) {
            BigInt result = 1;
            while (exp > 0) {
                if ((exp & 1U) != 0) {
                    result *= base;
                }

                exp >>= 1U;
                base *= base;
            }

            return result;
        }
    }

    std::int8_t NumberTheoryService::LegendreSymbol(const BigInt &number, const BigInt &odd_prime) {
        if (odd_prime <= 2) {
            throw std::invalid_argument("algorithm uses odd prime number");
        }

        const BigInt result = PowMod(number % odd_prime, (odd_prime - 1) >> 1, odd_prime);
        if (result == 0) {
            return 0;
        }
        if (result == 1) {
            return 1;
        }
        if (result == odd_prime - 1) {
            return -1;
        }

        throw std::invalid_argument("argument wasnt prime");
    }

    std::int8_t NumberTheoryService::JacobiSymbol(BigInt number, BigInt odd_positive) {
        if (odd_positive <= 0 || (odd_positive & 1) == 0) {
            throw std::invalid_argument("algorithm uses odd positive number");
        }

        number %= odd_positive;
        if (number < 0) {
            number += odd_positive;
        }

        std::int8_t sign{1};
        while (number != 0) {
            while ((number & 1) == 0) {
                number >>= 1;

                if (const auto r = odd_positive & 7; r == 3 || r == 5) {
                    sign = -sign;
                }
            }

            std::swap(number, odd_positive);

            if ((number & 3) == 3 && (odd_positive & 3) == 3) {
                sign = -sign;
            }

            number %= odd_positive;
        }

        return odd_positive == 1 ? sign : 0;
    }

    BigInt NumberTheoryService::GCDClassicEuclid(BigInt lhs, BigInt rhs) {
        if (lhs == 0 && rhs == 0) {
            throw std::invalid_argument("LHS and RHS are both zero");
        }

        if (lhs < 0) {
            lhs = -lhs;
        }
        if (rhs < 0) {
            rhs = -rhs;
        }

        while (rhs != 0) {
            lhs %= rhs;
            std::swap(lhs, rhs);
        }

        return lhs;
    }

    BezoutResult NumberTheoryService::GCDExtendedEuclid(const BigInt& lhs, const BigInt& rhs) {
        if (lhs == 0 && rhs == 0) {
            throw std::invalid_argument("LHS and RHS are both zero");
        }

        BigInt prev_r = lhs < 0 ? -lhs : lhs;
        BigInt r = rhs < 0 ? -rhs : rhs;
        BigInt prev_s = 1;
        BigInt s = 0;
        BigInt prev_t = 0;
        BigInt t = 1;

        while (r != 0) {
            const BigInt q = prev_r / r;

            auto temp = r;
            r = prev_r - q * r;
            prev_r = temp;

            temp = s;
            s = prev_s - q * s;
            prev_s = temp;

            temp = t;
            t = prev_t - q * t;
            prev_t = temp;
        }

        if (lhs < 0) {
            prev_s = -prev_s;
        }
        if (rhs < 0) {
            prev_t = -prev_t;
        }

        return {.gcd = prev_r, .x = prev_s, .y = prev_t};
    }

    BigInt NumberTheoryService::GCDBinaryEuclid(BigInt lhs, BigInt rhs) {
        if (lhs == 0 && rhs == 0) {
            throw std::invalid_argument("LHS and RHS are both zero");
        }

        if (lhs < 0) {
            lhs = -lhs;
        }
        if (rhs < 0) {
            rhs = -rhs;
        }

        if (lhs == 0) {
            return rhs;
        }
        if (rhs == 0) {
            return lhs;
        }

        std::size_t shift{0};
        while (((lhs | rhs) & 1) == 0) {
            lhs >>= 1;
            rhs >>= 1;
            ++shift;
        }

        while ((lhs & 1) == 0) {
            lhs >>= 1;
        }

        do {
            while ((rhs & 1) == 0) {
                rhs >>= 1;
            }

            if (lhs > rhs) {
                std::swap(lhs, rhs);
            }

            rhs -= lhs;
        } while (rhs != 0);

        return lhs << shift;
    }

    BigInt NumberTheoryService::PowMod(BigInt base, BigInt exp, const BigInt &mod) {
        if (mod <= 0 || exp < 0) {
            throw std::invalid_argument("invalid mod or exp");
        }

        if (mod == 1) {
            return 0;
        }

        base %= mod;
        if (base < 0) {
            base += mod;
        }

        BigInt result = 1;
        while (exp > 0) {
            if ((exp & 1) != 0) {
                result = result * base % mod;
            }

            exp >>= 1;
            base = base * base % mod;
        }

        return result;
    }

    BigInt NumberTheoryService::EulerFuncByDefinition(const BigInt &number) {
        if (number < 1) {
            throw std::invalid_argument("wrong number for euler function");
        }

        BigInt count = 0;
        for (BigInt i = 1; i <= number; ++i) {
            if (GCDBinaryEuclid(i, number) == 1) {
                ++count;
            }
        }

        return count;
    }

    BigInt NumberTheoryService::EulerFuncByFactorization(const BigInt &number) {
        if (number < 1) {
            throw std::invalid_argument("wrong number for euler function");
        }

        BigInt count = 1;
        for (const auto& [prime, power] : Factorization(number)) {
            count *= (prime - 1) * Pow(prime, power - 1);
        }

        return count;
    }

    BigInt NumberTheoryService::EulerFuncByDFT(const BigInt &number) {
        if (number < 1) {
            throw std::invalid_argument("wrong number for euler function");
        }

        boost::multiprecision::cpp_dec_float_100 sum = 0;
        const boost::multiprecision::cpp_dec_float_100 n{number.str()};

        for (BigInt i = 1; i <= number; ++i) {
            const boost::multiprecision::cpp_dec_float_100 k{i.str()};
            const boost::multiprecision::cpp_dec_float_100 gcd{GCDBinaryEuclid(i, number).str()};
            const boost::multiprecision::cpp_dec_float_100 angle =
                boost::multiprecision::cpp_dec_float_100{2} *
                boost::math::constants::pi<boost::multiprecision::cpp_dec_float_100>() *
                k / n;
            sum += gcd * boost::multiprecision::cos(angle);
        }

        const boost::multiprecision::cpp_dec_float_100 rounded = boost::multiprecision::floor(sum + boost::multiprecision::cpp_dec_float_100{"0.5"});

        return rounded.convert_to<BigInt>();
    }

    BigInt NumberTheoryService::CarmichaelFuncByFactorization(const BigInt &number) {
        if (number < 1) {
            throw std::invalid_argument("wrong number for euler function");
        }

        BigInt count = 1;
        for (const auto& [prime, power] : Factorization(number)) {
            BigInt lambda;

            if (prime == 2 && power > 2) {
                lambda = BigInt{1} << (power - 2);
            } else {
                lambda = (prime - 1) * Pow(prime, power - 1);
            }

            const auto gcd = GCDBinaryEuclid(count, lambda);
            count = count / gcd * lambda;
        }

        return count;
    }
}
