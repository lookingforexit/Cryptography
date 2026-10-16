module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

module crypto.wiener;

import std;

namespace crypto {
    std::vector<BigInt> WienerAttackService::CreateContinuedFraction(const ContinuedFractionConvergent &fraction) {
        if (fraction.denominator == 0) {
            throw std::invalid_argument("invalid denominator");
        }

        BigInt numerator = fraction.numerator;
        BigInt denominator = fraction.denominator;

        std::vector<BigInt> result;

        while (denominator != 0) {
            result.emplace_back(numerator / denominator);

            const BigInt remainder = numerator % denominator;
            numerator = denominator;
            denominator = remainder;
        }

        return result;
    }

    std::vector<ContinuedFractionConvergent> WienerAttackService::CreateConvergents(const ContinuedFractionConvergent &fraction) {
        const auto decomposition = CreateContinuedFraction(fraction);

        std::vector<ContinuedFractionConvergent> result;
        result.reserve(decomposition.size());

        BigInt p_prev_prev = 0;
        BigInt p_prev = 1;
        BigInt q_prev_prev = 1;
        BigInt q_prev = 0;

        for (std::size_t i = 0; i < decomposition.size(); ++i) {
            const BigInt p = decomposition[i] * p_prev + p_prev_prev;
            const BigInt q = decomposition[i] * q_prev + q_prev_prev;
            result.push_back({.numerator = p, .denominator = q});

            p_prev_prev = p_prev;
            p_prev = p;
            q_prev_prev = q_prev;
            q_prev = q;
        }

        return result;
    }

    WienerAttackResult WienerAttackService::Attack(const RSAService::PublicKey &public_key) {
        if (public_key.n <= 1 || public_key.e <= 0) {
            throw std::invalid_argument("invalid public_key");
        }

        const auto convergents = CreateConvergents({.numerator = public_key.e, .denominator = public_key.n});
        for (const auto& [k, d] : convergents) {
            if (k == 0) {
                continue;
            }

            if ((public_key.e * d - 1) % k != 0) {
                continue;
            }

            // phi = (ed - 1) / k
            const auto phi = (public_key.e * d - 1) / k;
            if (phi <= 0 || phi >= public_key.n) {
                continue;
            }

            // x^2 - ((N - phi) + 1)x + n = 0
            const auto sum_roots = public_key.n - phi + 1;
            const auto discriminant = sum_roots * sum_roots - 4 * public_key.n;
            if (discriminant >= 0) {
                const BigInt root = boost::multiprecision::sqrt(discriminant);
                if (root * root == discriminant && ((sum_roots + root) & 1) == 0) {
                    const BigInt factor1 = (sum_roots + root) >> 1;
                    const BigInt factor2 = (sum_roots - root) >> 1;
                    if (factor1 > 1 && factor2 > 1 && factor1 * factor2 == public_key.n) {
                        return {.d = d, .phi = phi, .convergents = convergents};
                    }
                }
            }
        }

        return {.d = std::nullopt, .phi = std::nullopt, .convergents = convergents};
    }

    std::unique_ptr<IProbabilisticPrimalityTest> WienerKeyGen::CreateTest() const {
        switch (test_type_) {
            case RSAService::ProbabilisticPrimalityTest::FermatPrimalityTest:
                return std::make_unique<FermatPrimalityTest>();
            case RSAService::ProbabilisticPrimalityTest::SolovayStrassenPrimalityTest:
                return std::make_unique<SolovayStrassenPrimalityTest>();
            case RSAService::ProbabilisticPrimalityTest::MillerRabinPrimalityTest:
                return std::make_unique<MillerRabinPrimalityTest>();
            default:
                throw std::logic_error("unsupported probabilistic primality test type");
        }
    }

    BigInt WienerKeyGen::GenerateOdd() {
        BigInt result{0};

        for (std::size_t i = 0; i < bit_length_; ++i) {
            if ((random_generator_() & 1) != 0) {
                result |= BigInt{1} << i;
            }
        }

        result |= BigInt{1} << (bit_length_ - 1);
        result |= 1;

        return result;
    }

    BigInt WienerKeyGen::GenerateProbablePrime() {
        while (true) {
            if (const auto odd = GenerateOdd(); test_->Test(odd, min_probability_)) {
                return odd;
            }
        }
    }

    WienerKeyGen::WienerKeyGen(
        RSAService::ProbabilisticPrimalityTest test_type,
        double min_probability,
        std::size_t bit_length
    ) :
        test_type_(test_type),
        min_probability_(min_probability),
        bit_length_(bit_length),
        test_(CreateTest()),
        random_generator_(std::random_device{}())
    {
        if (min_probability_ - 0.5 < -std::numeric_limits<double>::epsilon() ||
            min_probability_ - 1 >= 0) {
            throw std::invalid_argument("min_probability has to be in [0.5; 1)");
            }

        if (bit_length_ < 2) {
            throw std::invalid_argument("bit_length has to be greater than 2");
        }
    }

    RSAService::KeyPair WienerKeyGen::GenerateKeys() {
        while (true) {
            BigInt p = GenerateProbablePrime();
            BigInt q = GenerateProbablePrime();
            if (p == q) {
                continue;
            }

            const BigInt n = p * q;
            const BigInt fourth_root = boost::multiprecision::sqrt(boost::multiprecision::sqrt(n));
            const BigInt phi = (p - 1) * (q - 1);
            BigInt d = 3;
            bool flag = false;

            for (; 3 * d <= fourth_root; d += 2) {
                if (NumberTheoryService::GCDBinaryEuclid(d, phi) == 1) {
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                continue;
            }

            const auto bezout = NumberTheoryService::GCDExtendedEuclid(d, phi);
            BigInt e = bezout.x % phi;
            if (e < 0) {
                e += phi;
            }
            if (e <= 1 || e >= phi) {
                continue;
            }

            return {.public_key = {.n = n, .e = e}, .private_key = {.n = n, .d = d}};
        }
    }
}
