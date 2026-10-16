export module crypto.wiener;

import std;
import crypto.number_theory;
import crypto.rsa;
import crypto.primality_tests;

export namespace crypto {
    struct ContinuedFractionConvergent {
        BigInt numerator{0};
        BigInt denominator{0};
    };

    struct WienerAttackResult {
        std::optional<BigInt> d;
        std::optional<BigInt> phi;
        std::vector<ContinuedFractionConvergent> convergents;

        [[nodiscard]]
        bool Success() const noexcept {
            return d.has_value() && phi.has_value();
        }
    };

    class WienerAttackService final {
    public:
        static WienerAttackResult Attack(const RSAService::PublicKey& public_key);

    private:
        static std::vector<BigInt> CreateContinuedFraction(const ContinuedFractionConvergent& fraction);

        static std::vector<ContinuedFractionConvergent> CreateConvergents(const ContinuedFractionConvergent& fraction);
    };

    class WienerKeyGen final {
    public:
        explicit WienerKeyGen(RSAService::ProbabilisticPrimalityTest test_type, double min_probability, std::size_t bit_length);

        [[nodiscard]]
        RSAService::KeyPair GenerateKeys();

    private:
        [[nodiscard]]
        std::unique_ptr<IProbabilisticPrimalityTest> CreateTest() const;

        [[nodiscard]]
        BigInt GenerateOdd();

        [[nodiscard]]
        BigInt GenerateProbablePrime();

    private:
        RSAService::ProbabilisticPrimalityTest test_type_;
        double min_probability_;
        std::size_t bit_length_;
        std::unique_ptr<IProbabilisticPrimalityTest> test_;
        std::mt19937_64 random_generator_;
    };
}