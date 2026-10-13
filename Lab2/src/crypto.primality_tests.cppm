module;

#include <boost/multiprecision/cpp_int.hpp>

export module crypto.primality_tests;

import std;
import crypto.number_theory;

export namespace crypto {
    class IProbabilisticPrimalityTest {
    public:
        virtual ~IProbabilisticPrimalityTest() = default;

        [[nodiscard]]
        virtual bool Test(const BigInt& number, double min_probability) const = 0;
    };

    class ProbabilisticPrimalityTest : public IProbabilisticPrimalityTest {
    public:
        [[nodiscard]]
        bool Test(const BigInt& number, double min_probability) const final;

    protected:
        [[nodiscard]]
        virtual bool TestOneRound(const BigInt& number, const BigInt& base) const = 0;

        [[nodiscard]]
        virtual double ErrorProbabilityPerRound() const noexcept = 0;

    private:
        static BigInt RandomBelow(const BigInt& upper_bound, std::mt19937_64& engine);

        static BigInt RandomBase(const BigInt& number, std::mt19937_64& engine);
    };

    class FermatPrimalityTest final : public ProbabilisticPrimalityTest {
    protected:
        [[nodiscard]]
        bool TestOneRound(const BigInt &number, const BigInt &base) const override;

        [[nodiscard]]
        double ErrorProbabilityPerRound() const noexcept override;
    };

    class SolovayStrassenPrimalityTest final : public ProbabilisticPrimalityTest {
    protected:
        [[nodiscard]]
        bool TestOneRound(const BigInt &number, const BigInt &base) const override;

        [[nodiscard]]
        double ErrorProbabilityPerRound() const noexcept override;
    };

    class MillerRabinPrimalityTest final : public ProbabilisticPrimalityTest {
    protected:
        [[nodiscard]]
        bool TestOneRound(const BigInt &number, const BigInt &base) const override;

        [[nodiscard]]
        double ErrorProbabilityPerRound() const noexcept override;
    };
}
