module;

#include <boost/multiprecision/cpp_int.hpp>

export module crypto.rsa;

import std;
import crypto.number_theory;
import crypto.primality_tests;

export namespace  crypto {
    class RSAService final {
    public:
        struct PublicKey {
            BigInt n{0};
            BigInt e{0};
        };
        struct PrivateKey {
            BigInt n{0};
            BigInt d{0};
        };
        struct KeyPair {
            PublicKey public_key;
            PrivateKey private_key;
        };

        enum class ProbabilisticPrimalityTest {
            FermatPrimalityTest = 0,
            SolovayStrassenPrimalityTest = 1,
            MillerRabinPrimalityTest = 2,
        };

        class RSAKeyGen final {
        public:
            explicit RSAKeyGen(ProbabilisticPrimalityTest test_type, double min_probability, std::size_t bit_length);

            [[nodiscard]]
            KeyPair GenerateKeys();
        private:
            [[nodiscard]]
            std::unique_ptr<IProbabilisticPrimalityTest> CreateTest() const;

            [[nodiscard]]
            BigInt GenerateOdd();

            [[nodiscard]]
            BigInt GenerateProbablePrime();

        private:
            ProbabilisticPrimalityTest test_type_;
            double min_probability_;
            std::size_t bit_length_;
            std::unique_ptr<IProbabilisticPrimalityTest> test_;
            std::mt19937_64 random_generator_;
        };

    public:
        explicit RSAService(ProbabilisticPrimalityTest test_type, double min_probability, std::size_t bit_length);

        [[nodiscard]]
        KeyPair GenerateKeys();

        static BigInt Encrypt(const BigInt& plaintext, const PublicKey& public_key);

        static BigInt Decrypt(const BigInt& ciphertext, const PrivateKey& private_key);

    private:
        RSAKeyGen key_gen_;
    };
}