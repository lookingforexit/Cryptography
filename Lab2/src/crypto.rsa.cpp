module;

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

module crypto.rsa;

namespace crypto {
    std::unique_ptr<IProbabilisticPrimalityTest> RSAService::RSAKeyGen::CreateTest() const {
        switch (test_type_) {
            case ProbabilisticPrimalityTest::FermatPrimalityTest:
                return std::make_unique<FermatPrimalityTest>();
            case ProbabilisticPrimalityTest::SolovayStrassenPrimalityTest:
                return std::make_unique<SolovayStrassenPrimalityTest>();
            case ProbabilisticPrimalityTest::MillerRabinPrimalityTest:
                return std::make_unique<MillerRabinPrimalityTest>();
            default:
                throw std::logic_error("unsupported probabilistic primality test type");
        }
    }

    BigInt RSAService::RSAKeyGen::GenerateOdd() {
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

    BigInt RSAService::RSAKeyGen::GenerateProbabilisticPrime() {
        while (true) {
            if (const auto odd = GenerateOdd(); test_->Test(odd, min_probability_)) {
                return odd;
            }
        }
    }

    RSAService::RSAKeyGen::RSAKeyGen(
        ProbabilisticPrimalityTest test_type,
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

    RSAService::KeyPair RSAService::RSAKeyGen::GenerateKeys() {
        // n = pq
        // phi(n) = (p - 1)(q - 1)
        // gcd(e, phi) = 1
        // d = e^(-1) mod phi(n)
        while (true) {
            // 4th Fermat number, equals to 2^2^4 + 1
            const BigInt e = 65537;
            BigInt p{0};
            BigInt q{0};

            while (true) {
                p = GenerateProbabilisticPrime();
                if (NumberTheoryService::GCDBinaryEuclid(e, p - 1) == 1) {
                    break;
                }
            }

            while (true) {
                q = GenerateProbabilisticPrime();
                if (NumberTheoryService::GCDBinaryEuclid(e, q - 1) == 1) {
                    break;
                }
            }

            // Fermat's attack
            if (boost::multiprecision::abs(p - q) <= 1 << ((bit_length_ >> 1) - 100)) {
                continue;
            }

            const BigInt n = p * q;
            const BigInt phi = (p - 1) * (q - 1);
            const auto bezout = NumberTheoryService::GCDExtendedEuclid(e, phi);

            BigInt d = bezout.x % phi;
            if (d < 0) {
                d += phi;
            }

            // Wiener's attack
            if (3 * d <= boost::multiprecision::sqrt(boost::multiprecision::sqrt(n))) {
                continue;
            }

            return {.public_key = {.n = n, .e = e}, .private_key = {.n = n, .d = d}};
        }
    }

    RSAService::RSAService(
        ProbabilisticPrimalityTest test_type,
        double min_probability,
        std::size_t bit_length
    ) : key_gen_(test_type, min_probability, bit_length) {}

    RSAService::KeyPair RSAService::GenerateKeys() {
        return key_gen_.GenerateKeys();
    }

    BigInt RSAService::Encrypt(const BigInt &plaintext, const PublicKey &public_key) {
        // c = p^e mod n
        if (public_key.e != 65537 || public_key.n <= 1) {
            throw std::invalid_argument("invalid public key");
        }
        if (plaintext < 0 || plaintext >= public_key.n) {
            throw std::invalid_argument("invalid plaintext, it has to be in [0, n)");
        }

        return NumberTheoryService::PowMod(plaintext, public_key.e, public_key.n);
    }

    BigInt RSAService::Decrypt(const BigInt &ciphertext, const PrivateKey &private_key) {
        // p = c^d mod n
        if (private_key.d <= 0 || private_key.n <= 1) {
            throw std::invalid_argument("invalid public key");
        }
        if (ciphertext < 0 || ciphertext >= private_key.n) {
            throw std::invalid_argument("invalid ciphertext, it has to be in [0, n)");
        }

        return NumberTheoryService::PowMod(ciphertext, private_key.d, private_key.n);
    }
}
