#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

import std;
import crypto.number_theory;
import crypto.rsa;
import crypto.wiener;

int main() {
    std::println("Legendre symbol for 52 and 13 equals to: {} (expected 0)",
        static_cast<int>(crypto::NumberTheoryService::LegendreSymbol(52, 13))
    );
    std::println("Legendre symbol for 1 and 3 equals to: {} (expected 1)",
        static_cast<int>(crypto::NumberTheoryService::LegendreSymbol(1, 3))
    );
    std::println("Legendre symbol for 3 and 5 equals to: {} (expected -1)",
        static_cast<int>(crypto::NumberTheoryService::LegendreSymbol(3, 5))
    );
    std::println("");

    std::println("Jacobi symbol for 3 and 15 equals to: {} (expected 0)",
        static_cast<int>(crypto::NumberTheoryService::JacobiSymbol(3, 15))
    );
    std::println("Jacobi symbol for 2 and 15 equals to: {} (expected 1)",
        static_cast<int>(crypto::NumberTheoryService::JacobiSymbol(2, 15))
    );
    std::println("Jacobi symbol for 2 and 5 equals to: {} (expected -1)",
        static_cast<int>(crypto::NumberTheoryService::JacobiSymbol(2, 5))
    );
    std::println("");

    std::println("GCD classic Euclid for 39 and 52 equals to {} (expected 13)",
        crypto::NumberTheoryService::GCDClassicEuclid(39, 52).str()
    );
    std::println("GCD binary Euclid for 39 and 52 equals to {} (expected 13)",
        crypto::NumberTheoryService::GCDBinaryEuclid(39, 52).str()
    );
    const auto bezout = crypto::NumberTheoryService::GCDExtendedEuclid(39, 52);
    std::println("GCD extended Euclid: 39 * {} + 52 * {} = {} (expected 39 * (-1) + 52 * 1 = 13)",
        bezout.x.str(), bezout.y.str(), bezout.gcd.str()
    );
    std::println("");

    std::println("PowMod for 13 and 2 mod 52 equals to {} (expected 13)",
        crypto::NumberTheoryService::PowMod(13, 2, 52).str()
    );
    std::println("");

    std::println("Euler function by definition for 30 equals to {} (expected 8)",
        crypto::NumberTheoryService::EulerFuncByDefinition(30).str()
    );
    std::println("Euler function by factorization for 30 equals to {} (expected 8)",
        crypto::NumberTheoryService::EulerFuncByFactorization(30).str()
    );
    std::println("Euler function by DFT for 30 equals to {} (expected 8)",
        crypto::NumberTheoryService::EulerFuncByDFT(30).str()
    );
    std::println("");

    std::println("Carmichael function for 32 equals to {} (expected 8)",
        crypto::NumberTheoryService::CarmichaelFuncByFactorization(32).str()
    );
    std::println("Carmichael function for 13 equals to {} (expected 12)",
        crypto::NumberTheoryService::CarmichaelFuncByFactorization(13).str()
    );
    std::println("");

    constexpr std::size_t kKeySize = 2048;
    crypto::RSAService rsa1(crypto::RSAService::ProbabilisticPrimalityTest::FermatPrimalityTest, 0.9, kKeySize >> 1);
    crypto::RSAService rsa2(crypto::RSAService::ProbabilisticPrimalityTest::SolovayStrassenPrimalityTest, 0.9, kKeySize >> 1);
    crypto::RSAService rsa3(crypto::RSAService::ProbabilisticPrimalityTest::MillerRabinPrimalityTest, 0.9, kKeySize >> 1);

    const auto [public_key1, private_key1] = rsa1.GenerateKeys();
    const auto [public_key2, private_key2] = rsa2.GenerateKeys();
    const auto [public_key3, private_key3] = rsa3.GenerateKeys();

    const crypto::BigInt msg = 65537;
    crypto::BigInt encrypted{0};
    crypto::BigInt decrypted{0};

    encrypted = rsa1.Encrypt(msg, public_key1);
    decrypted = rsa1.Decrypt(encrypted, private_key1);
    std::println("msg: {} = decrypted: {}", msg.str(), decrypted.str());

    encrypted = rsa2.Encrypt(msg, public_key2);
    decrypted = rsa2.Decrypt(encrypted, private_key2);
    std::println("msg: {} = decrypted: {}", msg.str(), decrypted.str());

    encrypted = rsa3.Encrypt(msg, public_key3);
    decrypted = rsa3.Decrypt(encrypted, private_key3);
    std::println("msg: {} = decrypted: {}", msg.str(), decrypted.str());

    crypto::WienerKeyGen bad_key_gen1(crypto::RSAService::ProbabilisticPrimalityTest::FermatPrimalityTest, 0.9, kKeySize >> 1);
    crypto::WienerKeyGen bad_key_gen2(crypto::RSAService::ProbabilisticPrimalityTest::SolovayStrassenPrimalityTest, 0.9, kKeySize >> 1);
    crypto::WienerKeyGen bad_key_gen3(crypto::RSAService::ProbabilisticPrimalityTest::MillerRabinPrimalityTest, 0.9, kKeySize >> 1);

    const auto [bad_public_key1, bad_private_key1] = bad_key_gen1.GenerateKeys();
    const auto [bad_public_key2, bad_private_key2] = bad_key_gen2.GenerateKeys();
    const auto [bad_public_key3, bad_private_key3] = bad_key_gen3.GenerateKeys();

    std::println("public_key1 (n, e): {} {}, private_key1 (n, d): {} {}",
        bad_public_key1.n.str(),
        bad_public_key1.e.str(),
        bad_private_key1.n.str(),
        bad_private_key1.d.str()
    );
    const auto attack_result1 = crypto::WienerAttackService::Attack(bad_public_key1);
    std::println("after Wiener's attack got (phi, d): {} {}",
        attack_result1.phi.value().str(),
        attack_result1.d.value().str()
    );

    std::println("public_key2 (n, e): {} {}, private_key2 (n, d): {} {}",
        bad_public_key2.n.str(),
        bad_public_key2.e.str(),
        bad_private_key2.n.str(),
        bad_private_key2.d.str()
    );
    const auto attack_result2 = crypto::WienerAttackService::Attack(bad_public_key2);
    std::println("after Wiener's attack got (phi, d): {} {}",
        attack_result2.phi.value().str(),
        attack_result2.d.value().str()
    );

    std::println("public_key3 (n, e): {} {}, private_key3 (n, d): {} {}",
        bad_public_key3.n.str(),
        bad_public_key3.e.str(),
        bad_private_key3.n.str(),
        bad_private_key3.d.str()
    );
    const auto attack_result3 = crypto::WienerAttackService::Attack(bad_public_key3);
    std::println("after Wiener's attack got (phi, d): {} {}",
        attack_result3.phi.value().str(),
        attack_result3.d.value().str()
    );

    return 0;
}
