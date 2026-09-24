#include <gtest/gtest.h>

import crypto.cipher;
import crypto.modes;
import crypto.padding;
import std;

namespace {

std::vector<std::byte> Bytes(std::initializer_list<unsigned int> values) {
    std::vector<std::byte> result;
    result.reserve(values.size());

    for (const auto value : values) {
        result.push_back(static_cast<std::byte>(value));
    }

    return result;
}

class XorCipher final : public crypto::SymmetricCipher {
public:
    explicit XorCipher(std::size_t block_size = 4)
        : block_size_(block_size) {}

    void SetKey(std::span<const std::byte>) override {}

    [[nodiscard]]
    std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override {
        std::vector<std::byte> result(block.begin(), block.end());

        for (auto& byte : result) {
            byte ^= std::byte{0xAA};
        }

        return result;
    }

    [[nodiscard]]
    std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const override {
        return EncryptBlock(block);
    }

    [[nodiscard]]
    std::size_t BlockSize() const override {
        return block_size_;
    }

private:
    std::size_t block_size_;
};

class EncryptOnlyXorCipher final : public crypto::SymmetricCipher {
public:
    void SetKey(std::span<const std::byte>) override {}

    [[nodiscard]]
    std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const override {
        std::vector<std::byte> result(block.begin(), block.end());

        for (auto& byte : result) {
            byte ^= std::byte{0x55};
        }

        return result;
    }

    [[nodiscard]]
    std::vector<std::byte> DecryptBlock(std::span<const std::byte>) const override {
        throw std::logic_error("DecryptBlock must not be used by this mode");
    }

    [[nodiscard]]
    std::size_t BlockSize() const override {
        return 4;
    }
};

std::vector<std::byte> Iv() {
    return Bytes({0x01, 0x02, 0x03, 0x04});
}

std::vector<std::byte> RandomDeltaIv() {
    return Bytes({0x10, 0x20, 0x00, 0x03});
}

void ExpectRoundTrip(
    crypto::CipherMode cipher_mode,
    std::span<const std::byte> iv = {}
) {
    XorCipher cipher;
    const auto input = Bytes({0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70});

    auto mode = crypto::MakeCipherModeStrategy(cipher_mode, iv);

    const auto encrypted = mode->Encrypt(cipher, input, crypto::PaddingMode::PKCS7);
    const auto decrypted = mode->Decrypt(cipher, encrypted, crypto::PaddingMode::PKCS7);

    EXPECT_EQ(decrypted, input);
}

void ExpectEncryptOnlyRoundTrip(
    crypto::CipherMode cipher_mode,
    std::span<const std::byte> iv
) {
    EncryptOnlyXorCipher cipher;
    const auto input = Bytes({0x10, 0x20, 0x30, 0x40, 0x50});

    auto mode = crypto::MakeCipherModeStrategy(cipher_mode, iv);

    const auto encrypted = mode->Encrypt(cipher, input, crypto::PaddingMode::PKCS7);
    const auto decrypted = mode->Decrypt(cipher, encrypted, crypto::PaddingMode::PKCS7);

    EXPECT_EQ(decrypted, input);
}

}

TEST(Modes, EcbDecryptsEncryptedData) {
    ExpectRoundTrip(crypto::CipherMode::ECB);
}

TEST(Modes, CbcDecryptsEncryptedData) {
    const auto iv = Iv();

    ExpectRoundTrip(crypto::CipherMode::CBC, iv);
}

TEST(Modes, PcbcDecryptsEncryptedData) {
    const auto iv = Iv();

    ExpectRoundTrip(crypto::CipherMode::PCBC, iv);
}

TEST(Modes, CfbDecryptsEncryptedData) {
    const auto iv = Iv();

    ExpectRoundTrip(crypto::CipherMode::CFB, iv);
}

TEST(Modes, OfbDecryptsEncryptedData) {
    const auto iv = Iv();

    ExpectRoundTrip(crypto::CipherMode::OFB, iv);
}

TEST(Modes, CtrDecryptsEncryptedData) {
    const auto iv = Iv();

    ExpectRoundTrip(crypto::CipherMode::CTR, iv);
}

TEST(Modes, RandomDeltaDecryptsEncryptedData) {
    const auto iv = RandomDeltaIv();

    ExpectRoundTrip(crypto::CipherMode::RandomDelta, iv);
}

TEST(Modes, CfbDecryptUsesEncryptBlock) {
    const auto iv = Iv();

    ExpectEncryptOnlyRoundTrip(crypto::CipherMode::CFB, iv);
}

TEST(Modes, OfbDecryptUsesEncryptBlock) {
    const auto iv = Iv();

    ExpectEncryptOnlyRoundTrip(crypto::CipherMode::OFB, iv);
}

TEST(Modes, CtrDecryptUsesEncryptBlock) {
    const auto iv = Iv();

    ExpectEncryptOnlyRoundTrip(crypto::CipherMode::CTR, iv);
}

TEST(Modes, RandomDeltaDecryptUsesEncryptBlock) {
    const auto iv = RandomDeltaIv();

    ExpectEncryptOnlyRoundTrip(crypto::CipherMode::RandomDelta, iv);
}

TEST(Modes, EcbRejectsIv) {
    const auto iv = Iv();

    EXPECT_THROW(
        static_cast<void>(crypto::MakeCipherModeStrategy(crypto::CipherMode::ECB, iv)),
        std::invalid_argument
    );
}

TEST(Modes, RejectsExtraParameters) {
    const auto iv = Iv();
    const std::vector<std::vector<std::byte>> extra_parameters{
        Bytes({0x01, 0x02, 0x03, 0x04})
    };

    EXPECT_THROW(
        static_cast<void>(crypto::MakeCipherModeStrategy(
            crypto::CipherMode::CBC,
            iv,
            extra_parameters
        )),
        std::invalid_argument
    );
}

TEST(Modes, CbcRejectsInvalidIvSize) {
    XorCipher cipher;
    const auto input = Bytes({0x10, 0x20, 0x30});
    const auto invalid_iv = Bytes({0x01, 0x02});

    auto mode = crypto::MakeCipherModeStrategy(crypto::CipherMode::CBC, invalid_iv);

    EXPECT_THROW(
        static_cast<void>(mode->Encrypt(cipher, input, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}

TEST(Modes, DecryptRejectsUnalignedData) {
    XorCipher cipher;
    const auto iv = Iv();
    const auto encrypted = Bytes({0x10, 0x20, 0x30});

    auto mode = crypto::MakeCipherModeStrategy(crypto::CipherMode::CTR, iv);

    EXPECT_THROW(
        static_cast<void>(mode->Decrypt(cipher, encrypted, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}

TEST(Modes, RandomDeltaRejectsOddBlockSize) {
    XorCipher cipher(3);
    const auto input = Bytes({0x10, 0x20, 0x30});
    const auto iv = Bytes({0x01, 0x02, 0x03});

    auto mode = crypto::MakeCipherModeStrategy(crypto::CipherMode::RandomDelta, iv);

    EXPECT_THROW(
        static_cast<void>(mode->Encrypt(cipher, input, crypto::PaddingMode::PKCS7)),
        std::invalid_argument
    );
}

TEST(Modes, CbcDoesNotProduceEqualBlocksForEqualPlainBlocks) {
    XorCipher cipher;
    const auto iv = Iv();
    const auto input = Bytes({
        0x10, 0x20, 0x30, 0x40,
        0x10, 0x20, 0x30, 0x40
    });

    auto mode = crypto::MakeCipherModeStrategy(crypto::CipherMode::CBC, iv);
    const auto encrypted = mode->Encrypt(cipher, input, crypto::PaddingMode::Zeros);

    ASSERT_GE(encrypted.size(), 8);
    EXPECT_FALSE(std::equal(encrypted.begin(), encrypted.begin() + 4, encrypted.begin() + 4));
}
