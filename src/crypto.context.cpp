module crypto.context;

import std;
import crypto.cipher;
import crypto.modes;
import crypto.padding;

namespace crypto {
    class SymmetricCipherContext::SymmetricCipherContextImpl {
    public:
        SymmetricCipherContextImpl(
            std::unique_ptr<SymmetricCipher> cipher,
            std::span<const std::byte> key,
            CipherMode cipher_mode,
            PaddingMode padding_mode,
            std::span<const std::byte> iv,
            std::vector<std::vector<std::byte>> extra_parameters
        )
        :
            cipher_(std::move(cipher)),
            key_(key.begin(), key.end()),
            cipher_mode_(cipher_mode),
            padding_mode_(padding_mode),
            iv_(iv.begin(), iv.end()),
            extra_parameters_(std::move(extra_parameters))
        {
            if (!cipher_) {
                throw std::invalid_argument("cipher is null");
            }

            cipher_->SetKey(key_);
        }

        ~SymmetricCipherContextImpl() = default;
    private:
        std::unique_ptr<SymmetricCipher> cipher_;
        std::vector<std::byte> key_;
        CipherMode cipher_mode_;
        PaddingMode padding_mode_;
        std::vector<std::byte> iv_;
        std::vector<std::vector<std::byte>> extra_parameters_;
    };

    SymmetricCipherContext::SymmetricCipherContext(
        std::unique_ptr<SymmetricCipher> cipher,
        std::span<const std::byte> key,
        CipherMode cipher_mode,
        PaddingMode padding_mode,
        std::span<const std::byte> iv,
        std::vector<std::vector<std::byte>> extra_parameters
    ) : symmetric_cipher_context_impl_(std::make_unique<SymmetricCipherContextImpl>(
            std::move(cipher),
            key,
            cipher_mode,
            padding_mode,
            iv,
            std::move(extra_parameters)
        )
    ) {}

    SymmetricCipherContext::~SymmetricCipherContext() = default;

    SymmetricCipherContext::SymmetricCipherContext(SymmetricCipherContext&& rhs) noexcept = default;
    SymmetricCipherContext& SymmetricCipherContext::operator=(SymmetricCipherContext&& rhs) noexcept = default;

    std::future<void> SymmetricCipherContext::EncryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        return std::async(std::launch::async, [](){throw std::logic_error("not implemented");});
    }
    std::future<void> SymmetricCipherContext::EncryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(std::launch::async, [](){throw std::logic_error("not implemented");});
    }

    std::future<void> SymmetricCipherContext::DecryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        return std::async(std::launch::async, [](){throw std::logic_error("not implemented");});
    }
    std::future<void> SymmetricCipherContext::DecryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(std::launch::async, [](){throw std::logic_error("not implemented");});
    }
}