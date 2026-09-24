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
            const std::vector<std::vector<std::byte>>& extra_parameters
        )
        :
            cipher_(std::move(cipher)),
            cipher_mode_strategy_(MakeCipherModeStrategy(
                cipher_mode,
                iv,
                extra_parameters
            )),
            padding_mode_(padding_mode)
        {
            if (!cipher_) {
                throw std::invalid_argument("cipher is null");
            }

            cipher_->SetKey(key);
        }

        ~SymmetricCipherContextImpl() = default;

        std::vector<std::byte> Encrypt(std::span<const std::byte> input) const {
            return cipher_mode_strategy_->Encrypt(*cipher_, input, padding_mode_);
        }
        std::vector<std::byte> Decrypt(std::span<const std::byte> input) const {
            return cipher_mode_strategy_->Decrypt(*cipher_, input, padding_mode_);
        }
    private:
        std::unique_ptr<SymmetricCipher> cipher_;
        std::unique_ptr<CipherModeStrategy> cipher_mode_strategy_;
        PaddingMode padding_mode_;
    };

    SymmetricCipherContext::SymmetricCipherContext(
        std::unique_ptr<SymmetricCipher> cipher,
        std::span<const std::byte> key,
        CipherMode cipher_mode,
        PaddingMode padding_mode,
        std::span<const std::byte> iv,
        const std::vector<std::vector<std::byte>>& extra_parameters
    ) : symmetric_cipher_context_impl_(std::make_unique<SymmetricCipherContextImpl>(
            std::move(cipher),
            key,
            cipher_mode,
            padding_mode,
            iv,
            extra_parameters
        )
    ) {}

    SymmetricCipherContext::~SymmetricCipherContext() = default;

    SymmetricCipherContext::SymmetricCipherContext(SymmetricCipherContext&& rhs) noexcept = default;
    SymmetricCipherContext& SymmetricCipherContext::operator=(SymmetricCipherContext&& rhs) noexcept = default;

    std::future<void> SymmetricCipherContext::EncryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        std::vector input_copy(input.begin(), input.end());

        return std::async(
            std::launch::async,
            [this, input_copy = std::move(input_copy), &result]() {
                result = symmetric_cipher_context_impl_->Encrypt(input_copy);
            }
        );
    }

    std::future<void> SymmetricCipherContext::DecryptAsync(
        std::span<const std::byte> input,
        std::vector<std::byte>& result
    ) const {
        std::vector input_copy(input.begin(), input.end());

        return std::async(
            std::launch::async,
            [this, input_copy = std::move(input_copy), &result]() {
                result = symmetric_cipher_context_impl_->Decrypt(input_copy);
            }
        );
    }

    namespace {
        std::vector<std::byte> ReadFile(const std::filesystem::path& path) {
            std::ifstream ifs(path, std::ios::binary | std::ios::ate);

            if (!ifs) {
                throw std::runtime_error("unable to open input file");
            }

            const auto file_size = ifs.tellg();
            if (file_size < 0) {
                throw std::runtime_error("unable to get input file size");
            }

            std::vector<std::byte> data(file_size);

            ifs.seekg(0);
            ifs.read(
                reinterpret_cast<char*>(data.data()),
                data.size()
            );

            if (!ifs) {
                throw std::runtime_error("unable to read input file");
            }

            return data;
        }

        void WriteFile(const std::filesystem::path& path, std::span<const std::byte> data) {
            std::ofstream ofs(path, std::ios::binary);

            if (!ofs) {
                throw std::runtime_error("unable to open output file");
            }

            ofs.write(reinterpret_cast<const char*>(data.data()), data.size());

            if (!ofs) {
                throw std::runtime_error("unable to write to output file");
            }
        }
    }

    std::future<void> SymmetricCipherContext::EncryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(
            std::launch::async,
            [this, input_path, output_path]() {
                const auto input = ReadFile(input_path);
                const auto encrypted = symmetric_cipher_context_impl_->Encrypt(input);
                WriteFile(output_path, encrypted);
            }
        );
    }

    std::future<void> SymmetricCipherContext::DecryptFileAsync(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) const {
        return std::async(
            std::launch::async,
            [this, input_path, output_path]() {
                const auto input = ReadFile(input_path);
                const auto decrypted = symmetric_cipher_context_impl_->Decrypt(input);
                WriteFile(output_path, decrypted);
            }
        );
    }
}