module crypto.modes;

namespace crypto {
    namespace {
        void ValidateBlockSize(std::size_t block_size) {
            if (block_size == 0) {
                throw std::invalid_argument("invalid block size");
            }
        }

        void ValidateBlockAlignedData(
            std::span<const std::byte> data,
            std::size_t block_size,
            std::string_view mode_name
        ) {
            ValidateBlockSize(block_size);

            if (data.empty() || data.size() % block_size != 0) {
                throw std::invalid_argument(std::format("invalid data size for {} mode", mode_name));
            }
        }

        void ValidateIVSize(std::span<const std::byte> iv, std::size_t expected_size, std::string_view mode_name) {
            if (iv.size() != expected_size) {
                throw std::invalid_argument(std::format("invalid IV size for {} mode", mode_name));
            }
        }

        void ValidateOutputBlockSize(std::span<const std::byte> block, std::size_t block_size, std::string_view mode_name) {
            if (block.size() != block_size) {
                throw std::logic_error(std::format("invalid output block size for {} mode", mode_name));
            }
        }

        std::vector<std::byte> XORBlocks(std::span<const std::byte> lhs, std::span<const std::byte> rhs) {
            if (lhs.size() != rhs.size()) {
                throw std::invalid_argument("blocks have different sizes");
            }

            std::vector<std::byte> output(lhs.size());
            for (std::size_t i = 0; i < output.size(); ++i) {
                output[i] = lhs[i] ^ rhs[i];
            }

            return output;
        }

        void AppendBlock(std::vector<std::byte>& vector, std::span<const std::byte> block) {
            vector.insert(vector.end(), block.begin(), block.end());
        }

        class ECBMode final : public CipherModeStrategy {
        public:
            ~ECBMode() override = default;

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto encrypted = cipher.EncryptBlock(block);
                    ValidateOutputBlockSize(encrypted, block_size, "ecb");
                    AppendBlock(result, encrypted);
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ecb");

                std::vector<std::byte> result;
                result.reserve(data.size());

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto cipher_block = std::span{data.data() + offset, block_size};
                    const auto decrypted = cipher.DecryptBlock(cipher_block);
                    ValidateOutputBlockSize(decrypted, block_size, "ecb");
                    AppendBlock(result, decrypted);
                }

                return RemovePadding(result, block_size, padding_mode);
            }
        };

        class CBCMode final : public CipherModeStrategy {
        public:
            ~CBCMode() override = default;

            explicit CBCMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "cbc");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto encrypted = cipher.EncryptBlock(XORBlocks(block, prev_cipher_block));
                    ValidateOutputBlockSize(encrypted, block_size, "cbc");
                    AppendBlock(result, encrypted);

                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "cbc");
                ValidateIVSize(iv_, block_size, "cbc");

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto cipher_block = std::span{data.data() + offset, block_size};
                    const auto decrypted = cipher.DecryptBlock(cipher_block);
                    const auto block = XORBlocks(decrypted, prev_cipher_block);
                    AppendBlock(result, block);

                    prev_cipher_block.assign(cipher_block.begin(), cipher_block.end());
                }

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class PCBCMode final : public CipherModeStrategy {
        public:
            ~PCBCMode() override = default;

            explicit PCBCMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "pcbc");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_block = std::vector(block_size, std::byte{0});
                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto encrypted = cipher.EncryptBlock(XORBlocks(XORBlocks(block, prev_block), prev_cipher_block));
                    ValidateOutputBlockSize(encrypted, block_size, "pcbc");
                    AppendBlock(result, encrypted);

                    prev_block.assign(block.begin(), block.end());
                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "pcbc");
                ValidateIVSize(iv_, block_size, "pcbc");

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto prev_block = std::vector(block_size, std::byte{0});
                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto cipher_block = std::span{data.data() + offset, block_size};
                    const auto decrypted = cipher.DecryptBlock(cipher_block);
                    const auto block = XORBlocks(XORBlocks(decrypted, prev_block), prev_cipher_block);
                    AppendBlock(result, block);

                    prev_block = block;
                    prev_cipher_block.assign(cipher_block.begin(), cipher_block.end());
                }

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class CFBMode final : public CipherModeStrategy {
        public:
            ~CFBMode() override = default;

            explicit CFBMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                ValidateIVSize(iv_, block_size, "cfb");

                const auto padded = AddPadding(data, block_size, padding_mode);

                std::vector<std::byte> result;
                result.reserve(padded.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < padded.size(); offset += block_size) {
                    const auto block = std::span{padded.data() + offset, block_size};
                    const auto gamma = cipher.EncryptBlock(prev_cipher_block);
                    ValidateOutputBlockSize(gamma, block_size, "cfb");
                    const auto encrypted = XORBlocks(block, gamma);
                    AppendBlock(result, encrypted);

                    prev_cipher_block = encrypted;
                }

                return result;
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "cfb");
                ValidateIVSize(iv_, block_size, "cfb");

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto prev_cipher_block = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto cipher_block = std::span{data.data() + offset, block_size};
                    const auto gamma = cipher.EncryptBlock(prev_cipher_block);
                    ValidateOutputBlockSize(gamma, block_size, "cfb");
                    const auto decrypted = XORBlocks(cipher_block, gamma);
                    AppendBlock(result, decrypted);

                    prev_cipher_block.assign(cipher_block.begin(), cipher_block.end());
                }

                return RemovePadding(result, block_size, padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class OFBMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(const SymmetricCipher& cipher, std::span<const std::byte> data) const {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ofb");
                ValidateIVSize(iv_, block_size, "ofb");

                std::vector<std::byte> result;
                result.reserve(data.size());

                auto gamma = iv_;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    gamma = cipher.EncryptBlock(gamma);
                    ValidateOutputBlockSize(gamma, block_size, "ofb");
                    const auto block = std::span{data.data() + offset, block_size};
                    const auto new_block = XORBlocks(block, gamma);
                    AppendBlock(result, new_block);
                }

                return result;
            }

        public:
            ~OFBMode() override = default;

            explicit OFBMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class CTRMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data
            ) const {
                const auto block_size = cipher.BlockSize();
                ValidateBlockAlignedData(data, block_size, "ctr");
                ValidateIVSize(iv_, block_size, "ctr");

                std::vector<std::byte> result;
                result.reserve(data.size());

                std::uint64_t counter = 0;

                for (std::size_t offset = 0; offset < data.size(); offset += block_size, ++counter) {
                    std::vector counter_block(iv_.begin(), iv_.end());

                    for (std::size_t i = counter_block.size(), value = counter; i > 0 && value != 0; --i) {
                        const auto index = i - 1;

                        const auto sum =
                            static_cast<unsigned>(counter_block[index]) +
                            static_cast<unsigned>(value & 0xFF);

                        counter_block[index] = static_cast<std::byte>(sum & 0xFF);
                        value = (value >> 8) + (sum >> 8);
                    }

                    const auto block = std::span{data.data() + offset, block_size};
                    const auto gamma = cipher.EncryptBlock(counter_block);

                    ValidateOutputBlockSize(gamma, block_size, "ctr");
                    AppendBlock(result, XORBlocks(block, gamma));
                }

                return result;
            }

        public:
            ~CTRMode() override = default;

            explicit CTRMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };

        class RandomDeltaMode final : public CipherModeStrategy {
        private:
            [[nodiscard]]
            std::vector<std::byte> TransformBlocks(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data
            ) const {
                const auto block_size = cipher.BlockSize();

                ValidateBlockAlignedData(data, block_size, "random delta");
                ValidateIVSize(iv_, block_size, "random delta");

                if (block_size & 1) {
                    throw std::invalid_argument("random delta requires even block size");
                }

                std::vector<std::byte> result;
                result.reserve(data.size());

                std::vector state(iv_.begin(), iv_.end());
                const std::vector delta(
                    iv_.begin() + static_cast<std::ptrdiff_t>(block_size >> 1),
                    iv_.end()
                );

                for (std::size_t offset = 0; offset < data.size(); offset += block_size) {
                    const auto block = std::span{data.data() + offset, block_size};
                    const auto gamma = cipher.EncryptBlock(state);

                    ValidateOutputBlockSize(gamma, block_size, "random delta");
                    AppendBlock(result, XORBlocks(block, gamma));

                    unsigned carry = 0;

                    for (std::size_t i = delta.size(); i > 0; --i) {
                        const auto state_index = state.size() - (delta.size() - i) - 1;
                        const auto delta_index = i - 1;

                        const auto sum =
                            static_cast<unsigned>(state[state_index]) +
                            static_cast<unsigned>(delta[delta_index]) +
                            carry;

                        state[state_index] = static_cast<std::byte>(sum & 0xFF);
                        carry = sum >> 8;
                    }

                    for (std::size_t i = state.size() - delta.size(); i > 0 && carry != 0; --i) {
                        const auto index = i - 1;
                        const auto sum = static_cast<unsigned>(state[index]) + carry;

                        state[index] = static_cast<std::byte>(sum & 0xFF);
                        carry = sum >> 8;
                    }
                }

                return result;
            }

        public:
            ~RandomDeltaMode() override = default;

            explicit RandomDeltaMode(std::span<const std::byte> iv) : iv_(iv.begin(), iv.end()) {}

            [[nodiscard]]
            std::vector<std::byte> Encrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto block_size = cipher.BlockSize();
                ValidateBlockSize(block_size);
                const auto padded = AddPadding(data, block_size, padding_mode);
                return TransformBlocks(cipher, padded);
            }

            [[nodiscard]]
            std::vector<std::byte> Decrypt(
                const SymmetricCipher& cipher,
                std::span<const std::byte> data,
                PaddingMode padding_mode
            ) const override {
                const auto decrypted = TransformBlocks(cipher, data);
                return RemovePadding(decrypted, cipher.BlockSize(), padding_mode);
            }

        private:
            std::vector<std::byte> iv_;
        };
    }

    CipherModeStrategy::~CipherModeStrategy() = default;

    namespace {
        void ValidateNoIV(std::span<const std::byte> iv, std::string_view mode_name) {
            if (!iv.empty()) {
                throw std::invalid_argument(std::format("{} mode does not use IV", mode_name));
            }
        }

        void ValidateNoExtraParameters(
            const std::vector<std::vector<std::byte>>& extra_parameters,
            std::string_view mode_name
        ) {
            if (!extra_parameters.empty()) {
                throw std::invalid_argument(std::format("{} mode does not support extra parameters", mode_name));
            }
        }
    }

    std::unique_ptr<CipherModeStrategy> MakeCipherModeStrategy(
        CipherMode cipher_mode,
        std::span<const std::byte> iv,
        const std::vector<std::vector<std::byte>>& extra_parameters
    ) {
        switch (cipher_mode) {
            case CipherMode::ECB:
                ValidateNoIV(iv, "ecb");
                ValidateNoExtraParameters(extra_parameters, "ecb");
                return std::make_unique<ECBMode>();
            case CipherMode::CBC:
                ValidateNoExtraParameters(extra_parameters, "cbc");
                return std::make_unique<CBCMode>(iv);
            case CipherMode::PCBC:
                ValidateNoExtraParameters(extra_parameters, "pcbc");
                return std::make_unique<PCBCMode>(iv);
            case CipherMode::CFB:
                ValidateNoExtraParameters(extra_parameters, "cfb");
                return std::make_unique<CFBMode>(iv);
            case CipherMode::OFB:
                ValidateNoExtraParameters(extra_parameters, "ofb");
                return std::make_unique<OFBMode>(iv);
            case CipherMode::CTR:
                ValidateNoExtraParameters(extra_parameters, "ctr");
                return std::make_unique<CTRMode>(iv);
            case CipherMode::RandomDelta:
                ValidateNoExtraParameters(extra_parameters, "random delta");
                return std::make_unique<RandomDeltaMode>(iv);
        }

        throw std::invalid_argument("invalid cipher mode");
    }
}
