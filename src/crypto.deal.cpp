module crypto.deal;

import std;
import crypto.cipher;
import crypto.des;

namespace crypto {
    namespace {
        inline constexpr std::size_t kDEALBlockSize = 16;
        inline constexpr std::size_t kDEALKeySize = 16;
        inline constexpr std::size_t kDEALRoundKeySize = 8;
        inline constexpr std::size_t kDEALRoundCount = 6;

        inline constexpr std::array<std::array<std::byte, 8>, 4> kDEALConstants{
            {
            {
                    std::byte{0x80}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                },
            {
                    std::byte{0x40}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                },
            {
                    std::byte{0x20}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                },
            {
                    std::byte{0x10}, std::byte{0}, std::byte{0}, std::byte{0},
                    std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
                },
            }
        };
        inline constexpr std::array kDEALScheduleKey = {
            std::byte{0x01}, std::byte{0x23}, std::byte{0x45}, std::byte{0x67},
            std::byte{0x89}, std::byte{0xAB}, std::byte{0xCD}, std::byte{0xEF},
        };


        void ValidateDEALBlock(std::span<const std::byte> block) {
            if (block.size() != kDEALBlockSize) {
                throw std::invalid_argument("invalid DEAL block size");
            }
        }

        void ValidateDEALKey(std::span<const std::byte> key) {
            if (key.size() != kDEALKeySize) {
                throw std::invalid_argument("invalid DEAL key size");
            }
        }

        void ValidateDEALRoundKey(std::span<const std::byte> key) {
            if (key.size() != kDEALRoundKeySize) {
                throw std::invalid_argument("invalid DEAL round key size");
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

        std::vector<std::byte> DESEncrypt(std::span<const std::byte> key, std::span<const std::byte> block) {
            DES des;
            des.SetKey(key);

            return des.EncryptBlock(block);
        }

        class DEALKeyExpansion final : public KeyExpansion {
        public:
            [[nodiscard]]
            std::vector<std::vector<std::byte>> GenerateRoundKeys(std::span<const std::byte> input_key) const override {
                ValidateDEALKey(input_key);

                std::vector k0(input_key.begin(), input_key.begin() + (kDEALBlockSize >> 1));
                std::vector k1(input_key.begin() + (kDEALBlockSize >> 1), input_key.end());

                std::vector<std::vector<std::byte>> round_keys;
                round_keys.reserve(kDEALRoundCount);

                const auto r0 = DESEncrypt(kDEALScheduleKey, k0);
                const auto r1 = DESEncrypt(kDEALScheduleKey, XORBlocks(k1, r0));
                const auto r2 = DESEncrypt(kDEALScheduleKey, XORBlocks(XORBlocks(k0, kDEALConstants[0]), r1));
                const auto r3 = DESEncrypt(kDEALScheduleKey, XORBlocks(XORBlocks(k1, kDEALConstants[1]), r2));
                const auto r4 = DESEncrypt(kDEALScheduleKey, XORBlocks(XORBlocks(k0, kDEALConstants[2]), r3));
                const auto r5 = DESEncrypt(kDEALScheduleKey, XORBlocks(XORBlocks(k1, kDEALConstants[3]), r4));

                round_keys.push_back(r0);
                round_keys.push_back(r1);
                round_keys.push_back(r2);
                round_keys.push_back(r3);
                round_keys.push_back(r4);
                round_keys.push_back(r5);

                return round_keys;
            }
        };

        class DEALRoundTransformation final : public RoundTransformation {
        public:
            [[nodiscard]]
            std::vector<std::byte> Transform(
                std::span<const std::byte> input_block,
                std::span<const std::byte> round_key
            ) const override {
                if (input_block.size() != kDEALBlockSize >> 1) {
                    throw std::invalid_argument("invalid DEAL input block size");
                }
                ValidateDEALRoundKey(round_key);

                DES des;
                des.SetKey(round_key);

                return des.EncryptBlock(input_block);
            }
        };
    }

    class DEAL::DEALImpl {
    public:
        DEALImpl() : feistel_network_(
            std::make_shared<DEALKeyExpansion>(),
            std::make_shared<DEALRoundTransformation>(),
            kDEALBlockSize
        ) {}

        [[nodiscard]]
        std::vector<std::byte> EncryptBlock(std::span<const std::byte> block) const {
            ValidateDEALBlock(block);

            return feistel_network_.EncryptBlock(block);
        }

        [[nodiscard]]
        std::vector<std::byte> DecryptBlock(std::span<const std::byte> block) const {
            ValidateDEALBlock(block);

            return feistel_network_.DecryptBlock(block);
        }

        void SetKey(std::span<const std::byte> key) {
            feistel_network_.SetKey(key);
        }

        static std::size_t BlockSize() {
            return kDEALBlockSize;
        }

    private:
        FeistelNetwork feistel_network_;
    };

    DEAL::~DEAL() = default;

    DEAL::DEAL() : deal_impl_(std::make_unique<DEALImpl>()) {}

    DEAL::DEAL(DEAL&& rhs) noexcept = default;
    DEAL& DEAL::operator=(DEAL&& rhs) noexcept = default;

    std::vector<std::byte> DEAL::EncryptBlock(std::span<const std::byte> block) const {
        return deal_impl_->EncryptBlock(block);
    }

    std::vector<std::byte> DEAL::DecryptBlock(std::span<const std::byte> block) const {
        return deal_impl_->DecryptBlock(block);
    }

    void DEAL::SetKey(std::span<const std::byte> key) {
        deal_impl_->SetKey(key);
    }

    std::size_t DEAL::BlockSize() const {
        return deal_impl_->BlockSize();
    }
}
