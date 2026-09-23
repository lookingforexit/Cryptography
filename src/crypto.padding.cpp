module crypto.padding;

import std;

namespace crypto {
    std::vector<std::byte> AddPadding(
        std::span<const std::byte> data,
        std::size_t                block_size,
        PaddingMode                padding_mode
    ) {
        throw std::logic_error("not implemented");
    }

    std::vector<std::byte> RemovePadding(
        std::span<const std::byte> data,
        std::size_t                block_size,
        PaddingMode                padding_mode
    ) {
        throw std::logic_error("not implemented");
    }
}