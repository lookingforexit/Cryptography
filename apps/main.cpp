import std;
import crypto.context;
import crypto.padding;
import crypto.modes;
import crypto.des;


namespace {
    std::vector<std::byte> GenerateRandomBytes(std::size_t bytes_size) {
        std::vector<std::byte> bytes(bytes_size);

        std::random_device random_device;
        std::mt19937_64 generator(random_device());
        std::uniform_int_distribution distribution(0, std::numeric_limits<int>::max());

        for (auto& byte : bytes) {
            byte = static_cast<std::byte>(distribution(generator));
        }

        return bytes;
    }

    void DESDemo(
        crypto::PaddingMode padding_mode,
        crypto::CipherMode cipher_mode,
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        std::span<const std::byte> input
    ) {
        const crypto::SymmetricCipherContext context(
            std::make_unique<crypto::DES>(),
            key,
            cipher_mode,
            padding_mode,
            iv
        );

        std::vector<std::byte> encrypted;
        context.EncryptAsync(input, encrypted).get();

        std::vector<std::byte> decrypted;
        context.DecryptAsync(encrypted, decrypted).get();

        if (!std::ranges::equal(input, decrypted)) {
            throw std::runtime_error("input != D(E(input))");
        }
    }

    void DESDemo(
        crypto::PaddingMode padding_mode,
        crypto::CipherMode cipher_mode,
        std::span<const std::byte> key,
        std::span<const std::byte> iv,
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_path
    ) {
        const crypto::SymmetricCipherContext context(
            std::make_unique<crypto::DES>(),
            key,
            cipher_mode,
            padding_mode,
            iv
        );

        std::ifstream input_file(input_path, std::ios::binary | std::ios::ate);
        if (!input_file.is_open()) {
            throw std::runtime_error("failed to open input file");
        }
        const std::streamsize input_file_size = input_file.tellg();
        input_file.seekg(0, std::ios::beg);
        std::vector<char> buffer_start(input_file_size);
        if (!input_file.read(buffer_start.data(), input_file_size)) {
            throw std::runtime_error("failed to read input file");
        }
        input_file.close();

        context.EncryptFileAsync(input_path, output_path).get();
        context.DecryptFileAsync(output_path, input_path).get();

        std::ifstream output_file(input_path, std::ios::binary | std::ios::ate);
        if (!output_file.is_open()) {
            throw std::runtime_error("failed to open output file");
        }
        const std::streamsize output_file_size = output_file.tellg();
        output_file.seekg(0, std::ios::beg);
        std::vector<char> buffer_end(output_file_size);
        if (!output_file.read(buffer_end.data(), output_file_size)) {
            throw std::runtime_error("failed to read output file");
        }

        if (buffer_end != buffer_start) {
            throw std::runtime_error("file != D(E(file))");
        }

        output_file.close();
    }
}

int main() {
    // DES demonstration
    std::vector<std::byte> key = GenerateRandomBytes(8);
    std::vector<std::byte> iv = GenerateRandomBytes(8);
    std::vector<std::byte> input = GenerateRandomBytes(5251);
    input.push_back(std::byte{1});

    constexpr std::array padding_modes = {
        crypto::PaddingMode::Zeros,
        crypto::PaddingMode::ANSIX923,
        crypto::PaddingMode::PKCS7,
        crypto::PaddingMode::ISO10126,
    };
    constexpr std::array cipher_modes = {
        crypto::CipherMode::CBC,
        crypto::CipherMode::PCBC,
        crypto::CipherMode::CFB,
        crypto::CipherMode::OFB,
        crypto::CipherMode::CTR,
        crypto::CipherMode::RandomDelta,
    };

    for (const auto& padding_mode : padding_modes) {
        DESDemo(padding_mode, crypto::CipherMode::ECB, key, {}, input);
    }
    for (const auto& padding_mode : padding_modes) {
        for (const auto& cipher_mode : cipher_modes) {
            DESDemo(padding_mode, cipher_mode, key, iv, input);
        }
    }

    const std::filesystem::path temp_file("assets/temp.txt");
    const std::filesystem::path file1("assets/text.txt");
    const std::filesystem::path file2("assets/song.mp3");
    const std::filesystem::path file3("assets/homyak.jpeg");

    for (const auto& padding_mode : padding_modes) {
        DESDemo(padding_mode, crypto::CipherMode::ECB, key, {}, file1, temp_file);
        //DESDemo(padding_mode, crypto::CipherMode::ECB, key, {}, file2, temp_file);
        //DESDemo(padding_mode, crypto::CipherMode::ECB, key, {}, file3, temp_file);
    }
    for (const auto& padding_mode : padding_modes) {
        for (const auto& cipher_mode : cipher_modes) {
            DESDemo(padding_mode, cipher_mode, key, iv, file1, temp_file);
            //DESDemo(padding_mode, cipher_mode, key, iv, file2, temp_file);
            //DESDemo(padding_mode, cipher_mode, key, iv, file3, temp_file);
        }
    }

    std::cout << "DES demonstration finished" << std::endl;


    return 0;
}
