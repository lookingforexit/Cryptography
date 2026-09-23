export module crypto.modes;

export namespace crypto {
    enum class CipherMode {
        ECB = 0,
        CBC = 1,
        PCBC = 2,
        CFB = 3,
        OFB = 4,
        CTR = 5,
        RandomDelta = 6,
    };
}