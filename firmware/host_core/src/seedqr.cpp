#include "nsealr/seedqr.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "nsealr/sha256.hpp"

namespace nsealr {
namespace {

bool is_ascii_whitespace(char ch) {
    return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
}

std::size_t checksum_bits_for_word_count(std::size_t word_count) {
    if (word_count == 12U) {
        return 4U;
    }
    if (word_count == 24U) {
        return 8U;
    }
    throw SeedQrError("SeedQR word count must be 12 or 24");
}

std::size_t checksum_bits_for_entropy_size(std::size_t entropy_size) {
    if (entropy_size == 16U) {
        return 4U;
    }
    if (entropy_size == 32U) {
        return 8U;
    }
    throw SeedQrError("CompactSeedQR byte length must be 16 or 32");
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    throw SeedQrError("SeedQR checksum digest is invalid");
}

int digest_bit(const std::string& digest_hex, std::size_t bit_index) {
    const int nibble = hex_nibble(digest_hex[bit_index / 4U]);
    return (nibble >> static_cast<int>(3U - (bit_index % 4U))) & 1;
}

int index_bit(const SeedQrWordIndexes& indexes, std::size_t bit_index) {
    const std::size_t word = bit_index / 11U;
    const std::size_t bit = bit_index % 11U;
    return (indexes[word] >> static_cast<unsigned>(10U - bit)) & 1U;
}

std::vector<std::uint8_t> entropy_from_indexes(const SeedQrWordIndexes& indexes) {
    const std::size_t checksum_bits = checksum_bits_for_word_count(indexes.size());
    const std::size_t entropy_bits = (indexes.size() * 11U) - checksum_bits;
    std::vector<std::uint8_t> entropy(entropy_bits / 8U, 0);
    for (std::size_t bit_index = 0; bit_index < entropy_bits; ++bit_index) {
        if (index_bit(indexes, bit_index) != 0) {
            entropy[bit_index / 8U] |= static_cast<std::uint8_t>(1U << static_cast<unsigned>(7U - (bit_index % 8U)));
        }
    }
    return entropy;
}

void require_valid_bip39_checksum(const SeedQrWordIndexes& indexes) {
    const std::size_t checksum_bits = checksum_bits_for_word_count(indexes.size());
    const std::size_t entropy_bits = (indexes.size() * 11U) - checksum_bits;
    const std::vector<std::uint8_t> entropy = entropy_from_indexes(indexes);
    const std::string entropy_string(reinterpret_cast<const char*>(entropy.data()), entropy.size());
    const std::string digest = sha256_hex(std::string_view(entropy_string.data(), entropy_string.size()));
    for (std::size_t bit_index = 0; bit_index < checksum_bits; ++bit_index) {
        const int actual = index_bit(indexes, entropy_bits + bit_index);
        const int expected = digest_bit(digest, bit_index);
        if (actual != expected) {
            throw SeedQrError("SeedQR BIP-39 checksum is invalid");
        }
    }
}

int entropy_bit(const std::vector<std::uint8_t>& entropy, std::size_t bit_index) {
    return (entropy[bit_index / 8U] >> static_cast<unsigned>(7U - (bit_index % 8U))) & 1U;
}

}  // namespace

SeedQrWordIndexes decode_standard_seedqr_indexes(const std::string& digits) {
    std::string normalized;
    normalized.reserve(digits.size());
    for (const char ch : digits) {
        if (is_ascii_whitespace(ch)) {
            continue;
        }
        if (ch < '0' || ch > '9') {
            throw SeedQrError("Standard SeedQR digit stream must contain only digits");
        }
        normalized.push_back(ch);
    }
    if (normalized.empty()) {
        throw SeedQrError("Standard SeedQR digit stream must not be empty");
    }
    if ((normalized.size() % 4U) != 0U) {
        throw SeedQrError("Standard SeedQR digit stream length must contain four digits per word");
    }
    const std::size_t word_count = normalized.size() / 4U;
    (void)checksum_bits_for_word_count(word_count);

    SeedQrWordIndexes indexes;
    indexes.reserve(word_count);
    for (std::size_t offset = 0; offset < normalized.size(); offset += 4U) {
        const std::uint16_t index = static_cast<std::uint16_t>(
            ((normalized[offset] - '0') * 1000) + ((normalized[offset + 1U] - '0') * 100) +
            ((normalized[offset + 2U] - '0') * 10) + (normalized[offset + 3U] - '0'));
        if (index > 2047U) {
            throw SeedQrError("Standard SeedQR word index is outside the BIP-39 English wordlist");
        }
        indexes.push_back(index);
    }
    require_valid_bip39_checksum(indexes);
    return indexes;
}

SeedQrWordIndexes decode_compact_seedqr_indexes(const std::vector<std::uint8_t>& entropy) {
    const std::size_t checksum_bits = checksum_bits_for_entropy_size(entropy.size());
    const std::size_t entropy_bits = entropy.size() * 8U;
    const std::size_t total_bits = entropy_bits + checksum_bits;
    const std::size_t word_count = total_bits / 11U;
    const std::string entropy_string(reinterpret_cast<const char*>(entropy.data()), entropy.size());
    const std::string digest = sha256_hex(std::string_view(entropy_string.data(), entropy_string.size()));

    SeedQrWordIndexes indexes;
    indexes.reserve(word_count);
    for (std::size_t word = 0; word < word_count; ++word) {
        std::uint16_t value = 0;
        for (std::size_t bit = 0; bit < 11U; ++bit) {
            const std::size_t global_bit = (word * 11U) + bit;
            const int bit_value = global_bit < entropy_bits
                                      ? entropy_bit(entropy, global_bit)
                                      : digest_bit(digest, global_bit - entropy_bits);
            value = static_cast<std::uint16_t>((value << 1U) | static_cast<std::uint16_t>(bit_value));
        }
        indexes.push_back(value);
    }
    return indexes;
}

}  // namespace nsealr
