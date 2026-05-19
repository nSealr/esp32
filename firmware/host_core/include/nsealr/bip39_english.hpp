#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace nsealr {

constexpr std::size_t kBip39EnglishWordCount = 2048U;
constexpr std::size_t kMaxBip39MnemonicWords = 24U;

class Bip39Error final : public std::runtime_error {
public:
    explicit Bip39Error(const std::string& message) : std::runtime_error(message) {}
};

using Bip39WordIndexes = std::vector<std::uint16_t>;

[[nodiscard]] bool is_valid_bip39_word_count(std::size_t word_count);
[[nodiscard]] const char* bip39_english_word_at(std::uint16_t index);
[[nodiscard]] Bip39WordIndexes parse_bip39_english_mnemonic_indexes(std::string_view mnemonic);
[[nodiscard]] std::string bip39_english_mnemonic_from_indexes(const Bip39WordIndexes& indexes);
[[nodiscard]] std::vector<std::uint8_t> bip39_entropy_from_indexes(const Bip39WordIndexes& indexes);
void require_valid_bip39_checksum(const Bip39WordIndexes& indexes);

}  // namespace nsealr
