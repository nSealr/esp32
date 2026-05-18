#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "nsealr/bip39_english.hpp"

namespace nsealr {

class SeedQrError final : public std::runtime_error {
public:
    explicit SeedQrError(const std::string& message) : std::runtime_error(message) {}
};

using SeedQrWordIndexes = Bip39WordIndexes;

SeedQrWordIndexes decode_standard_seedqr_indexes(const std::string& digits);
SeedQrWordIndexes decode_compact_seedqr_indexes(const std::vector<std::uint8_t>& entropy);

}  // namespace nsealr
