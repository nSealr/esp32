#pragma once

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace nsealr {

class NsecDecodeError final : public std::runtime_error {
public:
    explicit NsecDecodeError(const std::string& message) : std::runtime_error(message) {}
};

using NsecSecretKey = std::array<std::uint8_t, 32>;

bool is_valid_nsec_secret_key(const NsecSecretKey& secret_key);
NsecSecretKey decode_nsec_secret_key(const std::string& nsec);
std::string decode_nsec_secret_key_hex(const std::string& nsec);
std::string encode_nsec_secret_key(const NsecSecretKey& secret_key);

}  // namespace nsealr
