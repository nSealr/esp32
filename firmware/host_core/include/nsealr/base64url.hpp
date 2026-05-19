#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace nsealr {

enum class Base64UrlErrorCode {
    InvalidCharacter,
    InvalidTrailingBits,
};

class Base64UrlError : public std::runtime_error {
public:
    Base64UrlError(Base64UrlErrorCode code, const char* message);

    Base64UrlErrorCode code() const noexcept;

private:
    Base64UrlErrorCode code_;
};

bool is_base64url_payload(std::string_view value);
std::string encode_base64url(std::string_view value);
std::string decode_base64url(std::string_view payload);

}  // namespace nsealr
