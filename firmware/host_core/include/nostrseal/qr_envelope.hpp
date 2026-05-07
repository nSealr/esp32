#pragma once

#include <stdexcept>
#include <string>

namespace nostrseal {

struct QrEnvelope {
    std::string payload_base64url;
    std::string payload_json;
};

class QrEnvelopeError final : public std::runtime_error {
public:
    explicit QrEnvelopeError(const std::string& message) : std::runtime_error(message) {}
};

QrEnvelope decode_qr_envelope(const std::string& envelope);

}  // namespace nostrseal
