#pragma once

#include <stdexcept>
#include <string>

namespace nostrseal {

struct QrEnvelope {
    std::string payload_base64url;
    std::string payload_json;
};

struct QrSigningRequest {
    int version;
    std::string request_id;
    std::string method;
    bool has_params;
};

class QrEnvelopeError final : public std::runtime_error {
public:
    explicit QrEnvelopeError(const std::string& message) : std::runtime_error(message) {}
};

QrEnvelope decode_qr_envelope(const std::string& envelope);
QrSigningRequest parse_qr_signing_request(const QrEnvelope& envelope);

}  // namespace nostrseal
