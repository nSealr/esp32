#include "nostrseal/device_protocol.hpp"

#include "nostrseal/serial_frame.hpp"
#include "transport_vector.hpp"

namespace nostrseal {

std::string handle_serial_frame(const std::string& line) {
    const SerialFrame request = decode_serial_frame(line);
    if (request.type == FrameType::Request &&
        request.payload_base64url == test_vectors::kCapabilityRequestPayloadBase64Url) {
        return encode_serial_frame(SerialFrame{FrameType::Response, test_vectors::kCapabilityResponsePayloadBase64Url});
    }
    if (request.type == FrameType::Request &&
        request.payload_base64url == test_vectors::kSignEventRequestPayloadBase64Url) {
        return encode_serial_frame(
            SerialFrame{FrameType::Response, test_vectors::kSignEventDisabledResponsePayloadBase64Url});
    }
    return encode_serial_frame(SerialFrame{FrameType::Error, "eyJlcnJvciI6InVuc3VwcG9ydGVkX3JlcXVlc3QifQ"});
}

}  // namespace nostrseal
