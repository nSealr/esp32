#include "nsealr/qr_response_display.hpp"

#include <stdexcept>
#include <utility>

#include "nsealr/qr_envelope.hpp"

namespace nsealr {
namespace {

std::vector<QrResponseDisplayFrame> wrap_static_response_frame(const std::string& payload) {
    return std::vector<QrResponseDisplayFrame>{QrResponseDisplayFrame{
        payload,
        1U,
        1U,
        false,
    }};
}

std::vector<QrResponseDisplayFrame> wrap_animated_response_frames(std::vector<std::string> payloads) {
    std::vector<QrResponseDisplayFrame> frames;
    frames.reserve(payloads.size());
    const std::size_t total = payloads.size();
    for (std::size_t offset = 0; offset < payloads.size(); ++offset) {
        frames.push_back(QrResponseDisplayFrame{
            std::move(payloads[offset]),
            offset + 1U,
            total,
            true,
        });
    }
    return frames;
}

}  // namespace

std::vector<QrResponseDisplayFrame> build_qr_response_display_frames(
    const std::string& response_json,
    std::size_t animated_chunk_size_chars) {
    if (response_json.size() <= kMaxStaticQrDecodedJsonBytes) {
        return wrap_static_response_frame(encode_qr_envelope_json(response_json));
    }
    return wrap_animated_response_frames(encode_animated_qr_envelope_json(response_json, animated_chunk_size_chars));
}

QrResponseDisplayResult run_qr_response_display_io(
    QrResponseDisplayIo& io,
    const std::string& response_json,
    std::size_t animated_chunk_size_chars,
    std::size_t animated_cycles) {
    if (animated_cycles == 0U) {
        throw std::invalid_argument("QR response display animated cycles must be non-zero");
    }
    if (animated_cycles > kMaxQrResponseDisplayCycles) {
        throw std::invalid_argument("QR response display animated cycles exceed max_qr_response_display_cycles");
    }

    const std::vector<QrResponseDisplayFrame> frames =
        build_qr_response_display_frames(response_json, animated_chunk_size_chars);
    const std::size_t cycles = frames.size() > 1U ? animated_cycles : 1U;
    std::vector<QrResponseDisplayFrame> displayed;
    displayed.reserve(frames.size() * cycles);
    for (std::size_t cycle = 0; cycle < cycles; ++cycle) {
        for (const QrResponseDisplayFrame& frame : frames) {
            io.show_response_qr_frame(frame);
            displayed.push_back(frame);
        }
    }
    return QrResponseDisplayResult{std::move(displayed)};
}

}  // namespace nsealr
