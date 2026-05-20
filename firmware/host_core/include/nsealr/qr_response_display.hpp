#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "nsealr/limits.hpp"

namespace nsealr {

inline constexpr std::size_t kMaxQrResponseDisplayCycles = 16;

struct QrResponseDisplayFrame {
    std::string payload;
    std::size_t index = 1;
    std::size_t total = 1;
    bool animated = false;
};

class QrResponseDisplayIo {
public:
    virtual ~QrResponseDisplayIo() = default;

    virtual void show_response_qr_frame(const QrResponseDisplayFrame& frame) = 0;
};

struct QrResponseDisplayResult {
    std::vector<QrResponseDisplayFrame> frames;
};

std::vector<QrResponseDisplayFrame> build_qr_response_display_frames(
    const std::string& response_json,
    std::size_t animated_chunk_size_chars = kMaxAnimatedQrFramePayloadChars);

QrResponseDisplayResult run_qr_response_display_io(
    QrResponseDisplayIo& io,
    const std::string& response_json,
    std::size_t animated_chunk_size_chars = kMaxAnimatedQrFramePayloadChars,
    std::size_t animated_cycles = 3);

}  // namespace nsealr
