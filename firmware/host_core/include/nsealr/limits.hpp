#pragma once

#include <cstddef>
#include <cstdint>

namespace nsealr {

inline constexpr std::size_t kMaxRequestIdLength = 128;
inline constexpr std::size_t kMaxDecodedRequestJsonBytes = 704;
inline constexpr std::size_t kMaxStaticQrDecodedJsonBytes = 704;
inline constexpr std::size_t kMaxAnimatedQrDecodedJsonBytes = 4096;
inline constexpr std::size_t kMaxAnimatedQrFramePayloadChars = 256;
inline constexpr std::size_t kMaxAnimatedQrFrameCount = 64;
inline constexpr std::size_t kMaxSerialFrameBytes = 1024;
inline constexpr std::size_t kMaxContentUtf8Bytes = 512;
inline constexpr std::size_t kMaxTagCount = 16;
inline constexpr std::size_t kMaxTagFieldsPerTag = 8;
inline constexpr std::size_t kMaxTagFieldUtf8Bytes = 64;
inline constexpr std::size_t kMaxTotalTagUtf8Bytes = 4096;
inline constexpr std::uint64_t kMaxSafeInteger = 9007199254740991ULL;

}  // namespace nsealr
