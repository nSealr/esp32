#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "nsealr/nip19_nsec.hpp"
#include "nsealr/seedqr.hpp"

namespace nsealr {

constexpr std::size_t kMaxStatelessSessionKeySources = 8U;
constexpr std::size_t kMaxSessionKeySourceLabelLength = 64U;

class SessionKeyringError final : public std::runtime_error {
public:
    explicit SessionKeyringError(const std::string& message) : std::runtime_error(message) {}
};

enum class SessionKeySourceKind {
    NsecSecretKey,
    Bip39WordIndexes,
};

struct SessionSeedWordIndexes {
    std::array<std::uint16_t, 24> values{};
    std::size_t count = 0;
};

struct SessionKeySource {
    SessionKeySourceKind kind = SessionKeySourceKind::NsecSecretKey;
    std::string label;
    NsecSecretKey nsec_secret_key{};
    SessionSeedWordIndexes bip39_word_indexes;
};

class StatelessSessionKeyring {
public:
    void add_nsec(std::string label, const NsecSecretKey& secret_key);
    void add_seedqr(std::string label, SeedQrWordIndexes word_indexes);
    void clear();

    [[nodiscard]] bool empty() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] const SessionKeySource& source_at(std::size_t index) const;

private:
    std::array<SessionKeySource, kMaxStatelessSessionKeySources> sources_{};
    std::size_t size_ = 0;
};

}  // namespace nsealr
