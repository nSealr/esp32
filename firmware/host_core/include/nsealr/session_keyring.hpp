#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "nsealr/bip39_english.hpp"
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
    std::array<std::uint16_t, kMaxBip39MnemonicWords> values{};
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
    StatelessSessionKeyring() = default;
    ~StatelessSessionKeyring() noexcept;
    StatelessSessionKeyring(const StatelessSessionKeyring&) = delete;
    StatelessSessionKeyring& operator=(const StatelessSessionKeyring&) = delete;
    StatelessSessionKeyring(StatelessSessionKeyring&&) = delete;
    StatelessSessionKeyring& operator=(StatelessSessionKeyring&&) = delete;

    void add_nsec(std::string label, const NsecSecretKey& secret_key);
    void add_bip39_seed(std::string label, Bip39WordIndexes word_indexes);
    void add_source(const SessionKeySource& source);
    void clear() noexcept;

    [[nodiscard]] bool empty() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] const SessionKeySource& source_at(std::size_t index) const;

private:
    std::array<SessionKeySource, kMaxStatelessSessionKeySources> sources_{};
    std::size_t size_ = 0;
};

}  // namespace nsealr
