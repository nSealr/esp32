#include "nsealr/session_keyring.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace nsealr {
namespace {

void require_valid_label(const std::string& label) {
    if (label.empty()) {
        throw SessionKeyringError("session key source label must not be empty");
    }
    if (label.size() > kMaxSessionKeySourceLabelLength) {
        throw SessionKeyringError("session key source label exceeds max length");
    }
}

void require_capacity(std::size_t size) {
    if (size >= kMaxStatelessSessionKeySources) {
        throw SessionKeyringError("stateless session keyring is full");
    }
}

void require_valid_seed_word_indexes(const Bip39WordIndexes& word_indexes) {
    if (!is_valid_bip39_word_count(word_indexes.size())) {
        throw SessionKeyringError("BIP-39 session seed must contain 12, 15, 18, 21, or 24 word indexes");
    }
    for (const std::uint16_t index : word_indexes) {
        if (index >= kBip39EnglishWordCount) {
            throw SessionKeyringError("BIP-39 session seed word index is outside the English wordlist");
        }
    }
}

template <typename T, std::size_t N>
void wipe_array(std::array<T, N>& values) noexcept {
    volatile T* data = values.data();
    for (std::size_t index = 0; index < values.size(); ++index) {
        data[index] = 0;
    }
}

}  // namespace

SessionKeySource::SessionKeySource(SessionKeySource&& other)
    : kind(other.kind),
      label(std::move(other.label)),
      nsec_secret_key(other.nsec_secret_key),
      bip39_word_indexes(other.bip39_word_indexes) {
    other.wipe();
}

SessionKeySource& SessionKeySource::operator=(const SessionKeySource& other) {
    if (this != &other) {
        wipe();
        kind = other.kind;
        label = other.label;
        nsec_secret_key = other.nsec_secret_key;
        bip39_word_indexes = other.bip39_word_indexes;
    }
    return *this;
}

SessionKeySource& SessionKeySource::operator=(SessionKeySource&& other) {
    if (this != &other) {
        wipe();
        kind = other.kind;
        label = std::move(other.label);
        nsec_secret_key = other.nsec_secret_key;
        bip39_word_indexes = other.bip39_word_indexes;
        other.wipe();
    }
    return *this;
}

SessionKeySource::~SessionKeySource() noexcept {
    wipe();
}

void SessionKeySource::wipe() noexcept {
    wipe_array(nsec_secret_key);
    wipe_array(bip39_word_indexes.values);
    bip39_word_indexes.count = 0;
    std::fill(label.begin(), label.end(), '\0');
    label.clear();
    kind = SessionKeySourceKind::NsecSecretKey;
}

StatelessSessionKeyring::~StatelessSessionKeyring() noexcept {
    clear();
}

void StatelessSessionKeyring::add_nsec(std::string label, const NsecSecretKey& secret_key) {
    require_valid_label(label);
    if (!is_valid_nsec_secret_key(secret_key)) {
        throw SessionKeyringError("NIP-19 nsec session source must be a valid secp256k1 scalar");
    }
    require_capacity(size_);
    SessionKeySource& source = sources_[size_++];
    source.kind = SessionKeySourceKind::NsecSecretKey;
    source.label = std::move(label);
    source.nsec_secret_key = secret_key;
    source.bip39_word_indexes = {};
}

void StatelessSessionKeyring::add_bip39_seed(std::string label, Bip39WordIndexes word_indexes) {
    require_valid_label(label);
    require_capacity(size_);
    require_valid_seed_word_indexes(word_indexes);
    SessionKeySource& source = sources_[size_++];
    source.kind = SessionKeySourceKind::Bip39WordIndexes;
    source.label = std::move(label);
    source.nsec_secret_key = {};
    source.bip39_word_indexes = {};
    source.bip39_word_indexes.count = word_indexes.size();
    std::copy(word_indexes.begin(), word_indexes.end(), source.bip39_word_indexes.values.begin());
}

void StatelessSessionKeyring::add_source(const SessionKeySource& source) {
    switch (source.kind) {
        case SessionKeySourceKind::NsecSecretKey:
            add_nsec(source.label, source.nsec_secret_key);
            return;
        case SessionKeySourceKind::Bip39WordIndexes:
            break;
    }

    Bip39WordIndexes word_indexes;
    word_indexes.reserve(source.bip39_word_indexes.count);
    for (std::size_t index = 0; index < source.bip39_word_indexes.count; ++index) {
        word_indexes.push_back(source.bip39_word_indexes.values[index]);
    }
    add_bip39_seed(source.label, std::move(word_indexes));
}

void StatelessSessionKeyring::clear() noexcept {
    for (std::size_t index = 0; index < size_; ++index) {
        sources_[index].wipe();
    }
    size_ = 0;
}

bool StatelessSessionKeyring::empty() const {
    return size_ == 0U;
}

std::size_t StatelessSessionKeyring::size() const {
    return size_;
}

const SessionKeySource& StatelessSessionKeyring::source_at(std::size_t index) const {
    if (index >= size_) {
        throw SessionKeyringError("session key source index is out of range");
    }
    return sources_[index];
}

}  // namespace nsealr
