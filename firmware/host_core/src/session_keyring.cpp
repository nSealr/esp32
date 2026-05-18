#include "nsealr/session_keyring.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>

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

void require_valid_seed_word_indexes(const SeedQrWordIndexes& word_indexes) {
    if (word_indexes.size() != 12U && word_indexes.size() != 24U) {
        throw SessionKeyringError("BIP-39 session seed must contain 12 or 24 word indexes");
    }
    for (const std::uint16_t index : word_indexes) {
        if (index > 2047U) {
            throw SessionKeyringError("BIP-39 session seed word index is outside the English wordlist");
        }
    }
}

void wipe_source(SessionKeySource& source) {
    std::fill(source.nsec_secret_key.begin(), source.nsec_secret_key.end(), 0U);
    std::fill(source.bip39_word_indexes.values.begin(), source.bip39_word_indexes.values.end(), 0U);
    source.bip39_word_indexes.count = 0;
    source.label.clear();
}

}  // namespace

void StatelessSessionKeyring::add_nsec(std::string label, const NsecSecretKey& secret_key) {
    require_valid_label(label);
    require_capacity(size_);
    SessionKeySource& source = sources_[size_++];
    source.kind = SessionKeySourceKind::NsecSecretKey;
    source.label = std::move(label);
    source.nsec_secret_key = secret_key;
    source.bip39_word_indexes = {};
}

void StatelessSessionKeyring::add_seedqr(std::string label, SeedQrWordIndexes word_indexes) {
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

void StatelessSessionKeyring::clear() {
    for (std::size_t index = 0; index < size_; ++index) {
        wipe_source(sources_[index]);
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
