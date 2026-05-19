#include "nsealr/session_source_qr.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include "nsealr/bip39_english.hpp"
#include "nsealr/nip19_nsec.hpp"
#include "nsealr/seedqr.hpp"

namespace nsealr {
namespace {

bool is_ascii_whitespace(char ch) {
    return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t';
}

std::string trim_ascii_whitespace(std::string_view value) {
    std::size_t start = 0;
    while (start < value.size() && is_ascii_whitespace(value[start])) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && is_ascii_whitespace(value[end - 1U])) {
        --end;
    }
    return std::string(value.substr(start, end - start));
}

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

bool is_standard_seedqr_digit_stream(std::string_view value) {
    bool saw_digit = false;
    for (const char ch : value) {
        if (is_ascii_whitespace(ch)) {
            continue;
        }
        if (ch < '0' || ch > '9') {
            return false;
        }
        saw_digit = true;
    }
    return saw_digit;
}

SessionKeySource source_from_single_entry_keyring(StatelessSessionKeyring& keyring) {
    if (keyring.size() != 1U) {
        throw SessionSourceQrError("decoded session QR source was not loaded into the RAM-only boundary");
    }
    return keyring.source_at(0);
}

SessionKeySource source_from_nsec(std::string label, const NsecSecretKey& secret_key) {
    StatelessSessionKeyring keyring;
    keyring.add_nsec(std::move(label), secret_key);
    return source_from_single_entry_keyring(keyring);
}

SessionKeySource source_from_bip39_indexes(std::string label, Bip39WordIndexes indexes) {
    StatelessSessionKeyring keyring;
    keyring.add_bip39_seed(std::move(label), std::move(indexes));
    return source_from_single_entry_keyring(keyring);
}

}  // namespace

SessionKeySource parse_session_source_qr_text(std::string label, std::string_view decoded_text) {
    const std::string text = trim_ascii_whitespace(decoded_text);
    if (text.empty()) {
        throw SessionSourceQrError("decoded session QR text must not be empty");
    }

    try {
        if (starts_with(text, "nsec1")) {
            return source_from_nsec(std::move(label), decode_nsec_secret_key(text));
        }
        if (is_standard_seedqr_digit_stream(text)) {
            return source_from_bip39_indexes(std::move(label), decode_standard_seedqr_indexes(text));
        }
        return source_from_bip39_indexes(std::move(label), parse_bip39_english_mnemonic_indexes(text));
    } catch (const NsecDecodeError& exc) {
        throw SessionSourceQrError(exc.what());
    } catch (const SeedQrError& exc) {
        throw SessionSourceQrError(exc.what());
    } catch (const Bip39Error& exc) {
        throw SessionSourceQrError(exc.what());
    } catch (const SessionKeyringError& exc) {
        throw SessionSourceQrError(exc.what());
    }
}

SessionKeySource parse_compact_seedqr_session_source(std::string label, const std::vector<std::uint8_t>& entropy) {
    try {
        return source_from_bip39_indexes(std::move(label), decode_compact_seedqr_indexes(entropy));
    } catch (const SeedQrError& exc) {
        throw SessionSourceQrError(exc.what());
    } catch (const SessionKeyringError& exc) {
        throw SessionSourceQrError(exc.what());
    }
}

}  // namespace nsealr
