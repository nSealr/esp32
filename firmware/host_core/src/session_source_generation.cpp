#include "nsealr/session_source_generation.hpp"

#include <utility>

#include "nsealr/seedqr.hpp"

namespace nsealr {
namespace {

SessionKeySource source_from_single_entry_keyring(StatelessSessionKeyring& keyring) {
    if (keyring.size() != 1U) {
        throw SessionSourceGenerationError("generated session source was not loaded into the RAM-only boundary");
    }
    return keyring.source_at(0);
}

}  // namespace

SessionKeySource generate_bip39_session_source(std::string label, const std::vector<std::uint8_t>& entropy) {
    if (entropy.size() != 16U && entropy.size() != 32U) {
        throw SessionSourceGenerationError("generated BIP-39 entropy must be 16 or 32 bytes");
    }
    try {
        StatelessSessionKeyring keyring;
        keyring.add_bip39_seed(std::move(label), decode_compact_seedqr_indexes(entropy));
        return source_from_single_entry_keyring(keyring);
    } catch (const SeedQrError& exc) {
        throw SessionSourceGenerationError(exc.what());
    } catch (const SessionKeyringError& exc) {
        throw SessionSourceGenerationError(exc.what());
    }
}

SessionKeySource generate_nsec_session_source(std::string label, const NsecSecretKey& entropy) {
    if (!is_valid_nsec_secret_key(entropy)) {
        throw SessionSourceGenerationError("generated nsec entropy must be a valid secp256k1 scalar");
    }
    try {
        StatelessSessionKeyring keyring;
        keyring.add_nsec(std::move(label), entropy);
        return source_from_single_entry_keyring(keyring);
    } catch (const SessionKeyringError& exc) {
        throw SessionSourceGenerationError(exc.what());
    }
}

}  // namespace nsealr
