#include "nsealr/approval_gate.hpp"

namespace nsealr {

void ApprovalGate::begin_review(const std::string& request_id, const std::string& approval_digest) {
    active_request_id_ = request_id;
    active_approval_digest_ = approval_digest;
    decision_ = ApprovalDecision::Pending;
}

void ApprovalGate::approve(const std::string& request_id, const std::string& approval_digest) {
    if (request_id == active_request_id_ && approval_digest == active_approval_digest_) {
        decision_ = ApprovalDecision::Approved;
    }
}

void ApprovalGate::reject(const std::string& request_id) {
    if (request_id == active_request_id_) {
        decision_ = ApprovalDecision::Rejected;
    }
}

bool ApprovalGate::can_sign(const std::string& request_id, const std::string& approval_digest) const {
    return decision_ == ApprovalDecision::Approved && request_id == active_request_id_ &&
           approval_digest == active_approval_digest_;
}

ApprovalDecision ApprovalGate::decision() const {
    return decision_;
}

const std::string& ApprovalGate::active_request_id() const {
    return active_request_id_;
}

const std::string& ApprovalGate::active_approval_digest() const {
    return active_approval_digest_;
}

}  // namespace nsealr
