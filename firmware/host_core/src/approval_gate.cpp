#include "nostrseal/approval_gate.hpp"

namespace nostrseal {

void ApprovalGate::begin_review(const std::string& request_id) {
    active_request_id_ = request_id;
    decision_ = ApprovalDecision::Pending;
}

void ApprovalGate::approve(const std::string& request_id) {
    if (request_id == active_request_id_) {
        decision_ = ApprovalDecision::Approved;
    }
}

void ApprovalGate::reject(const std::string& request_id) {
    if (request_id == active_request_id_) {
        decision_ = ApprovalDecision::Rejected;
    }
}

bool ApprovalGate::can_sign(const std::string& request_id) const {
    return decision_ == ApprovalDecision::Approved && request_id == active_request_id_;
}

ApprovalDecision ApprovalGate::decision() const {
    return decision_;
}

const std::string& ApprovalGate::active_request_id() const {
    return active_request_id_;
}

}  // namespace nostrseal
