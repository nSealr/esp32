#pragma once

#include <string>

namespace nsealr {

enum class ApprovalDecision {
    Pending,
    Approved,
    Rejected,
};

class ApprovalGate {
public:
    void begin_review(const std::string& request_id, const std::string& approval_digest);
    void approve(const std::string& request_id, const std::string& approval_digest);
    void reject(const std::string& request_id);

    [[nodiscard]] bool can_sign(const std::string& request_id, const std::string& approval_digest) const;
    [[nodiscard]] ApprovalDecision decision() const;
    [[nodiscard]] const std::string& active_request_id() const;
    [[nodiscard]] const std::string& active_approval_digest() const;

private:
    std::string active_request_id_;
    std::string active_approval_digest_;
    ApprovalDecision decision_ = ApprovalDecision::Pending;
};

}  // namespace nsealr
