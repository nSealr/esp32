#pragma once

#include <string>

namespace nostrseal {

enum class ApprovalDecision {
    Pending,
    Approved,
    Rejected,
};

class ApprovalGate {
public:
    void begin_review(const std::string& request_id);
    void approve(const std::string& request_id);
    void reject(const std::string& request_id);

    [[nodiscard]] bool can_sign(const std::string& request_id) const;
    [[nodiscard]] ApprovalDecision decision() const;
    [[nodiscard]] const std::string& active_request_id() const;

private:
    std::string active_request_id_;
    ApprovalDecision decision_ = ApprovalDecision::Pending;
};

}  // namespace nostrseal
