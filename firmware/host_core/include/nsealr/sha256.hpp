#pragma once

#include <string>
#include <string_view>

namespace nsealr {

std::string sha256_hex(std::string_view data);

}  // namespace nsealr
