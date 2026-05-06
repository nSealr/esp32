#pragma once

#include <string>
#include <string_view>

namespace nostrseal {

std::string sha256_hex(std::string_view data);

}  // namespace nostrseal
