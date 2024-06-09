// SPDX-License-Identifier: MIT

#include <array>
#include <print>
#include <ranges>

#include <crypto/sha.hpp>

auto main() -> int {
  auto hash_bytes{crypto::Sha256("hello world")};

  std::println(
      "{}",
      hash_bytes | std::views::transform([](std::byte elem) -> std::string {
        return std::format("{:02x}", static_cast<std::uint32_t>(elem));
      }) | std::views::join |
          std::ranges::to<std::string>());
}
