

// SPDX-License-Identifier: MIT

#include <ranges>

#include <crypto/sha.hpp>
#include <catch2/catch_test_macros.hpp>

namespace rng = std::ranges;

using namespace std::string_view_literals;

TEST_CASE("Sha256 hashing works correctly", "[sha256]") {
  SECTION("Typical input") {
    auto hash_result{crypto::Sha256("hello world") |
                     std::views::transform([](std::byte byte) -> std::string {
                       return std::format("{:02x}",
                                          static_cast<std::uint8_t>(byte));
                     }) |
                     std::views::join | rng::to<std::string>()};

    REQUIRE(
        std::string_view{hash_result} ==
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"sv);
  }

  SECTION("Longer input") {
    auto hash_result{
        crypto::Sha256("The quick brown fox jumps over the lazy dog.") |
        std::views::transform([](std::byte byte) -> std::string {
          return std::format("{:02x}", static_cast<std::uint8_t>(byte));
        }) |
        std::views::join | rng::to<std::string>()};

    REQUIRE(
        std::string_view{hash_result} ==
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"sv);
  }
}
