// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef>
#include <string_view>
#include <array>
#include <cstdint>
#include <ranges>
#include <vector>
#include <algorithm>
#include <cstring>
#include <span>

#include <utils.hpp>

namespace rng = std::ranges;

namespace details {
[[nodiscard]] auto PadMessage(std::vector<std::byte>&& message)
    -> std::vector<std::byte>;
}

namespace crypto {

template <bool kBigEndian = true>
[[nodiscard]] auto Sha256(std::string_view plain_text)
    -> std::array<std::byte, 32> {
  std::array<std::byte, 32> result{};
  constexpr std::array<std::uint32_t, 64> kRoundConstants{
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  auto right_rotate = [](std::uint32_t value,
                         std::size_t count) noexcept -> std::uint32_t {
    return (value >> count) | (value << (32 - count));
  };
  auto right_shift = [](std::uint32_t value,
                        std::size_t count) noexcept -> std::uint32_t {
    return (value >> count);
  };

  auto padded_message{details::PadMessage(
      plain_text | std::views::transform([](char c) -> std::byte {
        return static_cast<std::byte>(c);
      }) |
      rng::to<std::vector>())};

  std::array<std::uint32_t, 64> w{};
  rng::for_each(
      padded_message | std::views::chunk(64),
      [&w, &right_rotate, &right_shift](auto const& block) {
        rng::copy(block | std::views::chunk(4) |
                      std::views::transform([](auto chunk) -> std::uint32_t {
                        std::uint32_t value{0};
                        std::memcpy(&value, chunk.data(), 4);
                        return utils::SwapEndianness(value);
                      }),
                  rng::begin(w));

        rng::for_each(std::views::iota(16) | std::views::take(48),
                      [&w, &right_rotate, &right_shift](int i) {
                        auto const s0{right_rotate(w[i - 15], 7) ^
                                      right_rotate(w[i - 15], 18) ^
                                      right_shift(w[i - 15], 3)};
                        auto const s1{right_rotate(w[i - 2], 17) ^
                                      right_rotate(w[i - 2], 19) ^
                                      right_shift(w[i - 2], 10)};
                        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
                      });
      });

  std::array<std::uint32_t, 8> hash{0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                    0xa54ff53a, 0x510e527f, 0x9b05688c,
                                    0x1f83d9ab, 0x5be0cd19};
  auto a{hash[0]};
  auto b{hash[1]};
  auto c{hash[2]};
  auto d{hash[3]};
  auto e{hash[4]};
  auto f{hash[5]};
  auto g{hash[6]};
  auto h{hash[7]};
  rng::for_each(std::views::iota(0) | std::views::take(64),
                [&kRoundConstants, &w, &a, &b, &c, &d, &e, &f, &g, &h,
                 &right_shift, &right_rotate](int i) {
                  auto const s1{right_rotate(e, 6) ^ right_rotate(e, 11) ^
                                right_rotate(e, 25)};
                  auto const ch{(e & f) ^ (~e & g)};
                  auto const tmp1{h + s1 + ch + kRoundConstants[i] + w[i]};
                  auto const s0{right_rotate(a, 2) ^ right_rotate(a, 13) ^
                                right_rotate(a, 22)};
                  auto const maj{(a & b) ^ (a & c) ^ (b & c)};
                  auto const tmp2{s0 + maj};

                  h = g;
                  g = f;
                  f = e;
                  e = d + tmp1;
                  d = c;
                  c = b;
                  b = a;
                  a = tmp1 + tmp2;
                });
  hash[0] += a;
  hash[1] += b;
  hash[2] += c;
  hash[3] += d;
  hash[4] += e;
  hash[5] += f;
  hash[6] += g;
  hash[7] += h;

  if constexpr (kBigEndian) {
    rng::transform(hash, rng::begin(hash),
                   [](std::uint32_t elem) -> std::uint32_t {
                     return utils::SwapEndianness(elem);
                   });
  }

  rng::copy(std::as_bytes<std::uint32_t, 8>(hash), rng::begin(result));

  return result;
}

}  // namespace crypto
