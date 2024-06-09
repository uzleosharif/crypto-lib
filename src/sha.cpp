// SPDX-License-Identifier: MIT

#include "crypto/sha.hpp"

namespace details {

// NOTE: we want to transform the input message hence a vector argument is
// preferred over some view/span type (i.e. we are limiting API).
// Further, a vector container makes sense as it is perfectly modeling our need
// to store underlying byte-based data i.e. contiguous byte-data with
// transformation/expansion operations.
[[nodiscard]] auto PadMessage(std::vector<std::byte>&& message)
    -> std::vector<std::byte> {
  std::uint64_t const message_length_bits_be{
      utils::SwapEndianness(message.size() * 8)};
  auto const pad_length{(512 - ((message.size() + 1) * 8) % 512) / 8};

  message.push_back(std::byte{0x80});
  message.reserve(message.size() + pad_length);
  message.insert(rng::end(message), pad_length, std::byte{0x0});
  std::memcpy(message.data() + message.size() - 8, &message_length_bits_be, 8);

  if ((message.size() * 8) % 512 != 0) {
    throw std::runtime_error{std::format(
        "The padded message is not aligned on a 64B boundary. Size: {}",
        message.size())};
  }

  return message;
}

}  // namespace details
