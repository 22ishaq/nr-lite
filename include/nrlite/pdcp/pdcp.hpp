#pragma once

// PDCP entity for signalling radio bearers (TS 38.323), reduced to what RRC needs:
//
//   PDCP Data PDU for SRBs:  R R R R | SN (12 bits) | data | MAC-I (32 bits)
//
// MAC-I is always present on SRBs and is all-zero until integrity protection is activated. When
// activated, MAC-I = NIA2(K_RRCint, COUNT, BEARER = SRB id - 1, DIRECTION, header || data) and the
// data plus MAC-I may additionally be ciphered with NEA2. The receive side estimates COUNT from the
// SN with the standard window rule (§5.2.2.1) and drops duplicates (COUNT < RX_DELIV).
//
// Integrity is verified in PDCP once active. For the AS SecurityModeCommand, which arrives before
// the UE has the key, the PDU is delivered unverified and RRC calls verify() itself (TS 38.331 §5.3.4.3).

#include <cstdint>
#include <optional>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/result.hpp"
#include "nrlite/security/crypto.hpp"

namespace nrlite::pdcp {

constexpr std::uint32_t kSnBits = 12;
constexpr std::uint32_t kSnModulus = 1u << kSnBits;
constexpr std::uint32_t kWindowSize = kSnModulus / 2;
constexpr std::size_t kHeaderSize = 2;
constexpr std::size_t kMacSize = 4;

struct RxPdu {
  Bytes sdu;                ///< RRC PDU
  std::uint32_t count = 0;  ///< estimated COUNT
  bool integrity_verified = false;
  Bytes header_and_data;    ///< input for a deferred integrity check
  sec::Mac32 mac_i{};
};

enum class RxError { Malformed = 1, IntegrityFailure = 2, Duplicate = 3 };

class SrbEntity {
 public:
  /// `tx_direction` is Uplink for the UE side and Downlink for the gNB side.
  SrbEntity(std::uint8_t srb_id, sec::Direction tx_direction);

  Bytes transmit(const Bytes& sdu);
  /// Error::code carries an RxError.
  Result<RxPdu> receive(const Bytes& pdu);

  void enable_tx_integrity(const sec::Key128& key) { tx_int_ = key; }
  void enable_rx_integrity(const sec::Key128& key) { rx_int_ = key; }
  void enable_tx_ciphering(const sec::Key128& key) { tx_enc_ = key; }
  void enable_rx_ciphering(const sec::Key128& key) { rx_enc_ = key; }
  bool tx_integrity_active() const { return tx_int_.has_value(); }
  bool rx_integrity_active() const { return rx_int_.has_value(); }

  /// Checks MAC-I of a PDU that was delivered unverified (e.g. the AS SecurityModeCommand).
  bool verify(const RxPdu& pdu, const sec::Key128& key) const;

  /// Re-establishment: resets state variables and deactivates security.
  void reset();
  /// Falls back to no integrity/ciphering while keeping the COUNT state (e.g. after SMC failure).
  void disable_security() {
    tx_int_.reset();
    rx_int_.reset();
    tx_enc_.reset();
    rx_enc_.reset();
  }

  std::uint32_t tx_next() const { return tx_next_; }
  std::uint32_t rx_deliv() const { return rx_deliv_; }
  std::uint8_t srb_id() const { return srb_id_; }

 private:
  sec::Direction rx_direction() const {
    return tx_dir_ == sec::Direction::Uplink ? sec::Direction::Downlink : sec::Direction::Uplink;
  }
  std::uint8_t bearer() const { return static_cast<std::uint8_t>(srb_id_ - 1); }

  std::uint8_t srb_id_;
  sec::Direction tx_dir_;
  std::uint32_t tx_next_ = 0;
  std::uint32_t rx_deliv_ = 0;
  std::optional<sec::Key128> tx_int_, rx_int_, tx_enc_, rx_enc_;
};

}  // namespace nrlite::pdcp
