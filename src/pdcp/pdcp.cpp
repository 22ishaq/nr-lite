#include "nrlite/pdcp/pdcp.hpp"

#include <algorithm>
#include <stdexcept>

namespace nrlite::pdcp {

SrbEntity::SrbEntity(std::uint8_t srb_id, sec::Direction tx_direction) : srb_id_(srb_id), tx_dir_(tx_direction) {
  if (srb_id < 1 || srb_id > 3) throw std::invalid_argument("PDCP SRB id must be 1..3");
}

void SrbEntity::reset() {
  tx_next_ = 0;
  rx_deliv_ = 0;
  tx_int_.reset();
  rx_int_.reset();
  tx_enc_.reset();
  rx_enc_.reset();
}

Bytes SrbEntity::transmit(const Bytes& sdu) {
  const std::uint32_t count = tx_next_++;
  const std::uint32_t sn = count % kSnModulus;
  Bytes header_and_data{static_cast<std::uint8_t>((sn >> 8) & 0x0F), static_cast<std::uint8_t>(sn)};
  header_and_data.insert(header_and_data.end(), sdu.begin(), sdu.end());

  sec::Mac32 mac{0, 0, 0, 0};
  if (tx_int_) mac = sec::nia2(*tx_int_, count, bearer(), tx_dir_, header_and_data);

  Bytes body(header_and_data.begin() + kHeaderSize, header_and_data.end());
  body.insert(body.end(), mac.begin(), mac.end());
  if (tx_enc_) body = sec::nea2(*tx_enc_, count, bearer(), tx_dir_, body);

  Bytes pdu(header_and_data.begin(), header_and_data.begin() + kHeaderSize);
  pdu.insert(pdu.end(), body.begin(), body.end());
  return pdu;
}

Result<RxPdu> SrbEntity::receive(const Bytes& pdu) {
  if (pdu.size() < kHeaderSize + kMacSize) {
    return Error{"PDCP PDU too short (" + std::to_string(pdu.size()) + " octets)", static_cast<int>(RxError::Malformed)};
  }
  const std::uint32_t rcvd_sn = ((std::uint32_t{pdu[0]} & 0x0F) << 8) | pdu[1];
  const std::uint32_t deliv_sn = rx_deliv_ % kSnModulus;
  std::uint32_t hfn = rx_deliv_ / kSnModulus;
  if (static_cast<std::int64_t>(rcvd_sn) < static_cast<std::int64_t>(deliv_sn) - static_cast<std::int64_t>(kWindowSize)) {
    ++hfn;
  } else if (rcvd_sn >= deliv_sn + kWindowSize && hfn > 0) {
    --hfn;
  }
  const std::uint32_t count = hfn * kSnModulus + rcvd_sn;

  Bytes body(pdu.begin() + kHeaderSize, pdu.end());
  if (rx_enc_) body = sec::nea2(*rx_enc_, count, bearer(), rx_direction(), body);

  RxPdu out;
  out.count = count;
  std::copy(body.end() - kMacSize, body.end(), out.mac_i.begin());
  out.sdu.assign(body.begin(), body.end() - kMacSize);
  out.header_and_data.assign(pdu.begin(), pdu.begin() + kHeaderSize);
  out.header_and_data.insert(out.header_and_data.end(), out.sdu.begin(), out.sdu.end());

  if (rx_int_) {
    if (!verify(out, *rx_int_)) {
      return Error{"PDCP integrity check failed for COUNT " + std::to_string(count),
                   static_cast<int>(RxError::IntegrityFailure)};
    }
    out.integrity_verified = true;
  }
  if (count < rx_deliv_) {
    return Error{"PDCP duplicate (COUNT " + std::to_string(count) + " < RX_DELIV " + std::to_string(rx_deliv_) + ")",
                 static_cast<int>(RxError::Duplicate)};
  }
  rx_deliv_ = count + 1;
  return out;
}

bool SrbEntity::verify(const RxPdu& pdu, const sec::Key128& key) const {
  const sec::Mac32 expected = sec::nia2(key, pdu.count, bearer(), rx_direction(), pdu.header_and_data);
  return sec::equal_ct(expected.data(), pdu.mac_i.data(), kMacSize);
}

}  // namespace nrlite::pdcp
