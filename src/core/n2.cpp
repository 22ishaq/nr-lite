#include "nrlite/core/n2.hpp"

namespace nrlite::n2 {

std::string name(const Message& m) {
  return std::visit(overloaded{[](const InitialUeMessage&) { return "InitialUEMessage"; },
                               [](const UplinkNasTransport&) { return "UplinkNASTransport"; },
                               [](const DownlinkNasTransport&) { return "DownlinkNASTransport"; },
                               [](const InitialContextSetupRequest&) { return "InitialContextSetupRequest"; },
                               [](const InitialContextSetupResponse&) { return "InitialContextSetupResponse"; },
                               [](const InitialContextSetupFailure&) { return "InitialContextSetupFailure"; },
                               [](const UeContextReleaseRequest&) { return "UEContextReleaseRequest"; },
                               [](const UeContextReleaseCommand&) { return "UEContextReleaseCommand"; },
                               [](const UeContextReleaseComplete&) { return "UEContextReleaseComplete"; }},
                    m);
}

std::uint32_t ran_ue_id(const Message& m) {
  return std::visit([](const auto& v) { return v.ran_ue_id; }, m);
}

const Bytes* nas_pdu(const Message& m) {
  if (const auto* v = std::get_if<InitialUeMessage>(&m)) return &v->nas_pdu;
  if (const auto* v = std::get_if<UplinkNasTransport>(&m)) return &v->nas_pdu;
  if (const auto* v = std::get_if<DownlinkNasTransport>(&m)) return &v->nas_pdu;
  if (const auto* v = std::get_if<InitialContextSetupRequest>(&m)) return v->nas_pdu ? &*v->nas_pdu : nullptr;
  return nullptr;
}

bool is_uplink(const Message& m) {
  return std::holds_alternative<InitialUeMessage>(m) || std::holds_alternative<UplinkNasTransport>(m) ||
         std::holds_alternative<InitialContextSetupResponse>(m) ||
         std::holds_alternative<InitialContextSetupFailure>(m) || std::holds_alternative<UeContextReleaseRequest>(m) ||
         std::holds_alternative<UeContextReleaseComplete>(m);
}

}  // namespace nrlite::n2
