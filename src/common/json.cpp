#include "nrlite/common/json.hpp"

#include <cstdio>
#include <stdexcept>

namespace nrlite {

Json& Json::set(const std::string& key, Json value) {
  auto* obj = std::get_if<Object>(&v_);
  if (obj == nullptr) throw std::logic_error("Json::set on a non-object");
  for (auto& kv : *obj) {
    if (kv.first == key) {
      kv.second = std::move(value);
      return *this;
    }
  }
  obj->emplace_back(key, std::move(value));
  return *this;
}

Json& Json::push(Json value) {
  auto* arr = std::get_if<Array>(&v_);
  if (arr == nullptr) throw std::logic_error("Json::push on a non-array");
  arr->push_back(std::move(value));
  return *this;
}

const Json* Json::find(const std::string& key) const {
  const auto* obj = std::get_if<Object>(&v_);
  if (obj == nullptr) return nullptr;
  for (const auto& kv : *obj) {
    if (kv.first == key) return &kv.second;
  }
  return nullptr;
}

std::string Json::dump() const {
  std::string out;
  dump_to(out);
  return out;
}

namespace {

void escape_to(std::string& out, const std::string& s) {
  out.push_back('"');
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += buf;
        } else {
          out.push_back(c);
        }
    }
  }
  out.push_back('"');
}

}  // namespace

void Json::dump_to(std::string& out) const {
  std::visit(
      [&out](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
          out += "null";
        } else if constexpr (std::is_same_v<T, bool>) {
          out += v ? "true" : "false";
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
          out += std::to_string(v);
        } else if constexpr (std::is_same_v<T, std::string>) {
          escape_to(out, v);
        } else if constexpr (std::is_same_v<T, Array>) {
          out.push_back('[');
          for (std::size_t i = 0; i < v.size(); ++i) {
            if (i != 0) out.push_back(',');
            v[i].dump_to(out);
          }
          out.push_back(']');
        } else {
          out.push_back('{');
          for (std::size_t i = 0; i < v.size(); ++i) {
            if (i != 0) out.push_back(',');
            escape_to(out, v[i].first);
            out.push_back(':');
            v[i].second.dump_to(out);
          }
          out.push_back('}');
        }
      },
      v_);
}

}  // namespace nrlite
