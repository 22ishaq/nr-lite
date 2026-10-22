#pragma once

#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace nrlite {

/// Error carried by Result. `code` is protocol specific (for NAS it is the 5GMM cause the
/// receiver should report, e.g. #96 "invalid mandatory information"); 0 means "no cause".
struct Error {
  std::string message;
  int code = 0;
};

/// Minimal expected<T, Error> for C++17. Decoders return Result so that malformed input never
/// escapes as an exception into protocol state machines.
template <typename T>
class Result {
 public:
  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}     // NOLINT(google-explicit-constructor)
  Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}  // NOLINT(google-explicit-constructor)

  bool ok() const { return storage_.index() == 0; }
  explicit operator bool() const { return ok(); }

  const T& value() const& {
    check();
    return std::get<0>(storage_);
  }
  T& value() & {
    check();
    return std::get<0>(storage_);
  }
  T&& value() && {
    check();
    return std::get<0>(std::move(storage_));
  }

  const T& operator*() const& { return value(); }
  T& operator*() & { return value(); }
  const T* operator->() const { return &value(); }
  T* operator->() { return &value(); }

  const Error& error() const {
    if (ok()) throw std::logic_error("Result::error() called on a value");
    return std::get<1>(storage_);
  }

 private:
  void check() const {
    if (!ok()) throw std::logic_error("Result::value() called on an error: " + std::get<1>(storage_).message);
  }

  std::variant<T, Error> storage_;
};

template <typename... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
template <typename... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

}  // namespace nrlite
