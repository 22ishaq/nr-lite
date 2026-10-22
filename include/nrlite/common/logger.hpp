#pragma once

#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "nrlite/common/event_loop.hpp"

namespace nrlite {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3, Off = 4 };

const char* to_string(LogLevel level);

/// Per-simulation logger. Lines are stamped with virtual time and a component tag such as
/// "UE1/RRC" or "AMF". The default sink writes to stderr; tests and bindings install their own.
class Logger {
 public:
  using Sink = std::function<void(LogLevel, TimeMs, const std::string& component, const std::string& text)>;

  explicit Logger(const EventLoop* clock = nullptr, LogLevel level = LogLevel::Warn);

  void set_level(LogLevel level) { level_ = level; }
  LogLevel level() const { return level_; }
  void set_sink(Sink sink) { sink_ = std::move(sink); }
  bool enabled(LogLevel level) const { return level >= level_ && level_ != LogLevel::Off; }

  void write(LogLevel level, std::string_view component, const std::string& text) const;

  template <typename... Args>
  void debug(std::string_view component, Args&&... args) const {
    log(LogLevel::Debug, component, std::forward<Args>(args)...);
  }
  template <typename... Args>
  void info(std::string_view component, Args&&... args) const {
    log(LogLevel::Info, component, std::forward<Args>(args)...);
  }
  template <typename... Args>
  void warn(std::string_view component, Args&&... args) const {
    log(LogLevel::Warn, component, std::forward<Args>(args)...);
  }
  template <typename... Args>
  void error(std::string_view component, Args&&... args) const {
    log(LogLevel::Error, component, std::forward<Args>(args)...);
  }

 private:
  template <typename... Args>
  void log(LogLevel level, std::string_view component, Args&&... args) const {
    if (!enabled(level)) return;
    std::ostringstream os;
    (os << ... << std::forward<Args>(args));
    write(level, component, os.str());
  }

  const EventLoop* clock_;
  LogLevel level_;
  Sink sink_;
};

}  // namespace nrlite
