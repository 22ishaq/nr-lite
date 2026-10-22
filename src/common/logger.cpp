#include "nrlite/common/logger.hpp"

#include <cstdio>

namespace nrlite {

const char* to_string(LogLevel level) {
  switch (level) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info: return "INFO";
    case LogLevel::Warn: return "WARN";
    case LogLevel::Error: return "ERROR";
    case LogLevel::Off: return "OFF";
  }
  return "?";
}

Logger::Logger(const EventLoop* clock, LogLevel level) : clock_(clock), level_(level) {}

void Logger::write(LogLevel level, std::string_view component, const std::string& text) const {
  if (!enabled(level)) return;
  const TimeMs now = clock_ != nullptr ? clock_->now() : 0;
  const std::string comp(component);
  if (sink_) {
    sink_(level, now, comp, text);
    return;
  }
  std::fprintf(stderr, "[%8lld ms] %-5s %-10s %s\n", static_cast<long long>(now), to_string(level), comp.c_str(),
               text.c_str());
}

}  // namespace nrlite
