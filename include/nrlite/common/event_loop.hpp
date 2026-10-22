#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>

namespace nrlite {

/// Virtual time in milliseconds. The whole simulator is single threaded and deterministic: time
/// only moves when the event loop is told to advance, so protocol timers (T300, T3510, ...) can
/// be exercised in microseconds of wall-clock time.
using TimeMs = std::int64_t;

class EventLoop {
 public:
  using EventId = std::uint64_t;
  using Callback = std::function<void()>;

  TimeMs now() const { return now_; }

  EventId schedule_in(TimeMs delay, Callback cb);
  EventId schedule_at(TimeMs at, Callback cb);
  bool cancel(EventId id);
  bool pending(EventId id) const { return index_.count(id) != 0; }

  /// Runs every event due at or before `until`, then sets now() = until.
  void run_until(TimeMs until);
  void advance(TimeMs delta) { run_until(now_ + delta); }

  /// Runs the single earliest event (moving time forward to it). Returns false if none is queued.
  bool step();

  /// Runs events until `done()` returns true or `limit` ms of virtual time have elapsed.
  /// Returns the value of done() at exit.
  bool run_until_condition(const std::function<bool()>& done, TimeMs limit);

  std::size_t pending_count() const { return queue_.size(); }
  std::optional<TimeMs> next_event_time() const;

 private:
  struct Key {
    TimeMs at;
    EventId id;
    bool operator<(const Key& o) const { return at != o.at ? at < o.at : id < o.id; }
  };
  std::map<Key, Callback> queue_;
  std::map<EventId, Key> index_;
  TimeMs now_ = 0;
  EventId next_id_ = 1;
};

/// A named one-shot protocol timer bound to an EventLoop.
class Timer {
 public:
  Timer(EventLoop& loop, std::string name, std::function<void()> on_expiry);
  ~Timer();
  Timer(const Timer&) = delete;
  Timer& operator=(const Timer&) = delete;

  /// Starts (or restarts) the timer.
  void start(TimeMs duration);
  void stop();
  bool running() const;
  /// Remaining time; 0 when not running.
  TimeMs remaining() const;
  TimeMs duration() const { return duration_; }
  const std::string& name() const { return name_; }
  /// Number of times this timer has expired since construction.
  unsigned expiry_count() const { return expiries_; }

 private:
  EventLoop& loop_;
  std::string name_;
  std::function<void()> on_expiry_;
  std::optional<EventLoop::EventId> event_;
  TimeMs deadline_ = 0;
  TimeMs duration_ = 0;
  unsigned expiries_ = 0;
};

}  // namespace nrlite
