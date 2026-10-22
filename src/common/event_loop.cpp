#include "nrlite/common/event_loop.hpp"

#include <stdexcept>
#include <utility>

namespace nrlite {

EventLoop::EventId EventLoop::schedule_in(TimeMs delay, Callback cb) {
  if (delay < 0) throw std::invalid_argument("EventLoop::schedule_in: negative delay");
  return schedule_at(now_ + delay, std::move(cb));
}

EventLoop::EventId EventLoop::schedule_at(TimeMs at, Callback cb) {
  if (at < now_) throw std::invalid_argument("EventLoop::schedule_at: time in the past");
  const EventId id = next_id_++;
  const Key key{at, id};
  queue_.emplace(key, std::move(cb));
  index_.emplace(id, key);
  return id;
}

bool EventLoop::cancel(EventId id) {
  auto it = index_.find(id);
  if (it == index_.end()) return false;
  queue_.erase(it->second);
  index_.erase(it);
  return true;
}

bool EventLoop::step() {
  if (queue_.empty()) return false;
  auto it = queue_.begin();
  const Key key = it->first;
  Callback cb = std::move(it->second);
  queue_.erase(it);
  index_.erase(key.id);
  now_ = key.at;
  cb();
  return true;
}

void EventLoop::run_until(TimeMs until) {
  if (until < now_) throw std::invalid_argument("EventLoop::run_until: time in the past");
  while (!queue_.empty() && queue_.begin()->first.at <= until) step();
  now_ = until;
}

bool EventLoop::run_until_condition(const std::function<bool()>& done, TimeMs limit) {
  const TimeMs deadline = now_ + limit;
  while (!done()) {
    if (queue_.empty() || queue_.begin()->first.at > deadline) {
      now_ = deadline;
      return done();
    }
    step();
  }
  return true;
}

std::optional<TimeMs> EventLoop::next_event_time() const {
  if (queue_.empty()) return std::nullopt;
  return queue_.begin()->first.at;
}

Timer::Timer(EventLoop& loop, std::string name, std::function<void()> on_expiry)
    : loop_(loop), name_(std::move(name)), on_expiry_(std::move(on_expiry)) {}

Timer::~Timer() { stop(); }

void Timer::start(TimeMs duration) {
  stop();
  duration_ = duration;
  deadline_ = loop_.now() + duration;
  event_ = loop_.schedule_in(duration, [this] {
    event_.reset();
    ++expiries_;
    if (on_expiry_) on_expiry_();
  });
}

void Timer::stop() {
  if (event_) {
    loop_.cancel(*event_);
    event_.reset();
  }
}

bool Timer::running() const { return event_.has_value(); }

TimeMs Timer::remaining() const { return running() ? deadline_ - loop_.now() : 0; }

}  // namespace nrlite
