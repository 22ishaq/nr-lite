#include <gtest/gtest.h>

#include <vector>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/json.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/common/result.hpp"

using namespace nrlite;

TEST(Hex, RoundTrip) {
  const Bytes b{0x00, 0x7e, 0xff, 0x10};
  EXPECT_EQ(to_hex(b), "007eff10");
  EXPECT_EQ(to_hex(b, true), "00 7e ff 10");
  EXPECT_EQ(from_hex("00 7E ff:10"), b);
  EXPECT_EQ(from_hex("0x007eff10"), b);
}

TEST(Hex, RejectsBadInput) {
  EXPECT_THROW(from_hex("abc"), std::invalid_argument);
  EXPECT_THROW(from_hex("zz"), std::invalid_argument);
  EXPECT_THROW(array_from_hex<4>("001122"), std::invalid_argument);
}

TEST(Hex, BigEndianHelpers) {
  Bytes b;
  put_u16(b, 0x1234);
  put_u32(b, 0xDEADBEEF);
  EXPECT_EQ(to_hex(b), "1234deadbeef");
}

TEST(ResultType, ValueAndError) {
  Result<int> ok = 5;
  ASSERT_TRUE(ok);
  EXPECT_EQ(*ok, 5);
  Result<int> bad = Error{"boom", 96};
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().message, "boom");
  EXPECT_EQ(bad.error().code, 96);
  EXPECT_THROW(bad.value(), std::logic_error);
  EXPECT_THROW(ok.error(), std::logic_error);
}

TEST(JsonValue, DumpsOrderedObject) {
  Json j = Json::object().set("b", 1).set("a", "x").set("c", true);
  j.set("list", Json::array().push(1).push(nullptr));
  EXPECT_EQ(j.dump(), R"({"b":1,"a":"x","c":true,"list":[1,null]})");
}

TEST(JsonValue, SetReplacesExistingKey) {
  Json j = Json::object().set("k", 1).set("k", 2);
  EXPECT_EQ(j.dump(), R"({"k":2})");
  ASSERT_NE(j.find("k"), nullptr);
  EXPECT_EQ(*j.find("k")->as_int(), 2);
  EXPECT_EQ(j.find("missing"), nullptr);
}

TEST(JsonValue, EscapesStrings) {
  EXPECT_EQ(Json(std::string("a\"b\\c\n\x01")).dump(), R"("a\"b\\c\n\u0001")");
}

TEST(JsonValue, WrongKindThrows) {
  Json arr = Json::array();
  EXPECT_THROW(arr.set("k", 1), std::logic_error);
  Json obj = Json::object();
  EXPECT_THROW(obj.push(1), std::logic_error);
}

TEST(EventLoop, RunsEventsInTimeOrder) {
  EventLoop loop;
  std::vector<int> order;
  loop.schedule_in(30, [&] { order.push_back(3); });
  loop.schedule_in(10, [&] { order.push_back(1); });
  loop.schedule_in(20, [&] { order.push_back(2); });
  loop.run_until(100);
  EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
  EXPECT_EQ(loop.now(), 100);
}

TEST(EventLoop, SameTimeEventsKeepFifoOrder) {
  EventLoop loop;
  std::vector<int> order;
  for (int i = 0; i < 5; ++i) loop.schedule_in(5, [&order, i] { order.push_back(i); });
  loop.advance(5);
  EXPECT_EQ(order, (std::vector<int>{0, 1, 2, 3, 4}));
}

TEST(EventLoop, CancelPreventsExecution) {
  EventLoop loop;
  bool ran = false;
  const auto id = loop.schedule_in(10, [&] { ran = true; });
  EXPECT_TRUE(loop.pending(id));
  EXPECT_TRUE(loop.cancel(id));
  EXPECT_FALSE(loop.cancel(id));
  loop.advance(20);
  EXPECT_FALSE(ran);
}

TEST(EventLoop, EventsScheduledDuringRunAreHonoured) {
  EventLoop loop;
  int count = 0;
  loop.schedule_in(1, [&] {
    ++count;
    loop.schedule_in(1, [&] { ++count; });
  });
  loop.advance(5);
  EXPECT_EQ(count, 2);
}

TEST(EventLoop, StepAdvancesToNextEvent) {
  EventLoop loop;
  loop.schedule_in(42, [] {});
  EXPECT_EQ(loop.next_event_time(), 42);
  EXPECT_TRUE(loop.step());
  EXPECT_EQ(loop.now(), 42);
  EXPECT_FALSE(loop.step());
}

TEST(EventLoop, RunUntilCondition) {
  EventLoop loop;
  bool flag = false;
  loop.schedule_in(100, [&] { flag = true; });
  EXPECT_FALSE(loop.run_until_condition([&] { return flag; }, 50));
  EXPECT_EQ(loop.now(), 50);
  EXPECT_TRUE(loop.run_until_condition([&] { return flag; }, 100));
  EXPECT_EQ(loop.now(), 100);
}

TEST(EventLoop, RejectsPastTimes) {
  EventLoop loop;
  loop.advance(10);
  EXPECT_THROW(loop.schedule_at(5, [] {}), std::invalid_argument);
  EXPECT_THROW(loop.schedule_in(-1, [] {}), std::invalid_argument);
  EXPECT_THROW(loop.run_until(5), std::invalid_argument);
}

TEST(TimerTest, ExpiresAfterDuration) {
  EventLoop loop;
  int fired = 0;
  Timer t(loop, "T300", [&] { ++fired; });
  t.start(1000);
  EXPECT_TRUE(t.running());
  loop.advance(999);
  EXPECT_EQ(fired, 0);
  EXPECT_EQ(t.remaining(), 1);
  loop.advance(1);
  EXPECT_EQ(fired, 1);
  EXPECT_FALSE(t.running());
  EXPECT_EQ(t.expiry_count(), 1u);
}

TEST(TimerTest, RestartResetsDeadline) {
  EventLoop loop;
  int fired = 0;
  Timer t(loop, "T", [&] { ++fired; });
  t.start(100);
  loop.advance(80);
  t.start(100);
  loop.advance(80);
  EXPECT_EQ(fired, 0);
  loop.advance(20);
  EXPECT_EQ(fired, 1);
}

TEST(TimerTest, StopCancels) {
  EventLoop loop;
  int fired = 0;
  Timer t(loop, "T", [&] { ++fired; });
  t.start(10);
  t.stop();
  loop.advance(100);
  EXPECT_EQ(fired, 0);
  EXPECT_EQ(t.remaining(), 0);
}

TEST(TimerTest, CanRestartFromItsOwnCallback) {
  EventLoop loop;
  int fired = 0;
  Timer* self = nullptr;
  Timer t(loop, "T", [&] {
    if (++fired < 3) self->start(10);
  });
  self = &t;
  t.start(10);
  loop.advance(100);
  EXPECT_EQ(fired, 3);
}

TEST(TimerTest, DestructorCancelsPendingEvent) {
  EventLoop loop;
  int fired = 0;
  {
    Timer t(loop, "T", [&] { ++fired; });
    t.start(10);
  }
  loop.advance(100);
  EXPECT_EQ(fired, 0);
  EXPECT_EQ(loop.pending_count(), 0u);
}

TEST(LoggerTest, SinkReceivesStampedLinesAboveLevel) {
  EventLoop loop;
  Logger log(&loop, LogLevel::Info);
  std::vector<std::string> lines;
  log.set_sink([&](LogLevel lvl, TimeMs t, const std::string& comp, const std::string& text) {
    lines.push_back(std::string(to_string(lvl)) + "@" + std::to_string(t) + " " + comp + " " + text);
  });
  loop.advance(7);
  log.debug("X", "hidden");
  log.info("UE1/RRC", "value=", 42);
  log.set_level(LogLevel::Off);
  log.error("X", "also hidden");
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "INFO@7 UE1/RRC value=42");
}
