#include "vast/actor/indexer.h"
#include "vast/actor/task.h"

#include "framework/unit.h"

using namespace caf;
using namespace vast;

using bitstream_type = ewah_bitstream;

SUITE("actors")

TEST("indexer")
{
  VAST_DEBUG("creating test events");
  auto t0 = type::record{{"c", type::count{}}, {"s", type::string{}}};
  t0.name("test-record-event");
  auto t1 = type::real{};
  t1.name("test-real-event");
  size_t n = 1000;
  std::vector<event> events(n);
  for (size_t i = 0; i < n; ++i)
  {
    if (i % 2 == 0)
      events[i] = event::make(record{i, to_string(i)}, t0);
    else
      events[i] = event::make(4.2 + i, t1);
    events[i].id(i);
  }
  REQUIRE(events[0].type() == t0);
  REQUIRE(events[1].type() == t1);

  VAST_DEBUG("indexing the events");
  scoped_actor self;
  path dir0 = "vast-test-indexer-t0";
  path dir1 = "vast-test-indexer-t1";
  auto i0 = self->spawn<event_indexer<bitstream_type>, monitored>(dir0, t0);
  auto i1 = self->spawn<event_indexer<bitstream_type>, monitored>(dir1, t1);
  self->send(i0, events);
  self->send(i1, events);

  VAST_DEBUG("running a query against the first indexer");
  predicate pred{type_extractor{type::count{}}, less, data{100u}};
  auto t = self->spawn<task, monitored>();
  self->send(t, i0);
  self->send(i0, expression{pred}, self, t);
  self->receive(
    [&](expression const& expr, bitstream_type const& hit)
    {
      CHECK(expr == expression{pred});
      CHECK(hit.find_first() == 0);
      CHECK(hit.count() == 100 / 2); // Every other event in [0,100).
    });
  self->receive([&](down_msg const& msg) { CHECK(msg.source == t); });

  VAST_DEBUG("running a query against the second indexer");
  pred = {type_extractor{t1}, less_equal, data{42.0}};
  t = self->spawn<task, monitored>();
  self->send(t, i1);
  self->send(i1, expression{pred}, self, t);
  self->receive(
    [&](expression const& expr, bitstream_type const& hit)
    {
      CHECK(expr == expression{pred});
      CHECK(hit.find_first() == 1);
      CHECK(hit.count() == 19);
    });
  self->receive([&](down_msg const& msg) { CHECK(msg.source == t); });

  VAST_DEBUG("writing first index to file system");
  t = self->spawn<task, monitored>();
  self->send(t, i0);
  self->send(i0, flush_atom::value, t);
  self->receive([&](down_msg const& msg) { CHECK(msg.source == t); });
  REQUIRE(exists(dir0 / "type"));
  REQUIRE(exists(dir0 / "meta"));
  REQUIRE(exists(dir0 / "data"));
  self->send_exit(i0, exit::done);
  self->receive([&](down_msg const& msg) { CHECK(msg.source == i0); });
  VAST_DEBUG("writing second index to file system");
  t = self->spawn<task, monitored>();
  self->send(t, i1);
  self->send(i1, flush_atom::value, t);
  self->receive([&](down_msg const& msg) { CHECK(msg.source == t); });
  REQUIRE(exists(dir1 / "type"));
  REQUIRE(exists(dir1 / "meta"));
  REQUIRE(exists(dir1 / "data"));
  self->send_exit(i1, exit::done);
  self->receive([&](down_msg const& msg) { CHECK(msg.source == i1); });

  VAST_DEBUG("loading index from file system and querying again");
  i0 = self->spawn<event_indexer<bitstream_type>, monitored>(dir0);
  pred = predicate{type_extractor{type::count{}}, equal, data{998u}};
  t = self->spawn<task, monitored>();
  self->send(t, i0);
  self->send(i0, expression{pred}, self, t);
  self->receive(
    [&](expression const& expr, bitstream_type const& hit)
    {
      CHECK(expr == expression{pred});
      CHECK(hit.find_first() == 998u);
      CHECK(hit.count() == 1);
    });
  self->receive([&](down_msg const& msg) { CHECK(msg.source == t); });
  self->send_exit(i0, exit::done);
  self->receive([&](down_msg const& msg) { CHECK(msg.source == i0); });

  VAST_DEBUG("cleaning up");
  self->await_all_other_actors_done();
  rm(dir0);
  rm(dir1);
}