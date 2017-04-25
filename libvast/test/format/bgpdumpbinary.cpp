#include "vast/error.hpp"
#include "vast/event.hpp"

#include "vast/format/bgpdumpbinary.hpp"
#include "vast/concept/parseable/to.hpp"
#include "vast/concept/parseable/vast/address.hpp"
#include "vast/concept/parseable/vast/subnet.hpp"
#include "vast/filesystem.hpp"
#include "vast/detail/make_io_stream.hpp"

#define SUITE format
#include "test.hpp"
#include "data.hpp"

using namespace vast;

TEST(bgpdumpbinary parsing) {
  auto in = detail::make_input_stream(bgpdumpbinary::updates20150505, false);
  format::bgpdumpbinary::reader reader{std::move(*in)};
  auto e = expected<event>{no_error};
  std::vector<event> events;
  while (e || !e.error()) {
    e = reader.read();
    if (e)
      events.push_back(std::move(*e));
  }
  REQUIRE(!e);
  CHECK_EQUAL(e.error(), ec::end_of_input);
  REQUIRE(!events.empty());
  CHECK_EQUAL(events[0].type().name(), "bgpdump::announcement");  
  auto r = get_if<vector>(events[0].data());
  REQUIRE(r);
  auto addr = get_if<address>(r->at(1));
  CHECK_EQUAL(*addr, *to<address>("12.0.1.63"));
  CHECK_EQUAL(r->at(2), count{7018});
  auto subn = get_if<subnet>(r->at(3));
  CHECK_EQUAL(*subn, *to<subnet>("200.29.24.0/24"));
  auto as_path = get_if<vector>(r->at(4));
  CHECK_EQUAL(as_path->size(), 3);
  CHECK_EQUAL(as_path->at(0), count{7018});
  CHECK_EQUAL(as_path->at(1), count{6762});
  CHECK_EQUAL(as_path->at(2), count{14318});

  CHECK_EQUAL(events[13].type().name(), "bgpdump::withdrawn");
  r = get_if<vector>(events[13].data());
  REQUIRE(r);
  addr = get_if<address>(r->at(1));
  CHECK_EQUAL(*addr, *to<address>("12.0.1.63"));
  CHECK_EQUAL(r->at(2), count{7018});
  subn = get_if<subnet>(r->at(3));
  CHECK_EQUAL(*subn, *to<subnet>("200.29.24.0/24"));

  CHECK_EQUAL(events[73].type().name(), "bgpdump::state_change");
  r = get_if<vector>(events[73].data());
  REQUIRE(r);
  addr = get_if<address>(r->at(1));
  CHECK_EQUAL(*addr, *to<address>("111.91.233.1"));
  CHECK_EQUAL(r->at(2), count{45896});
  CHECK_EQUAL(r->at(3), count{3});
  CHECK_EQUAL(r->at(4), count{2});
}
