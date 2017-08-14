#include "vast/concept/parseable/to.hpp"
#include "vast/concept/parseable/vast/expression.hpp"
#include "vast/query_options.hpp"

#include "vast/system/archive.hpp"
#include "vast/system/exporter.hpp"
#include "vast/system/importer.hpp"
#include "vast/system/index.hpp"
#include "vast/system/replicated_store.hpp"

#define SUITE export
#include "test.hpp"
#include "fixtures/actor_system_and_events.hpp"

using namespace caf;
using namespace vast;
using namespace std::chrono;

FIXTURE_SCOPE(exporter_tests, fixtures::actor_system_and_events)

TEST(exporter historical) {
  auto i = self->spawn(system::index, directory / "index", 1000, 5, 5);
  auto a = self->spawn(system::archive, directory / "archive", 1, 1024);
  MESSAGE("ingesting conn.log");
  self->send(i, bro_conn_log);
  self->send(a, bro_conn_log);
  auto expr = to<expression>("service == \"http\" && :addr == 212.227.96.110");
  REQUIRE(expr);
  MESSAGE("issueing historical query");
  auto e = self->spawn(system::exporter, *expr, historical);
  self->send(e, a);
  self->send(e, system::index_atom::value, i);
  self->send(e, system::sink_atom::value, self);
  self->send(e, system::run_atom::value);
  self->send(e, system::extract_atom::value);
  MESSAGE("waiting for results");
  std::vector<event> results;
  self->do_receive(
    [&](std::vector<event>& xs) {
      std::move(xs.begin(), xs.end(), std::back_inserter(results));
    },
    error_handler()
  ).until([&] { return results.size() == 28; });
  MESSAGE("sanity checking result correctness");
  CHECK_EQUAL(results.front().id(), 105u);
  CHECK_EQUAL(results.front().type().name(), "bro::conn");
  CHECK_EQUAL(results.back().id(), 8354u);
  self->send_exit(i, exit_reason::user_shutdown);
  self->send_exit(a, exit_reason::user_shutdown);
}

TEST(exporter continuous -- exporter only) {
  auto i = self->spawn(system::index, directory / "index", 1000, 5, 5);
  auto a = self->spawn(system::archive, directory / "archive", 1, 1024);
  auto expr = to<expression>("service == \"http\" && :addr == 212.227.96.110");
  REQUIRE(expr);
  MESSAGE("issueing continuous query");
  auto e = self->spawn(system::exporter, *expr, continuous);
  self->send(e, a);
  self->send(e, system::index_atom::value, i);
  self->send(e, system::sink_atom::value, self);
  self->send(e, system::run_atom::value);
  self->send(e, system::extract_atom::value);
  MESSAGE("ingesting conn.log");
  self->send(e, bro_conn_log);
  MESSAGE("waiting for results");
  std::vector<event> results;
  self->do_receive(
    [&](std::vector<event>& xs) {
      std::move(xs.begin(), xs.end(), std::back_inserter(results));
    },
    error_handler()
  ).until([&] { return results.size() == 28; });
  MESSAGE("sanity checking result correctness");
  CHECK_EQUAL(results.front().id(), 105u);
  CHECK_EQUAL(results.front().type().name(), "bro::conn");
  CHECK_EQUAL(results.back().id(), 8354u);
  self->send_exit(i, exit_reason::user_shutdown);
  self->send_exit(a, exit_reason::user_shutdown);
}

TEST(exporter continuous -- with importer) {
  using namespace system;
  auto ind = self->spawn(system::index, directory / "index", 1000, 5, 5);
  auto arc = self->spawn(archive, directory / "archive", 1, 1024);
  auto imp = self->spawn(importer, directory / "importer", 128);
  auto con = self->spawn(raft::consensus, directory / "consensus");
  self->send(con, run_atom::value);
  meta_store_type ms = self->spawn(replicated_store<std::string, data>, con);
  auto expr = to<expression>("service == \"http\" && :addr == 212.227.96.110");
  REQUIRE(expr);
  MESSAGE("issueing continuous query");
  auto exp = self->spawn(exporter, *expr, continuous);
  self->send(exp, arc);
  self->send(exp, index_atom::value, ind);
  self->send(exp, sink_atom::value, self);
  self->send(exp, run_atom::value);
  self->send(exp, extract_atom::value);
  self->send(imp, arc);
  self->send(imp, index_atom::value, ind);
  self->send(imp, ms);
  self->send(imp, exp); // adds the exporter as a continuous query exporter ...
  MESSAGE("ingesting conn.log");
  self->send(imp, bro_conn_log);
  MESSAGE("waiting for results");
  std::vector<event> results;
  self->do_receive(
    [&](std::vector<event>& xs) {
      std::move(xs.begin(), xs.end(), std::back_inserter(results));
    },
    error_handler()
  ).until([&] { return results.size() == 28; });
  MESSAGE("sanity checking result correctness");
  CHECK_EQUAL(results.front().id(), 105u);
  CHECK_EQUAL(results.front().type().name(), "bro::conn");
  CHECK_EQUAL(results.back().id(), 8354u);
  self->send_exit(ind, exit_reason::user_shutdown);
  self->send_exit(arc, exit_reason::user_shutdown);
  self->send_exit(imp, exit_reason::user_shutdown);
  self->send_exit(con, exit_reason::user_shutdown);
}

TEST(exporter universal) {
  using namespace system;
  auto ind = self->spawn(system::index, directory / "index", 1000, 5, 5);
  auto arc = self->spawn(archive, directory / "archive", 1, 1024);
  auto imp = self->spawn(importer, directory / "importer", 128);
  auto con = self->spawn(raft::consensus, directory / "consensus");
  self->send(con, run_atom::value);
  meta_store_type ms = self->spawn(replicated_store<std::string, data>, con);
  auto expr = to<expression>("service == \"http\" && :addr == 212.227.96.110");
  REQUIRE(expr);
  self->send(imp, arc);
  self->send(imp, index_atom::value, ind);
  self->send(imp, ms);
  MESSAGE("ingesting conn.log for historical query part");
//  self->send(imp, bro_conn_log); // not sure why this doesn't work
  self->send(ind, bro_conn_log);
  self->send(arc, bro_conn_log);
  MESSAGE("issueing universal query");
  auto exp = self->spawn(exporter, *expr, continuous + historical);
  self->send(exp, arc);
  self->send(exp, index_atom::value, ind);
  self->send(exp, sink_atom::value, self);
  self->send(exp, run_atom::value);
  self->send(exp, extract_atom::value);
  self->send(imp, exp); // adds the exporter as a continuous query exporter ...
  MESSAGE("waiting for results");
  std::vector<event> results;
  self->do_receive(
    [&](std::vector<event>& xs) {
      std::move(xs.begin(), xs.end(), std::back_inserter(results));
    },
    error_handler()
  ).until([&] { return results.size() == 28; });
  MESSAGE("sanity checking result correctness");
  CHECK_EQUAL(results.front().id(), 105u);
  CHECK_EQUAL(results.front().type().name(), "bro::conn");
  CHECK_EQUAL(results.back().id(), 8354u);
  results.clear();
  MESSAGE("ingesting conn.log for continuous query part");
  self->send(imp, bro_conn_log);
  self->do_receive(
    [&](std::vector<event>& xs) {
      std::move(xs.begin(), xs.end(), std::back_inserter(results));
    },
    error_handler()
  ).until([&] { return results.size() == 28; });
  MESSAGE("sanity checking result correctness");
  CHECK_EQUAL(results.front().id(), 105u);
  CHECK_EQUAL(results.front().type().name(), "bro::conn");
  CHECK_EQUAL(results.back().id(), 8354u);
  self->send_exit(ind, exit_reason::user_shutdown);
  self->send_exit(arc, exit_reason::user_shutdown);
  self->send_exit(imp, exit_reason::user_shutdown);
  self->send_exit(con, exit_reason::user_shutdown);
}

FIXTURE_SCOPE_END()
