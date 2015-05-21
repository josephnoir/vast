#include <csignal>
#include <cstdlib>

#include <algorithm>
#include <iostream>
#include <limits>
#include <string>
#include <thread>

#include <caf/all.hpp>
#include <caf/io/all.hpp>
#include <caf/scheduler/profiled_coordinator.hpp>

#include "vast/announce.h"
#include "vast/banner.h"
#include "vast/filesystem.h"
#include "vast/logger.h"
#include "vast/actor/node.h"
#include "vast/actor/signal_monitor.h"
#include "vast/util/endpoint.h"
#include "vast/util/system.h"

using namespace vast;
using namespace std::string_literals;

int main(int argc, char *argv[])
{
  // Defaults.
  auto dir = "vast"s;
  auto endpoint = std::string{};
  auto host = "127.0.0.1"s;
  auto log_level = 3;
  auto messages = std::numeric_limits<size_t>::max();
  auto name = util::hostname();
  auto port = uint16_t{42000};
  auto profile_file = std::string{};
  auto threads = std::thread::hardware_concurrency();
  // Parse and validate command line.
  auto r = caf::message_builder(argv + 1, argv + argc).extract_opts({
    {"core,c", "spawn core actors"},
    {"directory,d", "path to persistent state directory", dir},
    {"endpoint,e", "the node endpoint", endpoint},
    {"foreground,f", "run daemon in foreground"},
    {"log-level,l", "verbosity of console and/or log file", log_level},
    {"messages,m", "maximum messages per CAF scheduler invocation", messages},
    {"name,n", "the name of this node", name},
    {"profile,p", "enable CAF profiler", profile_file},
    {"threads,t", "number of worker threads in CAF scheduler", threads},
    {"version,v", "print version and exit"}
  });
  if (! r.error.empty())
  {
    std::cerr << r.error << std::endl;
    return 1;
  }
  if (r.opts.count("version") > 0)
  {
    std::cout << VAST_VERSION << std::endl;
    return 0;
  }
  if (r.opts.count("help") > 0)
  {
    std::cout << banner() << "\n\n" << r.helptext;
    return 0;
  }
  if (r.opts.count("endpoint") > 0 
      && ! util::parse_endpoint(endpoint, host, port))
  {
    std::cout << "invalid endpoint: " << endpoint << std::endl;
    return 1;
  }
  if (! r.remainder.empty())
  {
    auto arg = r.remainder.get_as<std::string>(0);
    std::cerr << "invalid stray argument: " << arg << std::endl;
    return 1;
  }
  // Initialize logger.
  auto verbosity = static_cast<logger::level>(log_level);
  auto log_dir = path{dir} / node::log_path();
  if (! logger::file(verbosity, (log_dir / "vast.log").str()))
  {
    std::cerr << "failed to initialize logger file backend" << std::endl;
    return 1;
  }
  if (r.opts.count("foreground"))
  {
    auto colorized = true;
    if (! logger::console(verbosity, colorized))
    {
      std::cerr << "failed to initialize logger console backend" << std::endl;
      return 1;
    }
  }
  else
  {
    VAST_DEBUG("deamonizing process (PID", util::process_id() << ")");
    if (::daemon(0, 0) != 0)
    {
      VAST_ERROR("failed to daemonize process");
      return 1;
    }
  }
  // Replace/adjust scheduler.
  if (r.opts.count("profile"))
    caf::set_scheduler(
      new caf::scheduler::profiled_coordinator<>{
        profile_file, std::chrono::milliseconds{1000}, threads, messages});
  else if (r.opts.count("threads") || r.opts.count("messages"))
    caf::set_scheduler<>(threads, messages);
  VAST_VERBOSE(banner() << "\n\n");
  VAST_VERBOSE("set scheduler threads to", threads);
  VAST_VERBOSE("set scheduler maximum throughput to",
               (messages == std::numeric_limits<size_t>::max()
                ? "unlimited" : std::to_string(messages)));
  // Initialize node actor.
  announce_types();
  auto n = caf::spawn<node>(name, dir);
  caf::scoped_actor self;
  // Create core ecosystem.
  if (r.opts.count("core") > 0)
  {
    std::vector<caf::message> msgs = {
      caf::make_message("spawn", "identifier"),
      caf::make_message("spawn", "archive"),
      caf::make_message("spawn", "index"),
      caf::make_message("spawn", "importer"),
      caf::make_message("connect", "importer", "identifier"),
      caf::make_message("connect", "importer", "archive"),
      caf::make_message("connect", "importer", "index")
    };
    // FIXME: Perform these operations asynchronously.
    for (auto& msg : msgs)
      self->sync_send(n, msg).await([](ok_atom) {});
  }
  auto exit_code = 0;
  try
  {
    // Publish the node.
    auto bound_port = caf::io::publish(n, port, host.c_str());
    VAST_VERBOSE("listening on", host << ':' << bound_port,
                 "with name \"" << name << '"');
    /// Install signal handlers and block until either a signal arrives or the
    /// node terminates.
    auto sig_mon = self->spawn<signal_monitor>(self);
    self->monitor(n);
    auto stop = false;
    self->do_receive(
      [&](caf::down_msg const& msg)
      {
        VAST_DEBUG("received DOWN from " << msg.source);
        stop = true;
      },
      [&](signal_atom, int signal)
      {
        if (signal == SIGINT || signal == SIGTERM)
          stop = true;
        else
          self->send(n, signal_atom::value, signal);
      },
      caf::others() >> [&]
      {
        VAST_WARN("received unexpected message:",
                   caf::to_string(self->current_message()));
      }).until([&] { return stop == true; });
    if (n->exit_reason() == caf::exit_reason::not_exited)
      self->send_exit(n, exit::stop);
    self->send_exit(sig_mon, exit::stop);
    self->await_all_other_actors_done();
    auto er = n->exit_reason();
    if (er == exit::error)
      exit_code = 1;
    else if (er == exit::kill)
      exit_code = 2;
    else if (! (er == exit::done || er == exit::stop))
      exit_code = 255;
  }
  catch (caf::network_error const& e)
  {
    VAST_ERROR(e.what());
    self->send_exit(n, exit::stop);
    exit_code = 1;
  }
  caf::shutdown();
  logger::destruct();
  return exit_code;
}
