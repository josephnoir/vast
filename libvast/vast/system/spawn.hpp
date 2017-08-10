#ifndef VAST_SYSTEM_SPAWN_HPP
#define VAST_SYSTEM_SPAWN_HPP

#include <string>

#include <caf/local_actor.hpp>

#include "vast/expected.hpp"
#include "vast/filesystem.hpp"

#include "vast/system/node_state.hpp"

namespace vast {
namespace system {

struct options {
  caf::message params;
  path dir;
  std::string label;
};

expected<caf::actor> spawn_archive(caf::local_actor* self,
                                   options& opts);

expected<caf::actor> spawn_exporter(caf::stateful_actor<node_state>* self,
                                    options& opts);

expected<caf::actor> spawn_importer(caf::stateful_actor<node_state>* self,
                                    options& opts);

expected<caf::actor> spawn_index(caf::local_actor* self, options& opts);

expected<caf::actor> spawn_metastore(caf::local_actor* self, options& opts);

expected<caf::actor> spawn_profiler(caf::local_actor* self, options& opts);

expected<caf::actor> spawn_source(caf::local_actor* self, options& opts);

expected<caf::actor> spawn_sink(caf::local_actor* self, options& opts);

} // namespace system
} // namespace vast

#endif
