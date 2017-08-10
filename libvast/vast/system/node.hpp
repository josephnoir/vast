#ifndef VAST_SYSTEM_NODE_HPP
#define VAST_SYSTEM_NODE_HPP

#include <string>

#include "vast/filesystem.hpp"

#include "vast/system/node_state.hpp"

namespace vast {
namespace system {

/// Spawns a node.
/// @param self The actor handle
/// @param id The unique ID of the node.
/// @param dir The directory where to store persistent state.
caf::behavior node(caf::stateful_actor<node_state>* self, std::string id,
                   path dir);

} // namespace system
} // namespace vast

#endif
