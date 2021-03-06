/******************************************************************************
 *                    _   _____   __________                                  *
 *                   | | / / _ | / __/_  __/     Visibility                   *
 *                   | |/ / __ |_\ \  / /          Across                     *
 *                   |___/_/ |_/___/ /_/       Space and Time                 *
 *                                                                            *
 * This file is part of VAST. It is subject to the license terms in the       *
 * LICENSE file found in the top-level directory of this distribution and at  *
 * http://vast.io/license. No part of VAST, including this file, may be       *
 * copied, modified, propagated, or distributed except according to the terms *
 * contained in the LICENSE file.                                             *
 ******************************************************************************/

#include <algorithm>
#include <iostream>

#include "vast/config.hpp"

#include <caf/message_builder.hpp>
#include <caf/io/middleman.hpp>
#ifdef VAST_USE_OPENCL
#include <caf/opencl/manager.hpp>
#endif
#ifdef VAST_USE_OPENSSL
#include <caf/openssl/manager.hpp>
#endif

#include "vast/batch.hpp"
#include "vast/bitmap.hpp"
#include "vast/config.hpp"
#include "vast/error.hpp"
#include "vast/event.hpp"
#include "vast/expression.hpp"
#include "vast/operator.hpp"
#include "vast/query_options.hpp"
#include "vast/schema.hpp"
#include "vast/time.hpp"
#include "vast/type.hpp"
#include "vast/uuid.hpp"

#include "vast/system/configuration.hpp"
#include "vast/system/replicated_store.hpp"
#include "vast/system/query_statistics.hpp"
#include "vast/system/tracker.hpp"

#include "vast/detail/adjust_resource_consumption.hpp"
#include "vast/detail/string.hpp"
#include "vast/detail/system.hpp"

using namespace caf;

namespace vast::system {

configuration::configuration() {
  // -- CAF configuration ------------------------------------------------------
  // Consider only VAST's log messages by default.
  logger_component_filter = "vast";
  // Use 'vast.ini' instead of generic 'caf-application.ini'.
  config_file_path = "vast.ini";
  // Register VAST's custom types.
  add_message_type<batch>("vast::batch");
  add_message_type<bitmap>("vast::bitmap");
  add_message_type<data>("vast::data");
  add_message_type<event>("vast::event");
  add_message_type<expression>("vast::expression");
  add_message_type<query_options>("vast::query_options");
  add_message_type<relational_operator>("vast::relational_operator");
  add_message_type<schema>("vast::schema");
  add_message_type<type>("vast::type");
  add_message_type<timespan>("vast::timespan");
  add_message_type<uuid>("vast::uuid");
  // Containers
  add_message_type<std::vector<event>>("std::vector<vast::event>");
  // Actor-specific messages
  add_message_type<component_map>("vast::system::component_map");
  add_message_type<component_map_entry>("vast::system::component_map_entry");
  add_message_type<registry>("vast::system::registry");
  add_message_type<query_statistics>("vast::system::query_statistics");
  add_message_type<actor_identity>("vast::system::actor_identity");
  // Register VAST's custom error type.
  auto vast_renderer = [](uint8_t x, atom_value, const message& msg) {
    std::string result;
    result += "got ";
    switch (static_cast<ec>(x)) {
      default:
        result += to_string(static_cast<ec>(x));
        break;
      case ec::unspecified:
        result += "unspecified error";
        break;
    };
    if (!msg.empty()) {
      result += ": ";
      result += deep_to_string(msg);
    }
    return result;
  };
  auto caf_renderer = [](uint8_t x, atom_value, const message& msg) {
    std::string result;
    result += "got caf::";
    result += to_string(static_cast<sec>(x));
    if (!msg.empty()) {
      result += ": ";
      result += deep_to_string(msg);
    }
    return result;
  };
  add_error_category(atom("vast"), vast_renderer);
  add_error_category(atom("system"), caf_renderer);
  // Load modules.
  load<io::middleman>();
  middleman_enable_automatic_connections = true;
  // GPU acceleration.
#ifdef VAST_USE_OPENCL
  load<opencl::manager>();
  add_message_type<std::vector<uint32_t>>("std::vector<uint32_t>");
#endif
#ifdef VAST_USE_OPENSSL
  load<openssl::manager>();
#endif
}

configuration::configuration(int argc, char** argv) : configuration{} {
  command_line = {argv + 1, argv + argc};
  // Move CAF options to the end of the command line, parse them, and then
  // remove them.
  auto is_vast_opt = [](auto& x) { return !starts_with(x, "--caf#"); };
  auto caf_opt = std::stable_partition(command_line.begin(),
                                       command_line.end(), is_vast_opt);
  auto opt_msg = message_builder{caf_opt, command_line.end()}.to_message();
  parse(opt_msg);
  command_line.erase(caf_opt, command_line.end());
}

} // namespace vast::system
