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

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "vast/system/node_command.hpp"

namespace vast::system {

/// Default implementation for the export command.
/// @relates application
class export_command : public node_command {
public:
  export_command(command* parent, std::string_view name);

protected:
  int run_impl(caf::actor_system& sys, const option_map& options,
               argument_iterator begin, argument_iterator end) override;
};

} // namespace vast::system

