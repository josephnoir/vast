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

#include <sstream>

#include "vast/error.hpp"
#include "vast/option_map.hpp"

namespace vast {

optional<const option_map::mapped_type&> 
option_map::operator[](std::string_view name) const {
  // TODO: Remove explicit conversion to a string.
  // This requires to override *find* to support equivalent keys.
  if (auto x = xs_.find(std::string{name}); x != xs_.end())
    return x->second;
  return {};
}

void option_map::set(const key_type& name, const mapped_type& x) {
  xs_[name] = x;
}

expected<void> option_map::add(const key_type& name, const mapped_type& x) {
  if (auto it = xs_.find(name); it != xs_.end()) 
    return make_error(ec::unspecified, "name: " + name + " already exist");
  set(name, x);
  return {};
}

void option_map::clear() {
  xs_.clear();
}

option_map::iterator option_map::begin() {
  return xs_.begin();
}

option_map::const_iterator option_map::begin() const {
  return xs_.begin();
}

option_map::iterator option_map::end() {
  return xs_.end();
}

option_map::const_iterator option_map::end() const {
  return xs_.end();
}

option_map::reverse_iterator option_map::rbegin() {
  return xs_.rbegin();
}

option_map::const_reverse_iterator option_map::rbegin() const {
  return xs_.rbegin();
}

option_map::reverse_iterator option_map::rend() {
  return xs_.rend();
}

option_map::const_reverse_iterator option_map::rend() const {
  return xs_.rend();
}

bool option_map::empty() const {
  return xs_.empty();
}

option_map::size_type option_map::size() const {
  return xs_.size();
}

} // namespace vast
