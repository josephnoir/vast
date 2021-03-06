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

#include <string>
#include <string_view>
#include <vector>

#include "vast/optional.hpp"
#include "vast/expected.hpp"
#include "vast/data.hpp"

#include "vast/detail/steady_map.hpp"

namespace vast {

class option_map;

/// A set of `option_declarations` that can fill an `option_map` from a CLI
/// string.
class option_declaration_set {
public:
  /// Wraps the parse state.
  enum class parse_state {
    successful,
    option_already_exists,
    not_an_option,
    name_not_declared,
    arg_passed_but_not_declared,
    arg_declared_but_not_passed,
    failed_to_parse_argument,
    type_not_parsebale,
    in_progress,
    last_state
  };

  /// A declaration of a CLI argument option.
  class option_declaration {
  public:
    /// Constructs a declation of an option.
    /// @param long_name A long name that identifies this option.
    /// @param short_names A vector of short name that identifies this option.
    /// @param description A decprition to this option.
    /// @param has_argument A flag that describes whether this option has an
    ///        argument.
    /// @param default_value A value that is used when the option is not set by
    ///        a user.
    option_declaration(std::string_view long_name, std::vector<char> short_names,
                       std::string_view description, data default_value);

    /// Returns the long name.
    const std::string& long_name() const;

    /// Returns a vector short names.
    const std::vector<char>& short_names() const;

    /// Returns a description.
    const std::string& description() const;

    /// Checks whether this option requires an argument.
    bool has_argument() const;

    /// Returns the default value.
    const data& default_value() const;

    /// Creates a `data` with the type of `default_value` from a string.
    /// @param value The string from that the `data` is created.
    /// @returns a pair consisting of a `parser_state` and a `data`.
    ///          The state is successful when the parser processes `value`
    ///          without an error. If the state is not successful the
    ///          *default_value* is returned.
    std::pair<parse_state, data> parse(std::string_view value) const;

  private:
    std::string long_name_;
    std::vector<char> short_names_;
    std::string description_;
    data default_value_;
  };

  using argument_iterator = std::vector<std::string>::const_iterator;

  /// Creates an a set of `option_declaration`.
  option_declaration_set();

  /// Adds an `option_declation` to the set.
  /// @param name The Long name and optional short option names in the format
  ///             "<long name>,[<short names 1><short name 2><...>]", where a
  ///             short name consists of exact one char.
  /// @returns An error if a) no long option name exists, b) long option is name
  ///          taken, c) short option name is taken
  expected<void> add(std::string_view name, std::string_view desciption,
                     data default_value);

  /// Creates a summary of all option declarations.
  std::string usage() const;

  /// Determines the number of added `options_declarations's.
  size_t size() const;

  /// Searches for an `option_declaration` by its long name.
  optional<const option_declaration&> find(std::string_view long_name) const;

  /// Searches for an `option_declaration` by its short name.
  optional<const option_declaration&> find(char short_name) const;

  /// Fills an `option_map` from parsed CLI arguments.
  /// @param option_map The map of options that shall be filled.
  /// @param begin The iterator to the first argument that shall being parsed.
  /// @param end The *past-the-end* iterator of the last argument.
  /// @returns a pair constisting of a 'parser_state' and an iterator.
  ///          The `state` is *successful* when all arguments are successfully
  ///          parsed. Otherwise, it contains a value specific to the occurred
  ///          error. The 'iterator' points to the argument where the parser
  ///          encountered an error otherwise it points to the `end`.
  std::pair<parse_state, argument_iterator>
  parse(option_map& xs, argument_iterator begin, argument_iterator end) const;

private:
  using option_ptr = std::shared_ptr<option_declaration>;
  detail::steady_map<std::string, option_ptr> long_opts_;
  detail::steady_map<char, option_ptr> short_opts_;
};

const char* to_string(option_declaration_set::parse_state x);

} // namespace vast
