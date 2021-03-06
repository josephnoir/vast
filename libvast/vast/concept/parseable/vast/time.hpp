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

#include <chrono>
#include <ctime>
#include <cstring>

#include <date/date.h>

#include "vast/access.hpp"
#include "vast/time.hpp"
#include "vast/concept/parseable/core.hpp"
#include "vast/concept/parseable/numeric/real.hpp"
#include "vast/concept/parseable/string/char_class.hpp"

namespace vast {

// TODO: replace with Howard Hinnant's TZ stuff and then move into
// vast/concept/parseable/std/chrono.

template <class Rep, class Period>
struct duration_parser : parser<duration_parser<Rep, Period>> {
  using duration_type = std::chrono::duration<Rep, Period>;
  using attribute = duration_type;

  template <class Duration>
  static auto cast(Duration d) {
    return std::chrono::duration_cast<duration_type>(d);
  }

  template <class Iterator, class Attribute>
  bool parse(Iterator& f, const Iterator& l, Attribute& a) const {
    using namespace parsers;
    auto save = f;
    Rep i;
    if (!make_parser<Rep>{}(f, l, i))
      return false;
    static auto whitespace = *space;
    if (!whitespace(f, l, unused)) {
      f = save;
      return false;
    }
    using namespace std::chrono;
    static auto unit
      = "nsecs"_p ->* [] { return cast(nanoseconds(1)); }
      | "nsec"_p  ->* [] { return cast(nanoseconds(1)); }
      | "ns"_p    ->* [] { return cast(nanoseconds(1)); }
      | "usecs"_p ->* [] { return cast(microseconds(1)); }
      | "usec"_p  ->* [] { return cast(microseconds(1)); }
      | "us"_p    ->* [] { return cast(microseconds(1)); }
      | "msecs"_p ->* [] { return cast(milliseconds(1)); }
      | "msec"_p  ->* [] { return cast(milliseconds(1)); }
      | "ms"_p    ->* [] { return cast(milliseconds(1)); }
      | "secs"_p  ->* [] { return cast(seconds(1)); }
      | "sec"_p   ->* [] { return cast(seconds(1)); }
      | "s"_p     ->* [] { return cast(seconds(1)); }
      | "mins"_p  ->* [] { return cast(minutes(1)); }
      | "min"_p   ->* [] { return cast(minutes(1)); }
      | "m"_p     ->* [] { return cast(minutes(1)); }
      | "hrs"_p   ->* [] { return cast(hours(1)); }
      | "hours"_p ->* [] { return cast(hours(1)); }
      | "hour"_p  ->* [] { return cast(hours(1)); }
      | "h"_p     ->* [] { return cast(hours(1)); }
      | "days"_p  ->* [] { return cast(hours(24)); }
      | "day"_p   ->* [] { return cast(hours(24)); }
      | "d"_p     ->* [] { return cast(hours(24)); }
      | "weeks"_p ->* [] { return cast(hours(24 * 7)); }
      | "week"_p  ->* [] { return cast(hours(24 * 7)); }
      | "w"_p     ->* [] { return cast(hours(24 * 7)); }
      | "years"_p ->* [] { return cast(hours(24 * 365)); }
      | "year"_p  ->* [] { return cast(hours(24 * 365)); }
      | "y"_p     ->* [] { return cast(hours(24 * 365)); }
      ;
    if (!unit(f, l, a)) {
      f = save;
      return false;
    }
    a *= i;
    return true;
  }
};

template <class Rep, class Period>
struct parser_registry<std::chrono::duration<Rep, Period>> {
  using type = duration_parser<Rep, Period>;
};

namespace parsers {

template <class Rep, class Period>
auto const duration = duration_parser<Rep, Period>{};

auto const timespan = duration<vast::timespan::rep, vast::timespan::period>;

} // namespace parsers

struct ymdhms_parser : vast::parser<ymdhms_parser> {
  using attribute = timestamp;

  static auto make() {
    using namespace std::chrono;
    using namespace date;
    auto year = integral_parser<int, 4, 4>{}
                  .with([](auto x) { return x >= 1900; });
    auto mon = integral_parser<int, 2, 2>{}
                 .with([](auto x) { return x >= 1 && x <= 12; });
    auto day = integral_parser<int, 2, 2>{}
                 .with([](auto x) { return x >= 1 && x <= 31; });
    auto hour = integral_parser<int, 2, 2>{}
                 .with([](auto x) { return x >= 0 && x <= 23; });
    auto min = integral_parser<int, 2, 2>{}
                 .with([](auto x) { return x >= 0 && x <= 59; });
    auto sec = integral_parser<int, 2, 2>{}
                 .with([](auto x) { return x >= 0 && x <= 60; });
    return year >> '-' >> mon
        >> ~('-' >> day >> ~('+' >> hour >> ~(':' >> min >> ~(':' >> sec))));
  }

  template <class Iterator>
  bool parse(Iterator& f, const Iterator& l, unused_type) const {
    static auto p = make();
    return p(f, l, unused);
  }

  template <class Iterator>
  bool parse(Iterator& f, const Iterator& l, timestamp& tp) const {
    using namespace std::chrono;
    using namespace date;
    auto secs = 0;
    auto mins = 0;
    auto hrs = 0;
    auto dys = 1;
    auto mons = 1;
    auto yrs = 0;
    // Compose to match parser attribute.
    auto ms = std::tie(mins, secs);
    auto hms = std::tie(hrs, ms);
    auto dhms = std::tie(dys, hms);
    static auto p = make();
    if (!p(f, l, yrs, mons, dhms))
      return false;
    sys_days ymd = year{yrs} / mons / dys;
    auto delta = hours{hrs} + minutes{mins} + seconds{secs};
    tp = timestamp{ymd} + delta;
    return true;
  }
};

namespace parsers {

auto const ymdhms = ymdhms_parser{};

/// Parses a fractional seconds-timestamp as UNIX epoch.
auto const epoch = real_opt_dot
  ->* [](double d) { 
    using std::chrono::duration_cast; 
    return timestamp{duration_cast<vast::timespan>(double_seconds{d})};
  };

} // namespace parsers

struct timestamp_parser : parser<timestamp_parser> {
  using attribute = timestamp;

  template <class Iterator, class Attribute>
  bool parse(Iterator& f, const Iterator& l, Attribute& a) const {
    static auto plus = [](timespan span) {
      return timestamp::clock::now() + span;
    };
    static auto minus = [](timespan span) {
      return timestamp::clock::now() - span;
    };
    static auto ws = ignore(*parsers::space);
    static auto p
      = parsers::ymdhms
      | '@' >> parsers::epoch
      | "now" >> ws >> ( '+' >> ws >> parsers::timespan ->* plus
                       | '-' >> ws >> parsers::timespan ->* minus )
      | "now"_p ->* []() { return timestamp::clock::now(); }
      | "in" >> ws >> parsers::timespan ->* plus
      | (parsers::timespan ->* minus) >> ws >> "ago"
      ;
    return p(f, l, a);
  }
};

template <>
struct parser_registry<timestamp> {
  using type = timestamp_parser;
};

namespace parsers {

static auto const timestamp = timestamp_parser{};

} // namespace parsers
} // namespace vast

