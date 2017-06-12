#ifndef VAST_FORMAT_MRT_HPP
#define VAST_FORMAT_MRT_HPP

#include <iostream>

#include "vast/concept/parseable/core.hpp"
#include "vast/concept/parseable/numeric.hpp"
#include "vast/concept/parseable/vast/data.hpp"
#include "vast/event.hpp"
#include "vast/expected.hpp"
#include "vast/schema.hpp"

namespace vast {
namespace format {
namespace mrt {

/// A parser that reading bgp messages from MRT files.
struct mrt_parser : parser<mrt_parser> {
  using attribute = event;

  mrt_parser();

  template <class Iterator>
  bool parse(Iterator& f, Iterator& l, event& e) const {
    return true;
  }



  type mrt_bgp4mp_announce_type;
  type mrt_table_dump_type;
  type mrt_bgp4mp_withdraw_type;
  type mrt_bgp4mp_state_change_type;
  type mrt_bgp4mp_open_type;
  type mrt_bgp4mp_notification_type;
  type mrt_bgp4mp_keepalive_type;
};

/// A MRT reader.
class reader {
public:
  reader() = default;

  /// Constructs a MRT reader.
  explicit reader(std::unique_ptr<std::istream> input);

  expected<event> read();

  expected<void> schema(vast::schema const& sch);

  expected<vast::schema> schema() const;

  const char* name() const;

private:
  mrt_parser parser_;
  std::unique_ptr<std::istream> input_;
  std::vector<event> event_queue_;
};

} // namespace mrt
} // namespace format
} // namespace vast

#endif
