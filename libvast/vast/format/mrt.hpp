#ifndef VAST_FORMAT_MRT_HPP
#define VAST_FORMAT_MRT_HPP

#include <iostream>

#include "vast/error.hpp"
#include "vast/logger.hpp"
#include "vast/event.hpp"
#include "vast/expected.hpp"
#include "vast/schema.hpp"
#include "vast/address.hpp"
#include "vast/data.hpp"
#include "vast/concept/parseable/core.hpp"
#include "vast/concept/parseable/numeric.hpp"
#include "vast/concept/parseable/string.hpp"
#include "vast/concept/parseable/vast/data.hpp"
#include "vast/concept/printable/std/chrono.hpp"
#include "vast/concept/printable/vast/data.hpp"
#include "vast/concept/printable/vast/address.hpp"
#include "vast/concept/printable/vast/subnet.hpp"

namespace vast {
namespace format {
namespace mrt {

/// A parser that reading bgp messages from MRT files.
struct mrt_parser {
  using attribute = event;

  static constexpr size_t mrt_header_length = 12;

  struct mrt_header {
    vast::timestamp timestamp;
    count type = 0;
    count subtype = 0;
    count length = 0;
  };

  struct bgp4mp_info {
    bool as4;
    bool afi_ipv4;
    count peer_as_nr = 0;
    address peer_ip_addr;
    count length = 0;
  };

  mrt_parser();

  bool parse_mrt_header(std::vector<char>& raw, mrt_header& header);
  bool parse_bgp4mp_prefix(std::vector<char>& raw, bgp4mp_info& info,
                           count length, std::vector<subnet>& prefix);
  bool parse_mrt_message_table_dump_v2(std::vector<char>& raw,
                                       mrt_header& header);
  bool parse_mrt_message_bgp4mp_state_change(std::vector<char>& raw, bool as4,
                                             mrt_header& header,
                                             std::vector<event> &event_queue);
  bool parse_bgp4mp_message_open(std::vector<char>& raw, mrt_header& header,
                                 bgp4mp_info& info,
                                 std::vector<event>& event_queue);
  bool parse_bgp4mp_message_update(std::vector<char>& raw, mrt_header& header,
                                   bgp4mp_info& info,
                                   std::vector<event>& event_queue);
  bool parse_bgp4mp_message_notification();
  bool parse_bgp4mp_message_keepalive();
  bool parse_mrt_message_bgp4mp_message(std::vector<char>& raw, bool as4,
                                        mrt_header& header,
                                        std::vector<event> &event_queue);
  bool parse_mrt_message_bgp4mp(std::vector<char>& raw, mrt_header& header,
                                std::vector<event> &event_queue);
  bool parse_mrt_message_bgp4mp_et(std::vector<char>& raw, mrt_header& header,
                                   std::vector<event> &event_queue);
  bool parse(std::istream& input, std::vector<event> &event_queue);

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
