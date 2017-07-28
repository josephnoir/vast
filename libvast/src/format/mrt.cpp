#include "vast/format/mrt.hpp"

namespace vast {
namespace format {
namespace mrt {

mrt_parser::mrt_parser() {
  // Announce type.
  auto fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"source_ip", address_type{}},
    {"source_as", count_type{}},
    {"prefix", subnet_type{}},
    {"as_path", vector_type{count_type{}}},
    {"origin_as", count_type{}},
    {"origin", string_type{}},
    {"nexthop", address_type{}},
    {"local_pref", count_type{}},
    {"med", count_type{}},
    {"community", string_type{}},
    {"atomic_aggregate", string_type{}},
    {"aggregator", string_type{}},
  };
  mrt_bgp4mp_announce_type = record_type{fields};
  mrt_bgp4mp_announce_type.name("mrt::bgp4mp::announcement");
  // Table dump type.
  mrt_table_dump_type = record_type{std::move(fields)};
  mrt_table_dump_type.name("mrt::table_dump");
  // Withdraw type
  auto withdraw_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"source_ip", address_type{}},
    {"source_as", count_type{}},
    {"prefix", subnet_type{}},
  };
  mrt_bgp4mp_withdraw_type = record_type{std::move(withdraw_fields)};
  mrt_bgp4mp_withdraw_type.name("mrt::bgp4mp::withdrawn");
  // State-change type.
  auto state_change_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"source_ip", address_type{}},
    {"source_as", count_type{}},
    {"old_state", string_type{}},
    {"new_state", string_type{}},
  };
  mrt_bgp4mp_state_change_type = record_type{std::move(state_change_fields)};
  mrt_bgp4mp_state_change_type.name("mrt::bgp4mp::state_change");
  // Open type.
  auto open_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"version", count_type{}},
    {"my_autonomous_system", count_type{}},
    {"hold_time", count_type{}},
    {"bgp_identifier", count_type{}},
  };
  mrt_bgp4mp_open_type = record_type{std::move(open_fields)};
  mrt_bgp4mp_open_type.name("mrt::bgp4mp::open");
  // Notification type.
  auto notification_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"error_code", count_type{}},
    {"error_subcode", count_type{}},
  };
  mrt_bgp4mp_notification_type = record_type{std::move(notification_fields)};
  mrt_bgp4mp_notification_type.name("mrt::bgp4mp::notification");
  // Keepalive type.
  auto keepalive_fields = std::vector<record_field>{
      {"timestamp", timestamp_type{}},
  };
  mrt_bgp4mp_keepalive_type = record_type{std::move(keepalive_fields)};
  mrt_bgp4mp_keepalive_type.name("mrt::bgp4mp::keepalive");
}

bool mrt_parser::parse_mrt_header(std::vector<char>& raw, mrt_header& header) {
  using namespace parsers;
  using namespace std::chrono;
  auto count16 = b16be->*[](uint16_t x) { return count{x}; };
  auto count32 = b32be->*[](uint32_t x) { return count{x}; };
  auto stime32 = b32be->*[](uint32_t x) { return vast::timestamp{seconds(x)}; };
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  2.  MRT Common Header
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Type              |            Subtype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Length                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Message... (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  auto mrt_header_parser = stime32 >> count16 >> count16 >> count32;
  if (!mrt_header_parser(raw, header.timestamp, header.type, header.subtype,
                         header.length))
    return false;
  VAST_DEBUG("mrt-parser header", "timestamp", header.timestamp, "type",
             header.type, "subtype", header.subtype, "length",
             header.length);
  return true;
}

bool mrt_parser::parse_mrt_message_table_dump_v2(std::vector<char>& raw,
                                                 mrt_header& header) {
  return true;
}

bool mrt_parser::parse_mrt_message_bgp4mp_state_change(bool as4,
                                                       std::vector<char>& raw) {
  using namespace parsers;
  auto count16 = b16be->*[](uint16_t x) { return count{x}; };
  auto count32 = b32be->*[](uint32_t x) { return count{x}; };
  auto ipv4 = b32be->*[](uint32_t x) {
    return address{&x, address::ipv4, address::host};
  };
  auto ipv6 = bytes<16>->*[](std::array<uint8_t, 16> x) {
    return address{x.data(), address::ipv6, address::host};
  };
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.1.  BGP4MP_STATE_CHANGE Subtype
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Peer AS Number        |        Local AS Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Interface Index        |        Address Family         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Peer IP Address (variable)               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Local IP Address (variable)              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Old State          |          New State            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  count peer_as_nr = 0;
  count local_as_nr = 0;
  count interface_index = 0;
  count addr_family = 0;
  address peer_ip_addr;
  address local_ip_addr;
  count old_state;
  count new_state;
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.4.  BGP4MP_STATE_CHANGE_AS4 Subtype
    This subtype updates the BGP4MP_STATE_CHANGE Subtype to support
    4-byte AS numbers.
  */
  if (as4) {
    auto bgp4mp_state_change_parser = count32 >> count32 >> count16 >> count16;
    if(!bgp4mp_state_change_parser(raw, peer_as_nr, local_as_nr,
                                   interface_index, addr_family))
      return false;
    raw = std::vector<char>((raw.begin() + 12), raw.end());
  } else {
    auto bgp4mp_state_change_parser = count16 >> count16 >> count16 >> count16;
    if(!bgp4mp_state_change_parser(raw, peer_as_nr, local_as_nr,
                                   interface_index, addr_family))
      return false;
    raw = std::vector<char>((raw.begin() + 8), raw.end());
  }
  VAST_DEBUG("mrt-parser bgp4mp-state-change", "peer_as_nr", peer_as_nr,
             "local_as_nr", local_as_nr, "interface_index", interface_index,
             "addr_family", addr_family);
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.1.  BGP4MP_STATE_CHANGE Subtype
  Address Family Types:
    1    AFI_IPv4
    2    AFI_IPv6
  */
  if (addr_family == 1) {
    auto bgp4mp_state_change_parser = ipv4 >> ipv4 >> count16 >> count16;
    if (!bgp4mp_state_change_parser(raw, peer_ip_addr, local_ip_addr,
                                    old_state, new_state))
      return false;
  } else if (addr_family == 2) {
    auto bgp4mp_state_change_parser = ipv6 >> ipv6 >> count16 >> count16;
    if (!bgp4mp_state_change_parser(raw, peer_ip_addr, local_ip_addr,
                                    old_state, new_state))
      return false;
  } else {
    return false;
  }
  VAST_DEBUG("mrt-parser bgp4mp-state-change", "peer_ip_addr", peer_ip_addr,
             "local_ip_addr", local_ip_addr, "old_state", old_state,
             "new_state", new_state);
  return true;
}

bool mrt_parser::parse_bgp4mp_message_open(bool as4, std::vector<char>& raw) {
  using namespace parsers;
  auto count8 = byte->*[](uint8_t x) { return count{x}; };
  auto count16 = b16be->*[](uint16_t x) { return count{x}; };
  auto count32 = b32be->*[](uint32_t x) { return count{x}; };
  /*
  RFC 4271 https://tools.ietf.org/html/rfc4271
  4.2.  OPEN Message Format
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+
    |    Version    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     My Autonomous System      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Hold Time           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         BGP Identifier                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Opt Parm Len  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |             Optional Parameters (variable)                    |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  count version;
  count my_autonomous_system;
  count hold_time;
  count bgp_identifier;
  count opt_parm_len;
  if (as4) {
    auto bgp4mp_messasge_open_parser = count8 >> count32 >> count16 >>
                                       count32 >> count8;
    if (!bgp4mp_messasge_open_parser(raw, version, my_autonomous_system,
                                     hold_time, bgp_identifier, opt_parm_len))
      return false;
    raw = std::vector<char>((raw.begin() + 12), raw.end());
  } else {
    auto bgp4mp_messasge_open_parser = count8 >> count16 >> count16 >>
                                       count32 >> count8;
    if (!bgp4mp_messasge_open_parser(raw, version, my_autonomous_system,
                                     hold_time, bgp_identifier, opt_parm_len))
      return false;
    raw = std::vector<char>((raw.begin() + 10), raw.end());
  }
  VAST_DEBUG("mrt-parser bgp4mp-message-open", "version", version,
             "my_autonomous_system", my_autonomous_system, "hold_time",
             hold_time, "opt_parm_len", opt_parm_len);
  return true;
}

bool mrt_parser::parse_bgp4mp_message_update(bool as4, std::vector<char>& raw) {
  /*
  RFC 4271 https://tools.ietf.org/html/rfc4271
  4.3.  UPDATE Message Format
    +-----------------------------------------------------+
    |   Withdrawn Routes Length (2 octets)                |
    +-----------------------------------------------------+
    |   Withdrawn Routes (variable)                       |
    +-----------------------------------------------------+
    |   Total Path Attribute Length (2 octets)            |
    +-----------------------------------------------------+
    |   Path Attributes (variable)                        |
    +-----------------------------------------------------+
    |   Network Layer Reachability Information (variable) |
    +-----------------------------------------------------+
  */
  /*
  RFC 4271 https://tools.ietf.org/html/rfc4271
  4.3.  UPDATE Message Format
  Withdrawn Routes
    +---------------------------+
    |   Length (1 octet)        |
    +---------------------------+
    |   Prefix (variable)       |
    +---------------------------+
  */
  return true;
}

bool mrt_parser::parse_bgp4mp_message_notification() {
  return true;
}

bool mrt_parser::parse_bgp4mp_message_keepalive() {
  return true;
}

bool mrt_parser::parse_mrt_message_bgp4mp_message(bool as4,
                                                  std::vector<char>& raw) {
  using namespace parsers;
  auto count8 = byte->*[](uint8_t x) { return count{x}; };
  auto count16 = b16be->*[](uint16_t x) { return count{x}; };
  auto count32 = b32be->*[](uint32_t x) { return count{x}; };
  auto ipv4 = b32be->*[](uint32_t x) {
    return address{&x, address::ipv4, address::host};
  };
  auto ipv6 = bytes<16>->*[](std::array<uint8_t, 16> x) {
    return address{x.data(), address::ipv6, address::host};
  };
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.2.  BGP4MP_MESSAGE Subtype
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Peer AS Number        |        Local AS Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Interface Index        |        Address Family         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Peer IP Address (variable)               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Local IP Address (variable)              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    BGP Message... (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  count peer_as_nr = 0;
  count local_as_nr = 0;
  count interface_index = 0;
  count addr_family = 0;
  address peer_ip_addr;
  address local_ip_addr;
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.3.  BGP4MP_MESSAGE_AS4 Subtype
    This subtype updates the BGP4MP_MESSAGE Subtype to support 4-byte AS
    numbers.
  */
  if (as4) {
    auto bgp4mp_message_parser = count32 >> count32 >> count16 >> count16;
    if(!bgp4mp_message_parser(raw, peer_as_nr, local_as_nr, interface_index,
                              addr_family))
      return false;
    raw = std::vector<char>((raw.begin() + 12), raw.end());
  } else {
    auto bgp4mp_message_parser = count16 >> count16 >> count16 >> count16;
    if(!bgp4mp_message_parser(raw, peer_as_nr, local_as_nr, interface_index,
                              addr_family))
      return false;
    raw = std::vector<char>((raw.begin() + 8), raw.end());
  }
  VAST_DEBUG("mrt-parser bgp4mp-message", "peer_as_nr", peer_as_nr,
             "local_as_nr", local_as_nr, "interface_index", interface_index,
             "addr_family", addr_family);
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.2.  BGP4MP_MESSAGE Subtype
  Address Family Types:
    1    AFI_IPv4
    2    AFI_IPv6
  */
  if (addr_family == 1) {
    auto bgp4mp_message_parser = ipv4 >> ipv4;
    if (!bgp4mp_message_parser(raw, peer_ip_addr, local_ip_addr))
      return false;
    raw = std::vector<char>((raw.begin() + 8), raw.end());
  } else if (addr_family == 2) {
    auto bgp4mp_message_parser = ipv6 >> ipv6;
    if (!bgp4mp_message_parser(raw, peer_ip_addr, local_ip_addr))
      return false;
    raw = std::vector<char>((raw.begin() + 32), raw.end());
  } else {
    return false;
  }
  VAST_DEBUG("mrt-parser bgp4mp-message", "peer_ip_addr", peer_ip_addr,
             "local_ip_addr", local_ip_addr);
  /*
  RFC 4271 https://tools.ietf.org/html/rfc4271
  4.1.  Message Header Format
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                                                               +
    |                           Marker                              |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Length               |      Type     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */
  raw = std::vector<char>((raw.begin() + 16), raw.end()); //Marker
  count length;
  count type;
  auto bgp4mp_message_parser = count16 >> count8;
  if (!bgp4mp_message_parser(raw, length, type))
    return false;
  raw = std::vector<char>((raw.begin() + 3), raw.end());
  VAST_DEBUG("mrt-parser bgp4mp-message", "length", length, "type", type);
  /*
  RFC 4271 https://tools.ietf.org/html/rfc4271
  4.1.  Message Header Format
  Types:
    1 - OPEN
    2 - UPDATE
    3 - NOTIFICATION
    4 - KEEPALIVE
  */
  if (type == 1) {
    return parse_bgp4mp_message_open(as4, raw);
  } else if (type == 2) {
    return parse_bgp4mp_message_update(as4, raw);
  } else if (type == 3) {
    return parse_bgp4mp_message_notification();
  } else if (type == 4) {
    return parse_bgp4mp_message_keepalive();
  } else {
    VAST_WARNING("mrt-parser", "Unsupported MRT BGP4MP message type", type);
    return false;
  }
}

bool mrt_parser::parse_mrt_message_bgp4mp(std::vector<char>& raw,
                                          mrt_header& header) {
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.4.  BGP4MP Type
  Subtypes:
    0    BGP4MP_STATE_CHANGE
    1    BGP4MP_MESSAGE
    4    BGP4MP_MESSAGE_AS4
    5    BGP4MP_STATE_CHANGE_AS4
    6    BGP4MP_MESSAGE_LOCAL
    7    BGP4MP_MESSAGE_AS4_LOCAL
  */
  if (header.subtype == 0) {
    return parse_mrt_message_bgp4mp_state_change(false, raw);
  } else if (header.subtype == 1) {
    return parse_mrt_message_bgp4mp_message(false, raw);
  } else if (header.subtype == 4) {
    return parse_mrt_message_bgp4mp_message(true, raw);
  } else if (header.subtype == 5) {
    return parse_mrt_message_bgp4mp_state_change(true, raw);
  } else {
    VAST_WARNING("mrt-parser", "Unsupported MRT BGP4MP subtype",
                 header.subtype);
    return false;
  }
}

bool mrt_parser::parse_mrt_message_bgp4mp_et(std::vector<char>& raw,
                                             mrt_header& header) {
  using namespace parsers;
  using namespace std::chrono;
  auto ustime32 = b32be->*[](uint32_t x) {
    return vast::timestamp{microseconds(x)};
  };
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  3.  Extended Timestamp MRT Header
    [...]
    This field, Microsecond Timestamp, contains an unsigned 32BIT offset value
    in microseconds, which is added to the Timestamp field value.
    [...]
    The Microsecond Timestamp immediately follows the Length field in the MRT
    Common Header and precedes all other fields in the message.
    The Microsecond Timestamp is included in the computation of the Length field
    value.
    [...]
  */
  vast::timestamp timestamp_et;
  auto mrt_et_parser = ustime32;
  if (!mrt_et_parser(raw, timestamp_et))
    return false;
  //header.timestamp += timestamp_et; TODO
  raw = std::vector<char>((raw.begin() + 4), raw.end());
  VAST_DEBUG("mrt-parser bgp4mp-message-et", "timestamp", header.timestamp);
  return parse_mrt_message_bgp4mp(raw, header);
}

bool mrt_parser::parse(std::istream& input, std::vector<event>& event_queue) {
  mrt_header header;
  std::vector<char> raw(mrt_header_length);
  input.read(raw.data(), mrt_header_length);
  if (!input) {
    if(input.eof())
      return true;
    VAST_ERROR("mrt-parser", "Only", input.gcount(), "of", mrt_header_length,
                 "bytes could be read from stream");
    return false;
  }
  if (!parse_mrt_header(raw, header))
    return false;
  raw.resize(header.length);
  input.read(raw.data(), header.length);
  if (!input) {
    VAST_ERROR("mrt-parser", "Only", input.gcount(), "of", header.length,
                 "bytes could be read from stream");
    return false;
  }
  /*
  RFC 6396 https://tools.ietf.org/html/rfc6396
  4.  MRT Types
    11   OSPFv2
    12   TABLE_DUMP
    13   TABLE_DUMP_V2
    16   BGP4MP
    17   BGP4MP_ET
    32   ISIS
    33   ISIS_ET
    48   OSPFv3
    49   OSPFv3_ET
  */
  if (header.type == 13) {
    return parse_mrt_message_table_dump_v2(raw, header);
  } else if (header.type == 16) {
    return parse_mrt_message_bgp4mp(raw, header);
  } else if (header.type == 17) {
    return parse_mrt_message_bgp4mp_et(raw, header);
  } else {
    VAST_WARNING("mrt-parser", "Unsupported MRT type", header.type);
    return false;
  }
}

reader::reader(std::unique_ptr<std::istream> input) : input_{std::move(input)} {
  VAST_ASSERT(input_);
}

expected<event> reader::read() {
  if (!event_queue_.empty()) {
    event current_event = event_queue_.back();
    event_queue_.pop_back();
    return std::move(current_event);
  }
  if (input_->eof()) {
    return make_error(ec::end_of_input, "input exhausted");
  }
  if (!parser_.parse(*input_, event_queue_)) {
    return make_error(ec::parse_error, "parse error");
  }
  if (!event_queue_.empty()) {
    event current_event = event_queue_.back();
    event_queue_.pop_back();
    return std::move(current_event);
  }
  return no_error;
}

expected<void> reader::schema(vast::schema const& sch) {
  auto types = {
    &parser_.mrt_bgp4mp_announce_type,
    &parser_.mrt_table_dump_type,
    &parser_.mrt_bgp4mp_withdraw_type,
    &parser_.mrt_bgp4mp_state_change_type,
    &parser_.mrt_bgp4mp_open_type,
    &parser_.mrt_bgp4mp_notification_type,
    &parser_.mrt_bgp4mp_keepalive_type,
  };
  for (auto t : types)
    if (auto u = sch.find(t->name())) {
      if (!congruent(*t, *u))
        return make_error(ec::format_error, "incongruent type:", t->name());
      else
        *t = *u;
    }
  return {};
}

expected<schema> reader::schema() const {
  vast::schema sch;
  sch.add(parser_.mrt_bgp4mp_announce_type);
  sch.add(parser_.mrt_table_dump_type);
  sch.add(parser_.mrt_bgp4mp_withdraw_type);
  sch.add(parser_.mrt_bgp4mp_state_change_type);
  sch.add(parser_.mrt_bgp4mp_open_type);
  sch.add(parser_.mrt_bgp4mp_notification_type);
  sch.add(parser_.mrt_bgp4mp_keepalive_type);
  return sch;
}

char const* reader::name() const {
  return "mrt-reader";
}

} // namespace mrt
} // namespace format
} // namespace vast
