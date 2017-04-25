#include "vast/format/bgpdumpbinary.hpp"

namespace vast {
namespace format {
namespace bgpdumpbinary {

bgpdumpbinary_parser::bgpdumpbinary_parser() {
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
  announce_type = record_type{fields};
  announce_type.name("bgpdump::announcement");
  // Route type.
  route_type = record_type{std::move(fields)};
  route_type.name("bgpdump::routing");
  // Withdraw type
  auto withdraw_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"source_ip", address_type{}},
    {"source_as", count_type{}},
    {"prefix", subnet_type{}},
  };
  withdraw_type = record_type{std::move(withdraw_fields)};
  withdraw_type.name("bgpdump::withdrawn");
  // State-change type.
  auto state_change_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"source_ip", address_type{}},
    {"source_as", count_type{}},
    {"old_state", string_type{}},
    {"new_state", string_type{}},
  };
  state_change_type = record_type{std::move(state_change_fields)};
  state_change_type.name("bgpdump::state_change");
  // Open type.
  auto open_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"version", count_type{}},
    {"my_autonomous_system", count_type{}},
    {"hold_time", count_type{}},
    {"bgp_identifier", count_type{}},
  };
  open_type = record_type{std::move(open_fields)};
  open_type.name("bgpdump::open");  
  // Notification type.
  auto notification_fields = std::vector<record_field>{
    {"timestamp", timestamp_type{}},
    {"error_code", count_type{}},
    {"error_subcode", count_type{}},
  };
  notification_type = record_type{std::move(notification_fields)};
  notification_type.name("bgpdump::notification");
  // Keepalive type.
  auto keepalive_fields = std::vector<record_field>{
      {"timestamp", timestamp_type{}},
  };
  keepalive_type = record_type{std::move(keepalive_fields)};
  keepalive_type.name("bgpdump::keepalive");
}

expected<event> reader::read() {
  // Import the binary file once
  if (!imported_) {
    VAST_DEBUG(this, "Reading MRT-file");
    if(!this->import()){
      return make_error(ec::parse_error, "binary import failed");
    }
    counter_ = bytes_.begin();
    imported_ = true;
    VAST_DEBUG(this, "Reading MRT-file finished");
  }

  while (!event_queue_.empty()) {
    event current_event = event_queue_.back();
    event_queue_.pop_back();
    return std::move(current_event);
  }

  if (counter_ >= bytes_.end()) {
    return make_error(ec::end_of_input, "input exhausted");
  }

  // Parse the file from the last entry until end.
  static auto p = bgpdumpbinary_parser{};
  form def;
  form with;
  form ann;
  if (!p.parse(counter_, bytes_.end(), def, with, ann)) {
    return no_error;
  }
  vector defaultrecord;

  /*----------------- State Packet -------------------*/
  if (def.msg_type == "STATE") {
    packet_stream_ << "\nBGP4MP|";

    // Timestamp
    packet_stream_ << to_string(def.ts) << "|";
    defaultrecord.emplace_back(std::move(def.ts));

    // Message Type
    packet_stream_ << def.msg_type << "|";

    // State - Source IPv4
    if (def.addr_family == 1) {
      packet_stream_ << to_string(def.peer_ip_v4) << "|";
      defaultrecord.emplace_back(std::move(def.peer_ip_v4));
    }

    // State - Source IPv6
    else if (def.addr_family == 2) {
      packet_stream_ << to_string(def.peer_ip_v6) << "|";
      defaultrecord.emplace_back(std::move(def.peer_ip_v6));
    }

    // State - AS Number
    packet_stream_ << static_cast<int>(def.pasnr) << "|";
    defaultrecord.emplace_back(std::move(def.pasnr));

    // State - Mode 1
    packet_stream_ << static_cast<int>(def.old_state) << "|";
    defaultrecord.emplace_back(std::move(def.old_state));

    // State - Mode 2
    packet_stream_ << static_cast<int>(def.new_state) << "|";
    defaultrecord.emplace_back(std::move(def.new_state));

    event e{{std::move(defaultrecord), parser_.state_change_type}};
    e.timestamp(def.ts);
    event_queue_.push_back(e);

    packet_string_ = packet_stream_.str();
    VAST_DEBUG(this, packet_string_ << "\n");
    packet_stream_.str(std::string());
  }
  /*----------------- State Packet End----------------*/

  /*----------------- Open Packet --------------------*/
  if(def.msg_type == "O"){
    packet_stream_ << "\nBGP4MP|";

    // Timestamp
    packet_stream_ << to_string(def.ts) << "|";
    defaultrecord.emplace_back(std::move(def.ts));

    // Message Type
    packet_stream_ << def.msg_type << "|";

    // Open - Version
    packet_stream_ << to_string(def.version) << "|";
    defaultrecord.emplace_back(std::move(def.version));

    // Open - My Autonomous System
    packet_stream_ << to_string(def.my_autonomous_system) << "|";
    defaultrecord.emplace_back(std::move(def.my_autonomous_system));

    // Open - Hold Time
    packet_stream_ << to_string(def.hold_time) << "|";
    defaultrecord.emplace_back(std::move(def.hold_time));

    // Open - BGP Identifier
    packet_stream_ << to_string(def.bgp_id) << "|";
    defaultrecord.emplace_back(std::move(def.bgp_id));

    event e{{std::move(defaultrecord), parser_.open_type}};
    e.timestamp(def.ts);
    event_queue_.push_back(e);

    packet_string_ = packet_stream_.str();
    VAST_DEBUG(this, packet_string_ << "\n");
    packet_stream_.str(std::string());
  }
  /*----------------- Open Packet End ----------------*/

  /*----------------- Withdraw Packet ----------------*/
  auto prefix_counter = size_t{0};
  if (with.msg_type == "W") {
    vector withdrawrecord;

    if (with.addr_family == 1)
      prefix_counter = with.prefix_v4.size();
    else if (with.addr_family == 2)
      prefix_counter = with.prefix_v6.size();

    for (size_t i = 0; i < prefix_counter; ++i) {
      packet_stream_ << "\nBGP4MP|";

      // Timestamp
      packet_stream_ << to_string(with.ts) << "|";
      withdrawrecord.emplace_back(with.ts);

      // Message Type
      packet_stream_ << with.msg_type << "|";

      // Withdraw - Source IPv4
      if (with.addr_family == 1) {
        packet_stream_ << to_string(with.peer_ip_v4) << "|";
        withdrawrecord.emplace_back(with.peer_ip_v4);
      }

      // Withdraw - Source IPv6
      else if (with.addr_family == 2) {
        packet_stream_ << to_string(with.peer_ip_v6) << "|";
        withdrawrecord.emplace_back(with.peer_ip_v6);
      }

      // Withdraw - AS Number
      packet_stream_ << std::dec << with.pasnr << "|";
      withdrawrecord.emplace_back(with.pasnr);

      // Withdraw - Prefix IPv4
      if (with.addr_family == 1) {
        packet_stream_ << to_string(with.prefix_v4[i]) << "|";
        withdrawrecord.emplace_back(with.prefix_v4[i]);
      }

      // Withdraw - Prefix IPv6
      else if (with.addr_family == 2) {
        packet_stream_ << to_string(with.prefix_v6[i]) << "|";
        withdrawrecord.emplace_back(with.prefix_v6[i]);
      }

      event e{{std::move(withdrawrecord), parser_.withdraw_type}};
      e.timestamp(with.ts);
      event_queue_.push_back(e);

      packet_string_ = packet_stream_.str();
      VAST_DEBUG(this, packet_string_ << "\n");
      packet_stream_.str(std::string());
    }
  }
  /*----------------- Withdraw Packet End-------------*/

  /*----------------- Announce Packet ----------------*/
  if (ann.msg_type == "A") {
    vector announcerecord;

    if (ann.addr_family == 1) {
      prefix_counter = ann.prefix_v4.size();
    } else if (ann.addr_family == 2) {
      prefix_counter = ann.prefix_v6.size();
    } else {
      VAST_WARNING("invalid address family");
      return make_error(ec::unspecified, "invalid address family");
    }

    for (size_t i = 0; i < prefix_counter; ++i) {
      packet_stream_ << "\nBGP4MP|";

      // Timestamp
      packet_stream_ << to_string(ann.ts) << "|";
      announcerecord.emplace_back(ann.ts);

      // Message Type
      packet_stream_ << ann.msg_type << "|";

      // Announce - Source IPv4
      if (ann.addr_family == 1) {
        packet_stream_ << to_string(ann.peer_ip_v4) << "|";
        announcerecord.emplace_back(ann.peer_ip_v4);
      }

      // Announce - Source IPv6
      else if (ann.addr_family == 2) {
        packet_stream_ << to_string(ann.peer_ip_v6) << "|";
        announcerecord.emplace_back(ann.peer_ip_v6);
      }

      // Announce - AS Number
      packet_stream_ << ann.pasnr << "|";
      announcerecord.emplace_back(ann.pasnr);

      // Announce - Prefix IPv4
      if (ann.addr_family == 1) {
        packet_stream_ << to_string(ann.prefix_v4[i]) << "|";
        announcerecord.emplace_back(ann.prefix_v4[i]);
      }

      // Announce - Prefix IPv6
      else if (ann.addr_family == 2) {
        packet_stream_ << to_string(ann.prefix_v6[i]) << "|";
        announcerecord.emplace_back(ann.prefix_v6[i]);
      }

      // Announce - Paths
      packet_stream_ << to_string(ann.as_path) << "|";
      announcerecord.emplace_back(ann.as_path);

      // Announce - Origin
      packet_stream_ << ann.origin << "|";
      announcerecord.emplace_back(ann.origin);

      // Announce - Next Hop & Community IPv4
      if (ann.addr_family == 1) {
        packet_stream_ << to_string(ann.nexthop_v4) << "|";
        announcerecord.emplace_back(ann.nexthop_v4);
      }

      // Announce - Next Hop & Community IPv6
      else if (ann.addr_family == 2) {
        packet_stream_ << to_string(ann.nexthop_v6) << "|";
        announcerecord.emplace_back(ann.nexthop_v6);
      }

      // Announce - Local Pref
      packet_stream_ << ann.local_pref << "|";
      announcerecord.emplace_back(ann.local_pref);

      // Announce - Med
      packet_stream_ << ann.med << "|";
      announcerecord.emplace_back(ann.med);

      // Announce - Community
      packet_stream_ << ann.community << "|";
      announcerecord.emplace_back(ann.community);

      // Announce - Atomic Aggregate
      packet_stream_ << ann.atomic_aggregate << "|";
      announcerecord.emplace_back(ann.atomic_aggregate);

      // Announce - Aggregator
      count route;
      address addr;
      std::tie(route, addr) = ann.aggregator;
      packet_stream_ << "|";
      if (route != 0) {
        packet_stream_ << to_string(route) << " " << to_string(addr) << "|";
        announcerecord.emplace_back(to_string(route) + ' ' + to_string(addr));
      }

      event e{{std::move(announcerecord), parser_.announce_type}};
      e.timestamp(ann.ts);
      event_queue_.push_back(std::move(e));

      packet_string_ = packet_stream_.str();
      VAST_DEBUG(this, packet_string_ << "\n");
      packet_stream_.str(std::string());
    }
  }
  /*----------------- Announce Packet End --------------*/

  /*----------------- Notification Packet --------------*/
  if(def.msg_type == "N") {
    packet_stream_ << "\nBGP4MP|";

    // Timestamp
    packet_stream_ << to_string(def.ts) << "|";
    defaultrecord.emplace_back(def.ts);

    // Message Type
    packet_stream_ << def.msg_type << "|";

    // Notification - Error code
    packet_stream_ << to_string(def.error_code) << "|";
    defaultrecord.emplace_back(def.error_code);

    // Notification - Error subcode
    packet_stream_ << to_string(def.error_code) << "|";
    defaultrecord.emplace_back(def.error_code);

    event e{{std::move(defaultrecord), parser_.notification_type}};
    e.timestamp(def.ts);
    event_queue_.push_back(std::move(e));

    packet_string_ = packet_stream_.str();
    VAST_DEBUG(this, packet_string_ << "\n");
    packet_stream_.str(std::string());
  }
  /*----------------- Notification Packet End ----------*/

  /*----------------- Keepalive Packet -----------------*/
  if(def.msg_type == "K") {
    packet_stream_ << "\nBGP4MP|";

    // Timestamp
    packet_stream_ << to_string(def.ts) << "|";
    defaultrecord.emplace_back(def.ts);

    // Message Type
    packet_stream_ << def.msg_type << "|";

    event e{{std::move(defaultrecord), parser_.keepalive_type}};
    e.timestamp(def.ts);
    event_queue_.push_back(std::move(e));

    packet_string_ = packet_stream_.str();
    VAST_DEBUG(this, packet_string_ << "\n");
    packet_stream_.str(std::string());
  }
  /*----------------- Keepalive Packet End -------------*/

  /*----------------- TABLE_DUMP_V2 Packet -------------*/
  if(def.msg_type == "TDV2") {
    for(size_t j = 0; j < def.rib_entries.size(); j++){
      vector ribrecord;
      if (def.addr_family == 1) {
        prefix_counter = def.prefix_v4.size();
      } else if (def.addr_family == 2) {
        prefix_counter = def.prefix_v6.size();
      } else {
        VAST_WARNING("invalid address family");
        return make_error(ec::unspecified, "invalid address family");
      }

      for (size_t i = 0; i < prefix_counter; ++i) {
        packet_stream_ << "\nRIB|";

        // Timestamp
        packet_stream_ << to_string(def.rib_entries[j].ts) << "|";
        ribrecord.emplace_back(def.rib_entries[j].ts);

        // Message Type
        packet_stream_ << def.msg_type << "|";

        // TABLE_DUMP_V2 - Source IPv4
        if (def.addr_family == 1) {
          packet_stream_ << to_string(def.peer_ip_v4) << "|";
          ribrecord.emplace_back(def.peer_ip_v4);
        }

        // TABLE_DUMP_V2 - Source IPv6
        else if (def.addr_family == 2) {
          packet_stream_ << to_string(def.peer_ip_v6) << "|";
          ribrecord.emplace_back(def.peer_ip_v6);
        }

        // TABLE_DUMP_V2 - AS Number
        packet_stream_ << def.pasnr << "|";
        ribrecord.emplace_back(def.pasnr);

        // TABLE_DUMP_V2 - Prefix IPv4
        if (def.addr_family == 1) {
          packet_stream_ << to_string(def.prefix_v4[i]) << "|";
          ribrecord.emplace_back(def.prefix_v4[i]);
        }

        // TABLE_DUMP_V2 - Prefix IPv6
        else if (def.addr_family == 2) {
          packet_stream_ << to_string(def.prefix_v6[i]) << "|";
          ribrecord.emplace_back(def.prefix_v6[i]);
        }

        // TABLE_DUMP_V2 - Paths
        packet_stream_ << to_string(def.rib_entries[j].as_path) << "|";
        ribrecord.emplace_back(def.rib_entries[j].as_path);

        // TABLE_DUMP_V2 - Origin
        packet_stream_ << def.rib_entries[j].origin << "|";
        ribrecord.emplace_back(def.rib_entries[j].origin);

        // TABLE_DUMP_V2 - Next Hop & Community IPv4
        if (def.addr_family == 1) {
          packet_stream_ << to_string(def.rib_entries[j].nexthop_v4) << "|";
          ribrecord.emplace_back(def.rib_entries[j].nexthop_v4);
        }

        // TABLE_DUMP_V2 - Next Hop & Community IPv6
        else if (def.addr_family == 2) {
          packet_stream_ << to_string(def.rib_entries[j].nexthop_v6) << "|";
          ribrecord.emplace_back(def.rib_entries[j].nexthop_v6);
        }

        // TABLE_DUMP_V2 - Local Pref
        packet_stream_ << def.rib_entries[j].local_pref << "|";
        ribrecord.emplace_back(def.rib_entries[j].local_pref);

        // TABLE_DUMP_V2 - Med
        packet_stream_ << def.rib_entries[j].med << "|";
        ribrecord.emplace_back(def.rib_entries[j].med);

        // TABLE_DUMP_V2 - Community
        packet_stream_ << def.rib_entries[j].community << "|";
        ribrecord.emplace_back(def.rib_entries[j].community);

        // TABLE_DUMP_V2 - Atomic Aggregate
        packet_stream_ << def.rib_entries[j].atomic_aggregate << "|";
        ribrecord.emplace_back(def.rib_entries[j].atomic_aggregate);

        // TABLE_DUMP_V2 - Aggregator
        count route;
        address addr;
        std::tie(route, addr) = def.rib_entries[j].aggregator;
        packet_stream_ << "|";
        if (route != 0) {
          packet_stream_ << to_string(route) << " " << to_string(addr) << "|";
          ribrecord.emplace_back(to_string(route) + ' ' + to_string(addr));
        }

        event e{{std::move(ribrecord), parser_.route_type}};
        e.timestamp(def.ts);
        event_queue_.push_back(std::move(e));

        packet_string_ = packet_stream_.str();
        VAST_DEBUG(this, packet_string_ << "\n");
        packet_stream_.str(std::string());
      }
    }
  }
  /*----------------- TABLE_DUMP_V2 Packet End -------------*/
  
  if (!event_queue_.empty()) {
    event current_event = event_queue_.back();
    event_queue_.pop_back();
    return std::move(current_event);
  }
  return no_error;
}

expected<void> reader::schema(vast::schema const& sch) {
  auto types = {
    &parser_.announce_type,
    &parser_.route_type,
    &parser_.withdraw_type,
    &parser_.state_change_type,
    &parser_.open_type,
    &parser_.notification_type,
    &parser_.keepalive_type,
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
  sch.add(parser_.announce_type);
  sch.add(parser_.route_type);
  sch.add(parser_.withdraw_type);
  sch.add(parser_.state_change_type);
  sch.add(parser_.open_type);
  sch.add(parser_.notification_type);
  sch.add(parser_.keepalive_type);
  return sch;
}

char const* reader::name() const {
  return "bgpdumpbinary-reader";
}

bool reader::import(){
  if(!in_){
    return false;
  }
  while(!(in_->eof())){
      bytes_.push_back(in_->get());
  }
  return true;
}

} // namespace bgpdumpbinary
} // namespace format
} // namespace vast