#include "vast/error.hpp"
#include "vast/logger.hpp"

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

bool mrt_parser::parse(std::istream& input, std::vector<event>& event_queue){
  using namespace parsers;
  // TEST
  constexpr size_t mrt_header_length = 12;
  count mrt_timestamp;
  count mrt_type;
  count mrt_subtype;
  count mrt_length;
  char ca[mrt_header_length];
  //std::vector<char> v(mrt_header_length);
  //std::string str("", mrt_header_length);
  input.read(ca, mrt_header_length);
  std::string str(ca, mrt_header_length);
  //input.read(str.data(), mrt_header_length);
  //std::vector<char>::iterator v_it_begin = v.begin();
  //std::vector<char>::iterator v_it_end = v.end();
  static auto mrt_header = b32be >> b16be >> b16be >> b32be;
  //auto tpl = std::tie(mrt_timestamp, mrt_type, mrt_subtype, mrt_length);
  //if (!mrt_header(v_it_begin, v_it_end, tpl)){
  if (!mrt_header(str, mrt_timestamp, mrt_type, mrt_subtype, mrt_length)){
    return false;
  }
  // uint16_t t16 = 0;
  // std::vector<char>::iterator f = v_it_begin + 4;
  // parsers::b16be.parse(f, f + 2, t16);
  // mrt_type = count{t16};
  // t16 = 0;
  // parsers::b16be.parse(f, f + 2, t16);
  // mrt_subtype = count{t16};
  // uint32_t t32 = 0;
  // parsers::b32be.parse(f, f + 4, t32);
  // mrt_length = count{t32};
  VAST_DEBUG("mrt-parser", "timestamp type subtype length", mrt_timestamp, mrt_type, mrt_subtype, mrt_length);
  return true;
  // TEST END
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
  if(!parser_.parse(*input_, event_queue_)){
    return make_error(ec::parse_error, "parse error");
  }
  // TEST
  return make_error(ec::end_of_input, "input exhausted");
  // TEST END
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
