#ifndef VAST_FORMAT_BGPDUMPBINARY_HPP
#define VAST_FORMAT_BGPDUMPBINARY_HPP

#include <istream>
#include <iostream>
#include "vast/logger.hpp"
#include "vast/schema.hpp"
#include "vast/time.hpp"
#include "vast/date.hpp"
#include "vast/address.hpp"
#include "vast/subnet.hpp"
#include "vast/data.hpp"
#include "vast/concept/parseable/core.hpp"
#include "vast/concept/parseable/string.hpp"
#include "vast/concept/parseable/numeric/byte.hpp"
#include "vast/concept/parseable/vast/address.hpp"
#include "vast/concept/parseable/vast/time.hpp"
#include "vast/concept/parseable/vast/subnet.hpp"
#include "vast/concept/parseable/vast/data.hpp"
#include "vast/concept/printable/vast/address.hpp"
#include "vast/concept/printable/vast/subnet.hpp"
#include "vast/concept/printable/vast/data.hpp"
#include "vast/concept/printable/string.hpp"
#include "vast/concept/printable/to_string.hpp"
#include "vast/concept/printable/std/chrono.hpp"

#include "vast/format/reader.hpp"

namespace vast {
namespace format {
namespace bgpdumpbinary {

struct form {
  timestamp ts;
  count bgp_type;
  count type;
  count subtype;
  count interface_index;
  count addr_family;
  count old_state;
  count new_state;
  count bgp_length;
  count length;
  count pasnr;
  count med;
  count local_pref;
  count version;
  count my_autonomous_system;
  count hold_time;
  count bgp_id;
  count error_code;
  count error_subcode;
  std::string msg_type;
  std::string origin;
  std::string as_path_orded;
  std::string community;
  std::string atomic_aggregate;
  address peer_ip_v4;
  address peer_ip_v6;
  address nexthop_v4;
  address nexthop_v6;
  std::vector<data> as_path;
  std::vector<subnet> prefix_v4;
  std::vector<subnet> prefix_v6;
  std::tuple<count, address> aggregator;

  /* extended fields */
  uint16_t wd_rts_len;
  bool paket_error;
  std::vector<form> rib_entries;
};

/// A parser that reading bgp messages from the MRT files.
struct bgpdumpbinary_parser : parser<bgpdumpbinary_parser> {
  using attribute = event;

  bgpdumpbinary_parser();

  template <class Iterator>
  bool parse(Iterator &f, Iterator const &l, unused_type) const {
    if(f >= l)
      return false;
    else
      return true;
  }

  /*-----------------MRT Header-----------------*/
  template <class Iterator, class Attribute>
  bool parse_mrt_header(Iterator &f, Iterator const &l, Attribute &a) const {
    using namespace parsers;
    uint16_t t16 = 0;
    uint32_t t32 = 0;


    if(f + 12 <= l) {
      // MRT - Timestamp
      b32be.parse(f, f + 4, t32);
      a.ts = vast::timestamp{std::chrono::seconds{t32}};
      // MRT - Type
      b16be.parse(f, f + 2, t16);
      a.type = count{t16};
      // MRT - Subtype
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.subtype = count{t16};
      // MRT - Length
      t32 = 0;
      b32be.parse(f, f + 4, t32);
      a.length = count{t32};
      if(a.type == 17){
        VAST_DEBUG(this, "MRT MICROSECOND TIMESTAMP not supported");
        // 32bit microsecond timestamp included in length field calculation
        f += 4; 
        a.length -= 4;
      }
      return true;
    } else {
      VAST_DEBUG(this, "MRT HEADER size exceeded");
      f = l;
      return false;
    }
  }

  /*-------------BGP4MP_MESSAGE+BGP4MP_MESSAGE_AS4-------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_as4(Iterator &f, Iterator const &l,
                            Attribute &a) const {
    using namespace parsers;
    uint16_t t16 = 0;
    uint32_t t32 = 0;

    if(a.length != 0 && f + a.length <= l) {
      if(a.subtype == 1 || a.subtype == 0){
      // BGP4MP subtype BGP4MP_MESSAGE or BGP4MP_STATE_CHANGE
        // BGP4MP - Peer AS NUMBER
        b16be.parse(f, f + 2, t16);
        a.pasnr = count{t16};
        a.length -= 2;
        // BGP4MP - Local AS NUMBER
        t16 = 0;
        b16be.parse(f, f + 2, t16);
        a.length -= 2;    
      } else if (a.subtype == 4 || a.subtype == 5){
      // BGP4MP subtype BGP4MP_MESSAGE_AS4 or BG4MP_STATE_CHANGE_AS4
        // BGP4MP - Peer AS NUMBER
        b32be.parse(f, f + 4, t32);
        a.pasnr = count{t32};
        a.length -= 4;
        // BGP4MP - Local AS NUMBER
        t32 = 0;
        b32be.parse(f, f + 4, t32);
        a.length -= 4;    
      } else {
        VAST_WARNING(this, 
                     "MRT BGP4MP SUBTYPE not BGPMESSAGE or STATECHANGE -> ",
                     a.subtype);
        f += a.length;
        a.length = 0;
        return false;
      }
      // BGP4MP - Interface Index
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.interface_index = count{t16};
      a.length -= 2;
      // BGP4MP - Address Family
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.addr_family = t16;
      a.length -= 2;
      // BGP4MP -IPv4
      if (a.addr_family == 1) {
        // BGP4MP - Peer IP Address - IPv4
        t32 = 0;
        b32be.parse(f, f + 4, t32);
        a.peer_ip_v4 = address{&t32, address::ipv4, address::host};
        a.length -= 4;
        // BGP4MP - Local IP Address - IPv4
        f += 4;
        a.length -= 4;
      } else if (a.addr_family == 2) {
        // BGP4MP - Peer IP Address - IPv6
        std::array<uint8_t, 16> bytes;
        std::copy_n(f, 16, bytes.begin());
        auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
        a.peer_ip_v6 = address{bytes32, address::ipv6, address::network};
        a.length -= 16;
        f += 16;
        // BGP4MP - Local IP Address - IPV6
        f += 16;
        a.length -= 16;
      }
      return true;
    } else {
      VAST_DEBUG("MRT SIZE exceeded -> ", a.length);
      f = l;
      return false;
    }
  }

  /*-------------BGP4MP_STATE_CHANGE-------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_state_change(Iterator &f, Iterator const &l,
                                 Attribute &a) const {
    using namespace parsers;
    uint16_t t16 = 0;

    if(a.length != 0 && f + a.length <= l){     
      //BGP4MP_STATE_CHANGE or BGP4MP_STATE_CHANGE_AS4
      if (a.subtype == 0 || a.subtype == 5) {
        // BGP4MP - State - Type
        a.msg_type = "STATE";
        // BGP4MP - State - Mode 1
        b16be.parse(f, f + 2, t16);
        a.old_state = count{t16};
        a.length -= 2;
        // BGP4MP - State - Mode 2
        t16 = 0;
        b16be.parse(f, f + 2, t16);
        a.new_state = count{t16};
        a.length -= 2;

        return true;
      } else {
        return false;
      }
    } else {
      VAST_DEBUG("MRT SIZE exceeded -> ", a.length);
      f = l;
      return false;
    }
  }

  /*--------------------BGP---------------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp(Iterator &f, Iterator const &l, Attribute &a) const {
    using namespace parsers;
    uint8_t t8 = 0;
    uint16_t t16 = 0;

    if (a.length != 0 && f + a.length <= l) {
      // only BGP Message packets allowed
      if (a.subtype != 1 && a.subtype != 4) {
        VAST_DEBUG("MRT SUBTYPE not BGPMESSAGE -> ", a.subtype);
        f += a.length;
        a.length = 0;
        return false;
      }
      // BGP - Marker
      f += 16;
      a.length -= 16;
      // BGP - Length
      b16be.parse(f, f + 2, t16);
      a.bgp_length = count{t16};
      a.length -= 2;
      // BGP - Type
      byte.parse(f, f + 1, t8);
      a.bgp_type = count{t8};
      a.length -= 1;
      return true;
    } else {
      VAST_DEBUG("MRT SIZE exceeded -> ", a.length);
      f = l;
      return false;
    }
  }

  /*--------------------BGP4MP_MESSAGE_OPEN---------------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_open(Iterator &f, Iterator const &l,
                             Attribute &a) const {
    using namespace parsers;
    uint8_t t8 = 0;
    uint16_t t16 = 0;
    uint32_t t32 = 0;
    
    if (a.length != 0 && f + a.length <= l) {
      a.msg_type = "O";
      // BGP - OPEN - Version
      byte.parse(f, f + 1, t8);
      a.length--;
      a.version = t8;
      // BGP - OPEN - My Autonomous System
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      a.my_autonomous_system = t16;
      // BGP - OPEN - Hold Time
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      a.hold_time = t16;
      // BGP - OPEN - BGP Identifier
      b32be.parse(f, f + 4, t32);
      a.length -= 4;
      a.bgp_id = t32;
      // BGP - OPEN - Optionl Parameters Length
      t8 = 0;
      byte.parse(f, f + 1, t8);
      a.length--;
      uint8_t op_par_len = t8;
      // BGP - OPEN - Optional Parameters
      while(op_par_len > 0){
        // BGP - OPEN - Optional Parameters - Parameter Type
        t8 = 0;
        byte.parse(f, f + 1, t8);
        a.length--;
        op_par_len--;
        uint8_t par_type = t8;
        // BGP - OPEN - Optional Parameters - Parameter Length
        t8 = 0;
        byte.parse(f, f + 1, t8);
        a.length--;
        op_par_len--;
        uint8_t par_len = t8;
        // BGP - OPEN - Optional Parameters - Parameter Value
        VAST_DEBUG("BGP OPEN Optional Parameter not supported -> ", par_type);
        f += par_len; // TODO: parse parameter
        a.length -= par_len;
        op_par_len -= par_len;
      }
      return true;
    } else {
      f = l;
      return false;
    }
  }

  /*-------BGP4MP_MESSAGE_UPDATE_WITHDRAW-------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_update_withdraw(Iterator &f, Iterator const &l,
                                        Attribute &a) const {
    using namespace parsers;
    uint8_t t8 = 0;
    uint16_t t16 = 0;
    uint32_t t32 = 0;

    if(a.length != 0 && f + a.length <= l){
      // BGP - Withdraw Routes Length
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      a.wd_rts_len = t16;
      uint16_t wd_rts_len = t16;
      // BGP - Withdraw - IPv4
      if ((a.addr_family == 1) && (wd_rts_len > 0)) {
        a.msg_type = "W";
        uint8_t wd_prefix_len_v4;
        a.length -= wd_rts_len;
        // BGP - Withdraw - Length
        while (wd_rts_len > 0) {
          byte.parse(f, f + 1, t8);
          uint8_t wd_prefix_bits = t8;
          wd_rts_len--;
          wd_prefix_len_v4 = t8 / 8;
          if (t8 % 8 != 0)
            wd_prefix_len_v4++;
          // BGP - Withdraw - Prefix - IPv4
          for (auto i = 0; i < wd_prefix_len_v4; ++i) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            t32 <<= 8;
            t32 |= t8;
            wd_rts_len--;
          }

          for (auto i = 0; i < 4 - wd_prefix_len_v4; ++i)
            t32 <<= 8;
          a.prefix_v4.push_back(
            subnet{address{&t32, address::ipv4, address::host},
            wd_prefix_bits});
        }
        return true;
      }

      // BGP - Withdraw - IPv6
      else if ((a.addr_family == 2) && (wd_rts_len > 0)) {
        a.msg_type = "W";
        uint8_t wd_prefix_len_v6;
        uint32_t const *bytes32;
        std::array<uint8_t, 16> bytes;
        address addr_v6;
        a.length -= wd_rts_len;
        // BGP - Withdraw - Prefix - IPv6
        while (wd_rts_len > 0) {
          t8 = 0;
          byte.parse(f, f + 1, t8);
          wd_rts_len--;
          wd_prefix_len_v6 = t8 / 8;
          if (t8 % 8 != 0)
            wd_prefix_len_v6 += 1;
          std::copy_n(f, wd_prefix_len_v6, bytes.begin());
          bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
          addr_v6 = address{bytes32, address::ipv6, address::network};
          wd_rts_len -= wd_prefix_len_v6;
          a.prefix_v6.push_back(subnet{addr_v6, t8});
        }
        return true;

      } else {
        return true;
      }
    } else {
      f = l;
      return false;
    }
  }

  /*-------BGP4MP_MESSAGE_UPDATE_ANNOUNCE-------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_update_announce(Iterator &f, Iterator const &l,
                                        Attribute &a) const {
    using namespace parsers;
    uint8_t t8 = 0;
    uint16_t t16 = 0;
    uint32_t t32 = 0;

    if(a.length != 0 && f + a.length <= l){   
      // BGP - announce - Total Paths Length   
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      uint16_t total_path_len = t16;
      //RFC 4271 Page 20
      uint16_t prefix_len = a.bgp_length - total_path_len - a.wd_rts_len - 23;
     
      // BGP - announce - 
      // Path Attributes & Network Layer Reachability Information
      if (total_path_len == 0){
        return true;
      } else {
        if (a.length == 0) {
          VAST_WARNING(this, 
            "MRT LENGTH exceeded but Total Path Attribute Length > 0");
          return false;
        }
        // BGP - announce - Message Type   
        a.msg_type = "A";
      }
      uint8_t attr_type;
      uint8_t attr_flags;
      uint16_t attr_length;
      bool attr_ext_len_bit;
      bool attr_type_active = false;

      while (total_path_len > 0) {
        // BGP - announce - Attribute Flags
        byte.parse(f, f + 1, t8);
        a.length--;
        attr_flags = t8;
        total_path_len--;
        attr_ext_len_bit = static_cast<bool>((attr_flags & 16) >> 4);

        // BGP - announce - Attribute Type Code (1 Byte)
        t8 = 0;
        byte.parse(f, f + 1, t8);
        a.length--;
        attr_type = t8;
        total_path_len--;
        if (attr_ext_len_bit) {
          // BGP - announce - Attribute Length Field (2 Bytes)
          t16 = 0;
          b16be.parse(f, f + 2, t16);
          a.length -= 2;
          attr_length = t16;
          total_path_len -= 2;     
        } else {
          // BGP - announce - Attribute Length Field (1 Byte)
          t8 = 0;
          byte.parse(f, f + 1, t8);
          a.length--;
          attr_length = t8;     
          total_path_len--;
        }
        
        // BGP - announce - Origin
        if (attr_type == 1) {
          while (attr_length > 0) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            a.length--;

            if (t8 == 0)
              a.origin = "IGP";

            else if (t8 == 1)
              a.origin = "EGP";

            else if (t8 == 2)
              a.origin = "INCOMPLETE";
          
            total_path_len--;
            attr_length--;
          }
        }

        // BGP - announce - AS Path
        else if (attr_type == 2) {
          while (attr_length > 0) {
            // BGP - announce - AS Path - Segment Type
            t8 = 0;
            byte.parse(f, f + 1, t8);
            a.length--;
            total_path_len--;
            attr_length--;
            uint8_t path_seg_type = t8;
            if (path_seg_type == 1) {
              a.as_path_orded = "AS_SET";
              a.as_path.push_back(count{0});
            } else if (path_seg_type == 2)
              a.as_path_orded = "AS_SEQUENCE";

            // BGP - announce - AS Path - Segment Length (Number of AS)
            t8 = 0;
            byte.parse(f, f + 1, t8);
            a.length--;
            total_path_len--;
            attr_length--;
            uint8_t path_seg_length = t8;

            // BGP - announce - AS Path - Segment Value
            while (path_seg_length > 0) {
              t32 = 0;
              if (a.subtype == 1) { //BGP4MP_MESSAGE (RFC 6396 4.4.2)
                b16be.parse(f, f + 2, t32);
                a.length -= 2;
                total_path_len -= 2;
                attr_length -= 2;
              } else if (a.subtype == 4) { //BGP4MP_MESSAGE_AS4 (RFC 6396 4.4.3)
                b32be.parse(f, f + 4, t32);
                a.length -= 4;
                total_path_len -= 4;
                attr_length -= 4;
              }  
              a.as_path.push_back(count{t32});
              path_seg_length--;
            }
            if (path_seg_type == 1)
              a.as_path.push_back(count{0});
          }
        }
        // BGP - announce - Next Hop
        else if (attr_type == 3) {
          // BGP - announce - Next Hop - IPv4
          if (attr_length == 4) {
            t32 = 0;
            b32be.parse(f, f + 4, t32);
            a.nexthop_v4 = address{&t32, address::ipv4, address::host};
            a.length -= 4;
            total_path_len -= 4;
            attr_length -= 4;
          }
          // BGP - announce - Next Hop - IPv6
          else if (attr_length == 16) {
            std::array<uint8_t, 16> bytes;
            std::copy_n(f, 16, bytes.begin());
            auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
            a.nexthop_v6 = address{bytes32, address::ipv6, address::network};
            a.length -= 16;
            total_path_len -= 16;
            attr_length -= 16;
            f += 16;
          }
        }
        // BGP - announce - Multi Exit Disc (MED)
        else if (attr_type == 4) {
          t32 = 0;
          b32be.parse(f, f + 4, t32);
          a.med = count{t32};
          a.length -= 4;
          total_path_len -= 4;
          attr_length -= 4;
        }
        // BGP - announce - Local Pref
        else if (attr_type == 5) {
          t32 = 0;
          b32be.parse(f, f + 4, t32);
          a.local_pref = count{t32};
          a.length -= 4;
          total_path_len -= 4;
          attr_length -= 4;
        }
        // BGP - announce - ATOMIC AGGREGATE
        else if (attr_type == 6) {
        }
        // BGP - announce - AGGREGATOR
        else if (attr_type == 7) {
          a.atomic_aggregate = "AG";
          count aggregator_route;
          // BGP - announce - Aggregator - Route (2 Bytes)
          if (attr_length % 6 == 0) {
            t16 = 0;
            b16be.parse(f, f + 2, t16);
            aggregator_route = count{t16};
            total_path_len -= 2;
            a.length -= 2;
            attr_length -= 2;
          }
          // BGP - announce - Aggregator - Route (4 Bytes)
          else if (attr_length % 8 == 0) {
            t32 = 0;
            b32be.parse(f, f + 4, t32);
            aggregator_route = count{t32};
            total_path_len -= 4;
            a.length -= 4;
            attr_length -= 4;
          }
          // BGP - announce - Aggregator - Prefix
          t32 = 0;
          b32be.parse(f, f + 4, t32);
          auto aggregator_addr = address{&t32, address::ipv4, address::host};
          a.length -= 4;
          total_path_len -= 4;
          attr_length -= 4;
          a.aggregator = std::make_tuple(aggregator_route, aggregator_addr);
          if (attr_length > 0) {
            f += attr_length;
            total_path_len -= attr_length;
            a.length -= attr_length;
            attr_length = 0;
          }
        }

        // BGP - announce - Community (RFC 1997)
        else if (attr_type == 8) {
          // BGP - announce - Community
          while (attr_length > 0) {
            t16 = 0;
            b16be.parse(f, f + 2, t16);
            a.length -= 2;
            a.community += to_string(t16);
            t16 = 0;
            b16be.parse(f, f + 2, t16);
            a.community += std::string(":") + to_string(t16) + std::string(" ");
            a.length -= 2;
            total_path_len -= 4;
            attr_length -= 4;
          }
          a.community.erase(a.community.end() - 1);
        }

        // BGP - announce - MP_REACH_NLRI (RFC 2858)
        else if (attr_type == 14) {
          // BGP - announce - MP_REACH_NLRI - Address Family Identifier
          t16 = 0;
          b16be.parse(f, f + 2, t16);
          a.length -= 2;
          // BGP - announce - MP_REACH_NLRI -
          // Subsequent Address Family Identifier
          t8 = 0;
          byte.parse(f, f + 1, t8);
          a.length--;
          // BGP - announce - MP_REACH_NLRI - Length of Next Hop Network Address
          t8 = 0;
          byte.parse(f, f + 1, t8);
          a.length--;
          uint8_t mp_next_hop_len = t8;
          total_path_len -= (4 + mp_next_hop_len);
          attr_length -= (4 + mp_next_hop_len);
          // BGP - announce - MP_REACH_NLRI - Next Hop
          std::array<uint8_t, 16> bytes;
          std::copy_n(f, mp_next_hop_len, bytes.begin());
          auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
          a.nexthop_v6 = address{bytes32, address::ipv6, address::network};
          f += mp_next_hop_len;
          a.length -= mp_next_hop_len;
          // BGP - announce - MP_REACH_NLRI - Reserved
          f++;
          a.length--;
          total_path_len--;
          attr_length--;
          // BGP - announce - MP_REACH_NLRI - Prefix IPv6
          a.length -= attr_length;
          total_path_len -= attr_length;

          uint8_t prefix_len_v6;
          vast::address addr_v6;

          while (attr_length > 0) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            attr_length--;
            prefix_len_v6 = t8 / 8;

            if (t8 % 8 != 0)
              prefix_len_v6 += 1;

            std::copy_n(f, prefix_len_v6, bytes.begin());
            bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
            addr_v6 = address{bytes32, address::ipv6, address::network};
            attr_length -= prefix_len_v6;
            a.prefix_v6.push_back(subnet{addr_v6, t8});
            f += prefix_len_v6;
          }

          attr_type_active = true;
        }

        // BGP - announce - MP_UNREACH_NLRI (RFC 2858)
        else if (attr_type == 15) {
          a.msg_type = "W";
          // BGP - announce - MP_UNREACH_NLRI - Address Family Identifier
          t16 = 0;
          b16be.parse(f, f + 2, t16);
          a.length -= 2;
          // BGP - announce - MP_UNREACH_NLRI - Subsequent Address Family
          // Identifier
          t8 = 0;
          byte.parse(f, f + 1, t8);
          a.length--;
          attr_length -= 3;
          total_path_len -= 3;
          // BGP - announce - MP_UNREACH_NLRI - Prefix
          a.length -= attr_length;
          total_path_len -= attr_length;

          uint8_t prefix_len_v6;
          std::array<uint8_t, 16> bytes;
          uint32_t const *bytes32;
          vast::address addr_v6;

          while (attr_length > 0) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            attr_length--;
            prefix_len_v6 = t8 / 8;

            if (t8 % 8 != 0)
              prefix_len_v6 += 1;

            std::copy_n(f, prefix_len_v6, bytes.begin());
            bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
            addr_v6 = address{bytes32, address::ipv6, address::network};
            attr_length -= prefix_len_v6;
            a.prefix_v6.push_back(subnet{addr_v6, t8});
            f += prefix_len_v6;
          }

          attr_type_active = true;
        }

        // BGP - announce - Extended Communities Attribute (RFC 4360)
        else if (attr_type == 16) {
          VAST_DEBUG("Extended Communities not supported");
          a.length -= attr_length;
          f += attr_length;
          total_path_len -= attr_length;
        } else {
          VAST_DEBUG(this, "Attribute Type not supported -> ",
                     static_cast<uint16_t>(attr_type));
          if(attr_length > 0){
            a.length -= attr_length;
            f += attr_length;
            total_path_len -= attr_length;
          } else {
            f += a.length;
            a.length = 0;
            return false;
          }
        }
      }
      if (a.atomic_aggregate.empty())
        a.atomic_aggregate = "NAG";
      // BGP - announce - Prefix - IPv4
      if ((a.addr_family == 1) & (!attr_type_active)) {
        uint8_t prefix_len_v4;
        uint8_t prefix_bits;
        a.length -= prefix_len;

        while (prefix_len > 0) {
          t8 = 0;
          t32 = 0;
          byte.parse(f, f + 1, t8);
          prefix_bits = t8;
          prefix_len_v4 = t8 / 8;
          prefix_len--;

          if (t8 % 8 != 0)
            prefix_len_v4++;

          for (auto i = 0; i < prefix_len_v4; ++i) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            t32 <<= 8;
            t32 |= t8;
            prefix_len--;
          }

          for (auto i = 0; i < 4 - prefix_len_v4; ++i)
            t32 <<= 8;

          a.prefix_v4.push_back(
            subnet{address{&t32, address::ipv4, address::host},
            prefix_bits});
        }
      }

      // BGP - announce - Prefix IPv6
      else if ((a.addr_family == 2) & (!attr_type_active)) {
        uint8_t prefix_len_v6;
        std::array<uint8_t, 16> bytes;
        uint32_t const *bytes32;
        vast::address addr_v6;
        a.length -= prefix_len;

        while (prefix_len > 0) {
          t8 = 0;
          byte.parse(f, f + 1, t8);
          prefix_len_v6 = t8 / 8;

          if (t8 % 8 != 0)
            prefix_len_v6 += 1;

          std::copy_n(f, prefix_len_v6, bytes.begin());
          bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
          addr_v6 = address{bytes32, address::ipv6, address::network};
          prefix_len -= prefix_len_v6;
          a.prefix_v6.push_back(subnet{addr_v6, t8});
          f += prefix_len_v6;
        }
      }

      if (a.length != 0) {
        VAST_WARNING(this, 
          "The Length is not zero. There are some not interpreted fields -> ", 
          a.length);
        f += a.length;
        a.length = 0;
        return false;
      }
      return true;
    } else {
      f = l;
      return false;
    }
  }

  /*--------------------BGP4MP_MESSAGE_NOTIFICATION---------------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_notification(Iterator &f, Iterator const &l, 
                                     Attribute &a) const {
    using namespace parsers;
    uint8_t t8 = 0;

    if(a.length != 0 && f + a.length <= l){  
      a.msg_type = "N";
      // BGP - NOTIFICATION - Error code
      byte.parse(f, f + 1, t8);
      a.length--;
      a.error_code = t8;
      // BGP - NOTIFICATION - Error subcode
      t8 = 0;
      byte.parse(f, f + 1, t8);
      a.length--;
      a.error_subcode = t8;
      // BGP - NOTIFICATION - Data
      uint16_t data_len = a.bgp_length - 21; // RFC 4271 Page 23
      f += data_len; //TODO: parse data
      a.length -= data_len;
      return true;
    } else {
      f = l;
      return false;
    }
  }

  /*--------------------BGP4MP_MESSAGE_KEEPALIVE---------------------*/
  template <class Iterator, class Attribute>
  bool parse_bgp4mp_msg_keepalive(Iterator &f, Iterator const &l, 
                                  Attribute &a) const {
    
    if(f <= l){
      a.msg_type = "K";
      return true;
    }else{
      return false;
    } 
  }

  /*-----------------TABLE_DUMP-----------------*/
  /*
  template <typename Iterator, typename Attribute>
  bool parse_table_dump(Iterator &f, Iterator const &l, Attribute &a) const {
    using namespace parsers;
    uint8_t  t8  = 0;
    uint16_t t16 = 0;
    uint32_t t32 = 0;

    if(a.length != 0 && f + a.length <= l) {
      // TABLE_DUMP - View Number
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      // TABLE_DUMP - Sequence Number
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      // TABLE_DUMP - Prefix - IPv4
      if(a.subtype == 1) {
        b32be.parse(f, f + 4, t32);
        a.length -= 4;
        // TABLE_DUMP - Prefix Length
        byte.parse(f, f + 1, t8);
        a.length--;
        // subnet{address{&t32, address::ipv4, address::host}, t8}
      } 
      // TABLE_DUMP - Prefix - IPv6
      else if (a.subtype == 2) {
        std::array<uint8_t, 16> bytes;
        std::copy_n(f, 16, bytes.begin());
        auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
        f += 16;
        a.length -= 16;
        // TABLE_DUMP - Prefix Length
        byte.parse(f, f + 1, t8);
        a.length--;
        // = subnet{address{bytes32, address::ipv6, address::network}, t8}
      }
      // TABLE_DUMP - Status
      f++;
      a.length--;
      // TABLE_DUMP - Originated Time
      t32 = 0;
      b32be.parse(f, f + 4, t32);
      a.length -= 4;
      // TABLE_DUMP - Peer IP Address - IPv4
      if(a.subtype == 1) {
        b32be.parse(f, f + 4, t32);
        a.length -= 4;
        // = address{&t32, address::ipv4, address::host}
      } 
      // TABLE_DUMP - Peer IP Address - IPv6
      else if (a.subtype == 2) {
        std::array<uint8_t, 16> bytes;
        std::copy_n(f, 16, bytes.begin());
        auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
        f += 16;
        a.length -= 16;
        // = address{bytes32, address::ipv6, address::network}
      }
      // TABLE_DUMP - Peer AS
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      // TABLE_DUMP - Attribute Length
      t16 = 0;
      b16be.parse(f, f + 2, t16);
      a.length -= 2;
      uint16_t attr_length = t16;
      // TABLE_DUMP - BGP Attribute
      f += attr_length;
      a.length -= attr_length;
    } else {
      VAST_DEBUG("MRT SIZE EXCEEDED -> ", a.length);
      f = l;
      return false;
    }
    return true;
  }
  */

  /*-----------------TABLE_DUMP_V2-----------------*/
  template <class Iterator, class Attribute>
  bool parse_table_dump_v2(Iterator &f, Iterator const &l, Attribute &a) const {
    using namespace parsers;
    uint8_t  t8  = 0;
    uint16_t t16 = 0;
    uint32_t t32 = 0;

    if(a.length != 0 && f + a.length <= l) {
      a.msg_type = "TDV2";
      // TABLE_DUMP_V2 - PEER_INDEX_TABLE
      if(a.subtype == 1) {
        VAST_DEBUG(this, "TABLE_DUMP_V2 - PEER_INDEX_TABLE not supported");
        f += a.length;
        a.length = 0;
      }
      // TABLE_DUMP_V2 - AFI/ASFI-Specific RIB Subtypes
      else if (a.subtype > 1 && a.subtype < 6) {
        // TABLE_DUMP_V2 - Sequence Number
        b32be.parse(f, f + 4, t32);
        a.length -= 4;
        // TABLE_DUMP_V2 - Prefix Length
        byte.parse(f, f + 1, t8);
        a.length--;
        uint8_t prefix_bits = t8;
        // TABLE_DUMP_V2 - Prefix
        // TABLE_DUMP_V2 - Prefix - RIB_IPV4_UNICAST and _MULTICAST
        if(a.subtype == 2 || a.subtype == 3){
          a.addr_family = 1;
          uint8_t prefix_len_v4;
          t32 = 0;
          prefix_len_v4 = prefix_bits / 8;

          if (t8 % 8 != 0)
            prefix_len_v4++;

          for (auto i = 0; i < prefix_len_v4; ++i) {
            t8 = 0;
            byte.parse(f, f + 1, t8);
            t32 <<= 8;
            t32 |= t8;
          }

          for (auto i = 0; i < 4 - prefix_len_v4; ++i)
            t32 <<= 8;

          a.prefix_v4.push_back(
            subnet{address{&t32, address::ipv4, address::host}, 
            prefix_bits});
          a.length -= prefix_len_v4;        
        }
        // TABLE_DUMP_V2 - Prefix - RIB_IPV6_UNICAST and _MULTICAST
        else if(a.subtype == 4 || a.subtype == 5) {
          a.addr_family = 2;
          uint8_t prefix_len_v6;
          std::array<uint8_t, 16> bytes;
          uint32_t const *bytes32;
          vast::address addr_v6;

          prefix_len_v6 = prefix_bits / 8;

          if (t8 % 8 != 0)
            prefix_len_v6 += 1;

          std::copy_n(f, prefix_len_v6, bytes.begin());
          bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
          addr_v6 = address{bytes32, address::ipv6, address::network};
          a.prefix_v6.push_back(subnet{addr_v6, t8});
          f += prefix_len_v6;
          a.length -= prefix_len_v6;         
        }
        // TABLE_DUMP_V2 - Entry Count
        b16be.parse(f, f + 2, t16);
        a.length -= 2;
        uint16_t entry_cnt = t16;
        // TABLE_DUMP_V2 - RIB Entries
        while (entry_cnt > 0) {
          form ribentryform;
          // TABLE_DUMP_V2 - Peer Index
          f += 2;
          a.length -= 2;
          // TABLE_DUMP_V2 - Originated Time
          t32 = 0;
          b32be.parse(f, f + 4, t32);
          a.length -= 4;
          ribentryform.ts = vast::timestamp{std::chrono::seconds{t32}};
          // TABLE_DUMP_V2 - Attribute Length
          t16 = 0;
          b16be.parse(f, f + 2, t16);
          a.length -= 2;
          uint16_t total_path_len = t16;
          // TABLE_DUMP_V2 - BGP Attribute
          uint8_t attr_type;
          uint8_t attr_flags;
          uint16_t attr_length;
          bool attr_ext_len_bit;

          while (total_path_len > 0) {
            // TABLE_DUMP_V2 - Attribute Flags
            byte.parse(f, f + 1, t8);
            a.length--;
            attr_flags = t8;
            total_path_len--;
            attr_ext_len_bit = static_cast<bool>((attr_flags & 16) >> 4);

            // TABLE_DUMP_V2 - Attribute Type Code (1 Byte)
            t8 = 0;
            byte.parse(f, f + 1, t8);
            a.length--;
            attr_type = t8;
            total_path_len--;
            if (attr_ext_len_bit) {
              // TABLE_DUMP_V2 - Attribute Length Field (2 Bytes)
              t16 = 0;
              b16be.parse(f, f + 2, t16);
              a.length -= 2;
              attr_length = t16;
              total_path_len -= 2;     
            } else {
              // TABLE_DUMP_V2 - Attribute Length Field (1 Byte)
              t8 = 0;
              byte.parse(f, f + 1, t8);
              a.length--;
              attr_length = t8;     
              total_path_len--;
            }
            // TABLE_DUMP_V2 - Origin
            if (attr_type == 1) {
              while (attr_length > 0) {
                t8 = 0;
                byte.parse(f, f + 1, t8);
                a.length--;

                if (t8 == 0)
                  ribentryform.origin = "IGP";

                else if (t8 == 1)
                  ribentryform.origin = "EGP";

                else if (t8 == 2)
                  ribentryform.origin = "INCOMPLETE";
              
                total_path_len--;
                attr_length--;
              }
            }
            // TABLE_DUMP_V2 - AS Path
            else if (attr_type == 2) {
              while (attr_length > 0) {
                // TABLE_DUMP_V2 - AS Path - Segment Type
                t8 = 0;
                byte.parse(f, f + 1, t8);
                a.length--;
                total_path_len--;
                attr_length--;
                uint8_t path_seg_type = t8;
                if (path_seg_type == 1) {
                  ribentryform.as_path_orded = "AS_SET";
                  ribentryform.as_path.push_back(count{0});
                } else if (path_seg_type == 2)
                  ribentryform.as_path_orded = "AS_SEQUENCE";

                // TABLE_DUMP_V2 - AS Path - Segment Length (Number of AS)
                t8 = 0;
                byte.parse(f, f + 1, t8);
                a.length--;
                total_path_len--;
                attr_length--;
                uint8_t path_seg_length = t8;

                // TABLE_DUMP_V2 - AS Path - Segment Value
                while (path_seg_length > 0) {
                  t32 = 0;
                  b32be.parse(f, f + 4, t32);
                  a.length -= 4;
                  total_path_len -= 4;
                  attr_length -= 4;
                  ribentryform.as_path.push_back(count{t32});
                  path_seg_length--;
                }
                if (path_seg_type == 1)
                  ribentryform.as_path.push_back(count{0});
              }
            }
            // TABLE_DUMP_V2 - Next Hop
            else if (attr_type == 3) {
              // TABLE_DUMP_V2 - Next Hop - IPv4
              if (attr_length == 4) {
                t32 = 0;
                b32be.parse(f, f + 4, t32);
                ribentryform.nexthop_v4 = address{&t32, address::ipv4, 
                                                  address::host};
                a.length -= 4;
                total_path_len -= 4;
                attr_length -= 4;
              }
              // TABLE_DUMP_V2 - Next Hop - IPv6
              else if (attr_length == 16) {
                std::array<uint8_t, 16> bytes;
                std::copy_n(f, 16, bytes.begin());
                auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
                ribentryform.nexthop_v6 = address{bytes32, address::ipv6, 
                                                  address::network};
                a.length -= 16;
                total_path_len -= 16;
                attr_length -= 16;
                f += 16;
              }
            }
            // TABLE_DUMP_V2 - Multi Exit Disc (MED)
            else if (attr_type == 4) {
              t32 = 0;
              b32be.parse(f, f + 4, t32);
              ribentryform.med = count{t32};
              a.length -= 4;
              total_path_len -= 4;
              attr_length -= 4;
            }
            // TABLE_DUMP_V2 - Local Pref
            else if (attr_type == 5) {
              t32 = 0;
              b32be.parse(f, f + 4, t32);
              ribentryform.local_pref = count{t32};
              a.length -= 4;
              total_path_len -= 4;
              attr_length -= 4;
            }
            // TABLE_DUMP_V2 - ATOMIC AGGREGATE
            else if (attr_type == 6) {
            }
            // TABLE_DUMP_V2 - AGGREGATOR
            else if (attr_type == 7) {
              ribentryform.atomic_aggregate = "AG";
              count aggregator_route;
              // TABLE_DUMP_V2 - Aggregator - Route (2 Bytes)
              if (attr_length % 6 == 0) {
                t16 = 0;
                b16be.parse(f, f + 2, t16);
                aggregator_route = count{t16};
                total_path_len -= 2;
                a.length -= 2;
                attr_length -= 2;
              }
              // TABLE_DUMP_V2 - Aggregator - Route (4 Bytes)
              else if (attr_length % 8 == 0) {
                t32 = 0;
                b32be.parse(f, f + 4, t32);
                aggregator_route = count{t32};
                total_path_len -= 4;
                a.length -= 4;
                attr_length -= 4;
              }
              // TABLE_DUMP_V2 - Aggregator - Prefix
              t32 = 0;
              b32be.parse(f, f + 4, t32);
              auto aggregator_addr = address{&t32, address::ipv4, 
                                             address::host};
              a.length -= 4;
              total_path_len -= 4;
              attr_length -= 4;
              ribentryform.aggregator = std::make_tuple(aggregator_route, 
                                                        aggregator_addr);
              if (attr_length > 0) {
                f += attr_length;
                total_path_len -= attr_length;
                a.length -= attr_length;
                attr_length = 0;
              }
            }

            // TABLE_DUMP_V2 - Community (RFC 1997)
            else if (attr_type == 8) {
              // TABLE_DUMP_V2 - Community
              while (attr_length > 0) {
                t16 = 0;
                b16be.parse(f, f + 2, t16);
                a.length -= 2;
                ribentryform.community += to_string(t16);
                t16 = 0;
                b16be.parse(f, f + 2, t16);
                ribentryform.community += std::string(":") + to_string(t16) + 
                                          std::string(" ");
                a.length -= 2;
                total_path_len -= 4;
                attr_length -= 4;
              }
              ribentryform.community.erase(ribentryform.community.end() - 1);
            }

            // TABLE_DUMP_V2 - 
            // MP_REACH_NLRI (RFC 2858) 
            // modified by TABLE_DUMP_V2 (RFC 6396 Section 4.3.4)
            else if (attr_type == 14) {
              // TABLE_DUMP_V2 - MP_REACH_NLRI - 
              // Length of Next Hop Network Address
              t8 = 0;
              byte.parse(f, f + 1, t8);
              a.length--;
              uint8_t mp_next_hop_len = t8;
              total_path_len -= (4 + mp_next_hop_len);
              attr_length -= (4 + mp_next_hop_len);
              // TABLE_DUMP_V2 - MP_REACH_NLRI - Next Hop
              std::array<uint8_t, 16> bytes;
              std::copy_n(f, mp_next_hop_len, bytes.begin());
              auto bytes32 = reinterpret_cast<uint32_t const *>(bytes.data());
              ribentryform.nexthop_v6 = address{bytes32, address::ipv6, 
                                                address::network};
              f += mp_next_hop_len;
              a.length -= mp_next_hop_len;
            }

            // TABLE_DUMP_V2 - Extended Communities Attribute (RFC 4360)
            else if (attr_type == 16) {
              VAST_DEBUG("Extended Communities not supported");
              a.length -= attr_length;
              f += attr_length;
              total_path_len -= attr_length;
            } else {
              VAST_WARNING(this, "Attribute Type Not Supported -> ", 
                           static_cast<uint16_t>(attr_type));
              if(attr_length > 0){
                a.length -= attr_length;
                f += attr_length;
                total_path_len -= attr_length;
              } else {
                f += a.length;
                a.length = 0;
                return false;
              }
            }
          }
          a.rib_entries.push_back(ribentryform);
          entry_cnt--;
        }
      }
      // TABLE_DUMP_V2 - RIB_GENERIC
      else if (a.subtype == 6) {
        VAST_DEBUG(this, "TABLE_DUMP_V2 - RIB_GENERIC not supported");
        f += a.length;
        a.length = 0;
      }
    } else {
      f = l;
      return false;
    }
    return true;
  }

  template <class Iterator, class Attribute>
  bool parse(Iterator &f, Iterator const &l, Attribute &def, Attribute &with, 
             Attribute &ann) const {
    using namespace parsers;

    /*MRT Header*/
    if (!parse_mrt_header(f, l, def)) {
      return false;
    }

    /*TABLE_DUMP*/
    if (def.type == 12) {
      VAST_DEBUG(this, "Old TABLE_DUMP V1 not supported");
      //if(!parse_table_dump(f, l ,def)){
      //  VAST_WARNING(this, "FAILED TO PARSE TABLE_DUMP");
      //  return false;
      //}
    }

    /*TABLE_DUMP_V2*/
    else if (def.type == 13) {
      if(!parse_table_dump_v2(f, l, def)){
        VAST_WARNING(this, "Failed to parse TABLE_DUMP_V2");
        return false;
      }
    }
    
    /*BGP4MP*/
    else if (def.type == 16 || def.type == 17) {

      /*BGP4MP_MESSAGE_AS4*/
      if (!parse_bgp4mp_msg_as4(f, l, def)) {
        VAST_WARNING(this, "Failed to parse MRT MESSAGE");
        return false;
      }
      /*BGP4MP_STATE_CHANGE*/
      if (parse_bgp4mp_state_change(f, l, def)) {
        return true;
      }
      /*BGP*/
      if (!parse_bgp(f, l, def)) {
        VAST_WARNING(this, "Failed to parse BGP MESSAGE");
        return false;
      }

      /*BGP4MP_MESSAGE_OPEN*/
      if (def.bgp_type == 1) {
        if(!parse_bgp4mp_msg_open(f,l,def)) {
          VAST_WARNING(this, "Failed to parse BGP MESSAGE OPEN");
          return false;
        }
      }
      /*BGP4MP_MESSAGE_UPDATE*/
      else if (def.bgp_type == 2) {
        with = def;
        /*BGP4MP_MESSAGE_UPDATE_WITHDRAW*/
        if (!parse_bgp4mp_msg_update_withdraw(f, l, with)) {
          VAST_WARNING(this, "Failed to parse BGP MESSAGE UPDATE WITHDRAW");
          return false;
        } 
        ann = with;
        /*BGP4MP_MESSAGE_UPDATE_OUNCE*/
        if (!parse_bgp4mp_msg_update_announce(f, l, ann)) {
          VAST_WARNING(this, "Failed to parse BGP MESSAGE UPDATE ANNOUNCE");
          return false;
        }
      }
      /*BGP4MP_MESSAGE_NOTIFICATION*/
      else if (def.bgp_type == 3) {
        if (!parse_bgp4mp_msg_notification(f,l,def)) {
          VAST_WARNING(this, "Failed to parse BGP MESSAGE NOTIFICATION");
          return false;
        }
      }
      /*BGP4MP_MESSAGE_KEEPALIVE*/
      else if (def.bgp_type == 4) {
        if (!parse_bgp4mp_msg_keepalive(f,l,def)) {
          VAST_WARNING(this, "Failed to parse BGP MESSAGE KEEPALIVE");
          return false;
        }
      }
      /*BGP4MP_TYPE_NOT_SUPPORTED*/
      else {
        VAST_WARNING(this, "BGP TYPE not supported -> ", def.bgp_type);
        f += def.length;
        def.length = 0;
        return false;
      }

    } else {
      VAST_WARNING(this, 
                   "MRT TYPE not TABLE_DUMP (12,13) or BGP4MP (16,17) -> ", 
                   def.type);
      f += def.length;
      def.length = 0;
      return false;
    }

    return true;
  }

  type announce_type;
  type route_type;
  type withdraw_type;
  type state_change_type;
  type open_type;
  type notification_type;
  type keepalive_type;
};

/// A BGP binary reader
class reader : public format::reader<bgpdumpbinary_parser> {
public:
  using format::reader<bgpdumpbinary_parser>::reader;

  reader() = default;

  explicit reader(std::unique_ptr<std::istream> in) : in_{std::move(in)} {
    VAST_ASSERT(in_);
  }

  expected<event> read();

  expected<void> schema(vast::schema const& sch);

  expected<vast::schema> schema() const;

  const char* name() const;

private:
  bool import();

private:
  std::unique_ptr<std::istream> in_; 
  std::stringstream packet_stream_;
  std::string packet_string_;
  std::vector<uint8_t> bytes_;
  std::vector<uint8_t>::iterator counter_;
  std::vector<event> event_queue_;
  event first_event_;
  bool imported_ = false;
};

} // namespace bgpdumpbinary
} // namespace format
} // namespace vast

#endif
