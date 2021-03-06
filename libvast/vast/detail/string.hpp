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

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "vast/detail/assert.hpp"
#include "vast/detail/coding.hpp"

namespace vast::detail {

/// Unscapes a string according to an escaper.
/// @param str The string to escape.
/// @param escaper The escaper to use.
/// @returns The escaped version of *str*.
template <class Escaper>
std::string escape(const std::string& str, Escaper escaper) {
  std::string result;
  result.reserve(str.size());
  auto f = str.begin();
  auto l = str.end();
  auto out = std::back_inserter(result);
  while (f != l)
    escaper(f, l, out);
  return result;
}

/// Unscapes a string according to an unescaper.
/// @param str The string to unescape.
/// @param unescaper The unescaper to use.
/// @returns The unescaped version of *str*.
template <class Unescaper>
std::string unescape(const std::string& str, Unescaper unescaper) {
  std::string result;
  result.reserve(str.size());
  auto f = str.begin();
  auto l = str.end();
  auto out = std::back_inserter(result);
  while (f != l)
    if (!unescaper(f, l, out))
      return {};
  return result;
}

auto hex_escaper = [](auto& f, auto, auto out) {
  auto hex = byte_to_hex(*f++);
  *out++ = '\\';
  *out++ = 'x';
  *out++ = hex.first;
  *out++ = hex.second;
};

auto hex_unescaper = [](auto& f, auto l, auto out) {
  auto hi = *f++;
  if (f == l)
    return false;
  auto lo = *f++;
  if (!std::isxdigit(hi) || !std::isxdigit(lo))
    return false;
  *out++ = hex_to_byte(hi, lo);
  return true;
};

auto print_escaper = [](auto& f, auto l, auto out) {
  if (std::isprint(*f))
    *out++ = *f++;
  else
    hex_escaper(f, l, out);
};

auto byte_unescaper = [](auto& f, auto l, auto out) {
  if (*f != '\\') {
    *out++ = *f++;
    return true;
  }
  if (l - f < 4)
    return false; // Not enough input.
  if (*++f != 'x') {
    *out++ = *f++; // Remove escape backslashes that aren't \x.
    return true;
  }
  return hex_unescaper(++f, l, out);
};

// The JSON RFC (http://www.ietf.org/rfc/rfc4627.txt) specifies the escaping
// rules in section 2.5:
//
//    All Unicode characters may be placed within the quotation marks except
//    for the characters that must be escaped: quotation mark, reverse
//    solidus, and the control characters (U+0000 through U+001F).
//
// That is, '"', '\\', and control characters are the only mandatory escaped
// values. The rest is optional.
auto json_escaper = [](auto& f, auto l, auto out) {
  auto escape_char = [](char c, auto out) {
    *out++ = '\\';
    *out++ = c;
  };
  auto json_print_escaper = [](auto& f, auto, auto out) {
    if (std::isprint(*f)) {
      *out++ = *f++;
    } else {
      auto hex = byte_to_hex(*f++);
      *out++ = '\\';
      *out++ = 'u';
      *out++ = '0';
      *out++ = '0';
      *out++ = hex.first;
      *out++ = hex.second;
    }
  };
  switch (*f) {
    default:
      json_print_escaper(f, l, out);
      return;
    case '"':
    case '\\':
      escape_char(*f, out);
      break;
    case '\b':
      escape_char('b', out);
      break;
    case '\f':
      escape_char('f', out);
      break;
    case '\r':
      escape_char('r', out);
      break;
    case '\n':
      escape_char('n', out);
      break;
    case '\t':
      escape_char('t', out);
      break;
  }
  ++f;
};

auto json_unescaper = [](auto& f, auto l, auto out) {
  if (*f == '"') // Unescaped double-quotes not allowed.
    return false;
  if (*f != '\\') { // Skip every non-escape character.
    *out++ = *f++;
    return true;
  }
  if (l - f < 2)
    return false; // Need at least one char after \.
  switch (auto c = *++f) {
    default:
      return false;
    case '\\':
      *out++ = '\\';
      break;
    case '"':
      *out++ = '"';
      break;
    case '/':
      *out++ = '/';
      break;
    case 'b':
      *out++ = '\b';
      break;
    case 'f':
      *out++ = '\f';
      break;
    case 'r':
      *out++ = '\r';
      break;
    case 'n':
      *out++ = '\n';
      break;
    case 't':
      *out++ = '\t';
      break;
    case 'u': {
      // We currently only support single-byte escapings and any unicode escape
      // sequence other than \u00XX as is.
      if (l - f < 4)
        return false;
      std::array<char, 4> bytes{{0,0,0,0}};
      bytes[0] = *++f;
      bytes[1] = *++f;
      bytes[2] = *++f;
      bytes[3] = *++f;
      if (bytes[0] != '0' || bytes[1] != '0') {
        // Leave input as is, we don't know how to handle it (yet).
        *out++ = '\\';
        *out++ = 'u';
        std::copy(bytes.begin(), bytes.end(), out);
      } else {
        // Hex-unescape the XX portion of \u00XX.
        if (!std::isxdigit(bytes[2]) || !std::isxdigit(bytes[3]))
          return false;
        *out++ = hex_to_byte(bytes[2], bytes[3]);
      }
      break;
    }
  }
  ++f;
  return true;
};

auto percent_escaper = [](auto& f, auto, auto out) {
  auto is_unreserved = [](char c) {
    return std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~';
  };
  if (is_unreserved(*f)) {
    *out++ = *f++;
  } else {
    auto hex = byte_to_hex(*f++);
    *out++ = '%';
    *out++ = hex.first;
    *out++ = hex.second;
  }
};

auto percent_unescaper = [](auto& f, auto l, auto out) {
  if (*f != '%') {
    *out++ = *f++;
    return true;
  }
  if (l - f < 3) // Need %xx
    return false;
  return hex_unescaper(++f, l, out);
};

auto double_escaper = [](const std::string& esc) {
  return [&](auto& f, auto, auto out) {
    if (esc.find(*f) != std::string::npos)
      *out++ = *f;
    *out++ = *f++;
  };
};

auto double_unescaper = [](const std::string& esc) {
  return [&](auto& f, auto l, auto out) -> bool {
    auto x = *f++;
    if (f == l) {
      *out++ = x;
      return true;
    }
    *out++ = x;
    auto y = *f++;
    if (x == y && esc.find(x) == std::string::npos)
      *out++ = y;
    return true;
  };
};

/// Escapes all non-printable characters in a string with `\xAA` where `AA` is
/// the byte in hexadecimal representation.
/// @param str The string to escape.
/// @returns The escaped string of *str*.
/// @relates bytes_escape_all byte_unescape
std::string byte_escape(const std::string& str);

/// Escapes all non-printable characters in a string with `\xAA` where `AA` is
/// the byte in hexadecimal representation, plus a given list of extra
/// characters to escape.
/// @param str The string to escape.
/// @param extra The extra characters to escape.
/// @returns The escaped string of *str*.
/// @relates bytes_escape_all byte_unescape
std::string byte_escape(const std::string& str, const std::string& extra);

/// Escapes all characters in a string with `\xAA` where `AA` is
/// the byte in hexadecimal representation of the character.
/// @param str The string to escape.
/// @returns The escaped string of *str*.
/// @relates byte_unescape
std::string byte_escape_all(const std::string& str);

/// Unescapes a byte-escaped string, i.e., replaces all occurrences of `\xAA`
/// with the value of the byte `AA`.
/// @param str The string to unescape.
/// @returns The unescaped string of *str*.
/// @relates byte_escape bytes_escape_all
std::string byte_unescape(const std::string& str);

/// Escapes a string according to JSON escaping.
/// @param str The string to escape.
/// @returns The escaped string.
/// @relates json_unescape
std::string json_escape(const std::string& str);

/// Unescapes a string escaped with JSON escaping.
/// @param str The string to unescape.
/// @returns The unescaped string.
/// @relates json_escape
std::string json_unescape(const std::string& str);

/// Escapes a string according to percent-encoding.
/// @note This function escapes all non-*unreserved* characters as listed in
///       RFC3986. It does *not* correctly preserve HTTP URLs, but servers
///       merely as poor-man's substitute to prevent illegal characters from
///       slipping in.
/// @param str The string to escape.
/// @returns The escaped string.
/// @relates percent_unescape
std::string percent_escape(const std::string& str);

/// Unescapes a percent-encoded string.
/// @param str The string to unescape.
/// @returns The unescaped string.
/// @relates percent_escape
std::string percent_unescape(const std::string& str);

/// Escapes a string by repeating characters from a special set.
/// @param str The string to escape.
/// @param esc The set of characters to double-escape.
/// @returns The escaped string.
/// @relates double_unescape
std::string double_escape(const std::string& str, const std::string& esc);

/// Unescapes a string by removing consecutive character sequences.
/// @param str The string to unescape.
/// @param esc The set of repeated characters to unescape.
/// @returns The unescaped string.
/// @relates double_escape
std::string double_unescape(const std::string& str, const std::string& esc);

/// Replaces all occurences of a substring.
/// @param str The string in which to replace a substring.
/// @param search The string to search.
/// @param replace The replacement string.
/// @returns The string with replacements.
std::string replace_all(std::string str, std::string_view search,
                        std::string_view replace);

/// Splits a character sequence into a vector of substrings.
/// @param str The string to split.
/// @param sep The seperator where to split.
/// @param esc The escape string. If *esc* occurrs immediately in front of
///            *sep*, then *sep* will not count as a separator.
/// @param max_splits The maximum number of splits to perform.
/// @param include_sep If `true`, also include the separator after each
///                    match.
/// @pre `!sep.empty()`
/// @warning The lifetime of the returned substrings are bound to the lifetime
/// of the string pointed to by `str`.
/// @returns A vector of substrings.
std::vector<std::string_view> split(std::string_view str, std::string_view sep,
                                    std::string_view esc = "",
                                    size_t max_splits = -1,
                                    bool include_sep = false);

/// Constructs a `std::vector<std::string>` from a ::split result.
/// @param v The vector of iterator pairs from ::split.
/// @returns a vector of strings with the split elements.
std::vector<std::string> to_strings(const std::vector<std::string_view>& v);

/// Joins a sequence of strings according to a seperator.
/// @param begin The beginning of the sequence.
/// @param end The end of the sequence.
/// @param sep The string to insert between each element of the sequence.
/// @returns The joined string.
template <class Iterator, class Predicate>
std::string join(Iterator begin, Iterator end, std::string_view sep,
                 Predicate p) {
  std::string result;
  if (begin != end) {
    result += p(*begin++);
    for (; begin != end; ++begin) {
      result += sep;
      result += p(*begin);
    }
  }
  return result;
}

template <class Iterator>
std::string join(Iterator begin, Iterator end, std::string_view sep) {
  return join(begin, end, sep, [](auto&& x) -> decltype(x) { return x; });
}

template <class T>
std::string join(const std::vector<T>& v, std::string_view sep) {
  if constexpr (std::is_same_v<T, std::string>
                || std::is_same_v<T, std::string_view>) {
    return join(v.begin(), v.end(), sep);
  } else {
    auto pred = [](const T& x) {
      using std::to_string;
      return to_string(x);
    };
    return join(v.begin(), v.end(), sep, pred);
  }
}

/// Determines whether a string occurs at the beginning of another.
/// @param begin The beginning of the string.
/// @param end The end of the string.
/// @param str The substring to check at the start of *[begin, end)*.
/// @returns `true` iff *str* occurs at the beginning of *[begin, end)*.
template <class Iterator>
bool starts_with(Iterator begin, Iterator end, std::string_view str) {
  using diff = typename std::iterator_traits<Iterator>::difference_type;
  if (static_cast<diff>(str.size()) > end - begin)
    return false;
  return std::equal(str.begin(), str.end(), begin);
}

inline bool starts_with(std::string_view str, std::string_view start) {
  return starts_with(str.begin(), str.end(), start);
}

/// Determines whether a string occurs at the end of another.
/// @param begin The beginning of the string.
/// @param end The end of the string.
/// @param str The substring to check at the end of *[begin, end)*.
/// @returns `true` iff *str* occurs at the end of *[begin, end)*.
template <class Iterator>
bool ends_with(Iterator begin, Iterator end, std::string_view str) {
  using diff = typename std::iterator_traits<Iterator>::difference_type;
  return static_cast<diff>(str.size()) <= end - begin
         && std::equal(str.begin(), str.end(), end - str.size());
}

inline bool ends_with(std::string_view str, std::string_view end) {
  return ends_with(str.begin(), str.end(), end);
}

} // namespace vast::detail

