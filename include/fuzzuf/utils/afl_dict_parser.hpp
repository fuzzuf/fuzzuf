/*
 * fuzzuf
 * Copyright (C) 2021-2023 Ricerca Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
/**
 * @file afl_dict_parser.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_UTILS_AFL_DICT_PARSER_HPP
#define FUZZUF_INCLUDE_UTILS_AFL_DICT_PARSER_HPP
#include <fcntl.h>

#include <boost/phoenix.hpp>
#include <boost/spirit/home/support/char_encoding/standard.hpp>
#include <boost/spirit/include/qi.hpp>
#include <boost/version.hpp>
#include <cstdint>
#include <functional>
#include <string>
#include <system_error>

#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/utils/check_capability.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "fuzzuf/utils/map_file.hpp"
#include "fuzzuf/utils/range_traits.hpp"
#include "fuzzuf/utils/type_traits/remove_cvr.hpp"
#include "fuzzuf/utils/void_t.hpp"
/**
 * Enables loading AFL dictionary
 * Destination type should be Sequential container of T where T::word_t is
 * defined and word_t is a sequential container with value_type that is
 * compatible to char, and T has a constructor with word_t as an argument
 */
namespace fuzzuf::utils::dictionary {
FUZZUF_CHECK_CAPABILITY(HasGet, has_get, std::declval<T>().get())

/**
 * @class DictionaryWord
 * @brief Meta function to return word_t type of the dictionary type T
 * type is defined only if T has word_t and value_type of T has member function
 * get()
 * @tparam T Dictionary type
 */
template <typename T, typename Enable = void>
struct DictionaryWord {};
template <typename T>
struct DictionaryWord<T, std::enable_if_t<has_get_v<range::RangeValueT<T>>>> {
  using type = typename range::RangeValueT<T>::word_t;
};

template <typename T>
using DictionaryWordT = typename DictionaryWord<T>::type;

/**
 * Add new entry that type is Word to dictionary that type is Dict
 * requirements: RangeValue of T has member function get()
 */
template <typename Dest, typename Word>
auto EmplaceWord(Dest &dest, Word &&word)
    -> std::enable_if_t<has_get_v<range::RangeValueT<Dest>>> {
  dest.emplace_back(range::RangeValueT<Dest>{std::move(word)});
}

template <typename Iterator, typename Dict>
class AFLDictRule : public boost::spirit::qi::grammar<Iterator, Dict()> {
  using dictionary_t = Dict;
  using word_t = DictionaryWordT<dictionary_t>;

 public:
  AFLDictRule(unsigned int filter, bool strict,
              const std::function<void(std::string &&)> &eout)
      : AFLDictRule::base_type(root) {
    namespace qi = boost::spirit::qi;
    namespace phx = boost::phoenix;

    escape = (qi::lit("\\\\")[qi::_val = '\\']) |
             (qi::lit("\\\"")[qi::_val = '"']) |
             (("\\x" >> hex8_p)[qi::_val = qi::_1]);

    if (strict) {
      escaped_text = qi::as_string[*(
          ((qi::standard::blank | qi::standard::graph) - '"' - '\\') | escape)];
      name = qi::as_string[+(qi::standard::graph - '@' - '=' - '"' - '#')];
      comment = ('#' >> *(qi::standard::blank |
                          qi::standard::graph))[qi::_pass = true];
    } else {
      escaped_text = qi::as_string[*((qi::byte_ - '"' - '\\') | escape)];
      name =
          qi::as_string[+(qi::byte_ - '@' - '=' - '"' - '#' - ' ' - qi::eol)];
      comment = ('#' >> *(qi::byte_ - qi::eol))[qi::_pass = true];
    }

    quoted_text =
        qi::omit[qi::lit('"')] >> escaped_text >> qi::omit[qi::lit('"')];
    root =
        qi::skip(qi::standard::blank)
                [(comment[qi::_pass = true]) |
                 ((quoted_text >> qi::omit[*qi::standard::blank >> -comment])
                      [qi::_pass =
                           phx::bind(&AFLDictRule::without_level, qi::_val,
                                     std::string("(no name)"), qi::_1, eout)]) |
                 ((name >> '@' >> qi::uint_ >> '=' >> quoted_text >>
                   qi::omit[*qi::standard::blank >> -comment])
                      [qi::_pass =
                           phx::bind(&AFLDictRule::with_level, qi::_val, qi::_1,
                                     qi::_2, filter, qi::_3, eout)]) |
                 ((name >> '=' >> quoted_text >>
                   qi::omit[*qi::standard::blank >> -comment])
                      [qi::_pass = phx::bind(&AFLDictRule::without_level,
                                             qi::_val, qi::_1, qi::_2, eout)]) |
                 ((*qi::standard::blank)[qi::_pass = true])] %
            qi::eol >>
        qi::omit[*qi::standard::space];
  }

 private:
  static bool with_level(dictionary_t &dest, const std::string &name,
                         unsigned int level, unsigned int threshold,
                         const std::string &text,
                         const std::function<void(std::string &&)> &eout) {
    if (level < threshold) return true;

    return without_level(dest, name, text, eout);
  }

  static bool without_level(dictionary_t &dest, const std::string &name,
                            const std::string &text,
                            const std::function<void(std::string &&)> &eout) {
    if (dest.size() == dest.max_size()) {
      eout("Too many entries.");
      return false;
    }

    static const word_t word;
    if (word.max_size() < text.size()) {
      eout(name + " is too long.");
      return false;
    }

    EmplaceWord(dest, word_t(text.begin(), text.end()));

    return true;
  }

  boost::spirit::qi::uint_parser<uint8_t, 16, 2, 2> hex8_p;
  boost::spirit::qi::rule<Iterator, char()> escape;
  boost::spirit::qi::rule<Iterator, int()> comment;
  boost::spirit::qi::rule<Iterator, std::string()> name;
  boost::spirit::qi::rule<Iterator, std::string()> escaped_text;
  boost::spirit::qi::rule<Iterator, std::string()> quoted_text;
  boost::spirit::qi::rule<Iterator, dictionary_t()> root;
};

template <typename T>
auto LoadAFLDictionary(const std::string &filename_, T &dest, bool strict,
                       const std::function<void(std::string &&)> &eout)
    -> utils::void_t<DictionaryWordT<T>> {
  namespace qi = boost::spirit::qi;

  unsigned int level = 0u;
  std::string filename;

  {
    fs::path path(filename_);
    const std::string leaf = path.filename().string();
    boost::fusion::vector<std::string, unsigned int> parsed;
    auto iter = leaf.begin();
    const auto end = leaf.end();
    if (!qi::parse(iter, end,
                   qi::as_string[*(qi::char_ - '@')] >> '@' >> qi::uint_,
                   parsed) ||
        iter != end)
      filename = filename_;
    else {
      filename =
          (path.remove_filename() / fs::path(boost::fusion::at_c<0>(parsed)))
              .string();
      level = boost::fusion::at_c<1>(parsed);
    }
  }

  auto mapped_file = utils::map_file(filename, O_RDONLY, true);
  const AFLDictRule<uint8_t *, T> rule(level, strict, eout);
  auto iter = mapped_file.begin().get();
  const auto end = mapped_file.end().get();
#if BOOST_VERSION >= 107200
  /**
   * Since boost 1.72.0, Boost.Spirt requires input characters casted to int
   * are in the range of 0x00 to 0xff. Otherwise, any qi::standard::* rules
   * cause abort().
   * As Boost.Spirit casts input characters to signed char internally before
   * it casts to int, 8bit characters higher than 0x7f causes crash.
   * According by the implementation, it looks like a unexpected behaviour yet
   * it need to be avoided.
   */
  if (strict) {
    if (std::find_if(iter, end, [](char ch) {
          return !boost::spirit::char_encoding::standard::strict_ischar(ch);
        }) != end)
      throw exceptions::invalid_file("invalid dictionary file", __FILE__,
                                     __LINE__);
  }
#endif
  T temp;
  if (!qi::parse(iter, end, rule, temp) || iter != end)
    throw exceptions::invalid_file("invalid dictionary file", __FILE__,
                                   __LINE__);

  dest.insert(dest.end(), temp.begin(), temp.end());
}
}  // namespace fuzzuf::utils::dictionary
#endif
