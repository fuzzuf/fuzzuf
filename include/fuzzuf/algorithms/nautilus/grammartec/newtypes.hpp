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
 * @file newtypes.hpp
 * @brief Definitions of some simple types
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_NEWTYPES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_NAUTILUS_GRAMMARTEC_NEWTYPES_HPP

#include <boost/range/irange.hpp>

namespace fuzzuf::algorithm::nautilus::grammartec {

class IDBase {
 public:
  IDBase() : _id(0) {}
  IDBase(size_t id) : _id(id) {}
  size_t id() const { return _id; }
  virtual ~IDBase() {}

  IDBase(const IDBase& other) { _id = other.id(); }  // copy constructor
  inline operator size_t() const { return _id; }     // cast to size_t
  inline IDBase& operator=(const IDBase& other) {    // assignment
    _id = other.id();
    return *this;
  }
  inline bool operator==(const IDBase& rhs) const {  // eq comparison
    return _id == rhs.id();
  }
  inline bool operator!=(const IDBase& rhs) const {  // neq comparison
    return _id != rhs.id();
  }

 protected:
  size_t _id;
};

struct RuleID : IDBase {
  using IDBase::IDBase;
};

struct NodeID : IDBase {
  using IDBase::IDBase;

  /* Prefix increment */
  inline NodeID& operator++() {
    _id++;
    return *this;
  }
};

struct NTermID : IDBase {
  using IDBase::IDBase;
};

}  // namespace fuzzuf::algorithm::nautilus::grammartec

namespace std {

using namespace fuzzuf::algorithm::nautilus::grammartec;

/* Define hash function for use in unordered_map */
template <>
struct hash<RuleID> {
  std::size_t operator()(const RuleID& key) const { return key.id(); }
};

template <>
struct hash<NodeID> {
  std::size_t operator()(const NodeID& key) const { return key.id(); }
};

template <>
struct hash<NTermID> {
  std::size_t operator()(const NTermID& key) const { return key.id(); }
};

}  // namespace std

#endif
