/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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
 * @file pipe.hpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#ifndef FUZZUF_CC_INCLUDE_UTILS_PIPE_HPP
#define FUZZUF_CC_INCLUDE_UTILS_PIPE_HPP
#include <array>

namespace fuzzuf::utils {

/**
 * Wrapper for pipe operation required in executor.
 * This class is intended to make executor code simple.
 */
class Pipe {
 public:
  Pipe();
  Pipe(const Pipe&) = delete;
  Pipe(Pipe&&) = delete;
  Pipe& operator=(const Pipe&) = delete;
  Pipe& operator=(Pipe&&) = delete;
  ~Pipe();
  /**
   * Indicate this pipe is read only for this process.
   */
  void Readonly();
  /**
   * Indicate this pipe is write only for this process.
   */
  void Writeonly();
  /**
   * Close this pipe.
   */
  void CloseBoth();
  /**
   * Bind this pipe to specified file descriptor.
   * Pipe will marked as read only and read data is passed to the file
   * descriptor.
   */
  void PipeToFd(int fd);
  /**
   * Bind this pipe to specified file descriptor.
   * Pipe will marked as write only and incoming data from the file descriptor
   * is passed to the pipe.
   */
  void FdToPipe(int fd);
  /**
   * Get file descriptor of the pipe.
   * readonly() or writeonly() must be called prior to this function.
   */
  int GetFd() const;

 private:
  std::array<int, 2u> fds;
};

}

#endif

