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
/*
   PUTのタイムアウトのために設定されるタイマーが、例えば、SIGALRMによって実現されている場合、「1つのプロセスで1つしかタイマーを設定できない」状況になっている。
   この状況において、仮に2つFuzzerインスタンスを並列に起動したとすると、2つめのFuzzerインスタンスの起動によって、タイマーがリセットされてしまう。
   そうすると、1つめのFuzzerインスタンスで実行されているPUTが正常にタイムアウトしない可能性がある。これが発生していないことを確認するのがこのテストの目的。
   テストの方針を図示すると以下のようになる:

正常なケース
  秒数    FuzzerA                                  FuzzerB
   0      タイムアウト3秒でsleep 4を実行           PUT実行前に2秒待つ
          タイマー1をセットする。
   1
   2                                               タイムアウト3秒でsleep
4を実行 タイマー2をセットする。 3      タイマー1でタイムアウトする。
   4
   5 タイマー2でタイム・アウトする。

異常なケース
  秒数    FuzzerA                                  FuzzerB
   0      タイムアウト3秒でsleep 4を実行           PUT実行前に2秒待つ
          タイマー(グローバル)をセットする。
   1
   2                                               タイムアウト3秒でsleep
4を実行 タイマーがリセットされる。
   3
   4      タイマーがリセットされ残り1秒残っている
          sleep 4が正常終了してしまう
   5 タイマーでタイム・アウトする。
 */

#define BOOST_TEST_MODULE fuzzer.multiple.instances
#define BOOST_TEST_DYN_LINK
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>
#include <functional>
#include <iostream>
#include <random>
#include <thread>

#include "config.h"
#include "create_file.hpp"
#include "fuzzuf/exec_input/exec_input.hpp"
#include "fuzzuf/python/python_fuzzer.hpp"
#include "fuzzuf/utils/filesystem.hpp"
#include "move_to_program_location.hpp"

// Fuzzerのインスタンスを作り、わざとタイムアウトするPUTの実行を行う
// fork server mode, non fork server
// mode双方テストするため、引数でどちらのモードを使うか指定
// resultにはテストが成功した時true、失敗した時falseが入る
void LaunchInstance(bool forksrv, bool &result) {
  // Create root directory
  std::string root_dir_template("/tmp/fuzzuf_test.XXXXXX");
  const auto raw_dirname = mkdtemp(root_dir_template.data());
  if (!raw_dirname) throw -1;
  BOOST_CHECK(raw_dirname != nullptr);
#ifdef HAS_CXX_STD_FILESYSTEM
  namespace fs = std::filesystem;
#else
  namespace fs = boost::filesystem;
#endif
  auto root_dir = fs::path(raw_dirname);
  BOOST_SCOPE_EXIT(&root_dir) {
    // Executed on this test exit
    fs::remove_all(root_dir);
  }
  BOOST_SCOPE_EXIT_END

  auto input_dir = root_dir / "input";
  auto output_dir = root_dir / "output";
  BOOST_CHECK_EQUAL(fs::create_directory(input_dir), true);
  // AddSeedを使うので初期シードは必要ない
  // auto input_path = input_dir / "0";
  // create_file( input_path.string(), "Hello, World!" );

  // Create fuzzer instance
  auto fuzzer = fuzzuf::bindings::python::PythonFuzzer(
      {"../put_binaries/command_wrapper", "/bin/sleep",
       "4"},  // 4秒sleepする。ただしタイムアウトは3秒
      input_dir.native(), output_dir.native(), 3000, 10000, forksrv, true,
      true  // need_afl_cov, need_bb_cov
  );

  // Configurate fuzzer
  fuzzer.SuppressLog();

  auto id = fuzzer.AddSeed(
      1, {1});  // どんなシードを与えようがタイムアウトして然るべき

  // これがfalseならテスト失敗。ただしここではBOOST_CHECK_EQUALは呼ばない。
  // 子スレッド側で呼ばれるとどうなるかわからないので、ちゃんと親で呼ぶ
  result = (id == fuzzuf::exec_input::ExecInput::INVALID_INPUT_ID);
}

// 1プロセスで2つFuzzerインスタンスを作って両者でPUTを実行する（threadを利用する）。
// ただし、片方を少し遅延させて起動する。
// fork server mode, non fork server
// mode双方テストするため、引数でどちらのモードを使うか指定
void DelayedLaunchInstances(bool forksrv) {
  // cd $(dirname $0)
  MoveToProgramLocation();

  // std::threadで親スレッド・子スレッド側で2つのFuzzerインスタンスを作る。

  bool child_result = false;
  bool parent_result = false;

  std::thread child_thread(LaunchInstance, forksrv, std::ref(child_result));
  // 2秒待ってから親も起動。
  sleep(2);
  LaunchInstance(forksrv, parent_result);
  child_thread.join();

  BOOST_CHECK(parent_result);
  BOOST_CHECK(child_result);
}

// FIXME: 現状non fork server
// modeではこのテストは失敗するはずなので当座の処置としてfork server
// modeのみテストする
// 複数のインスタンスを同時に実行してもすべてのインスタンスでPUTのタイムアウトが正しく行われることの確認
BOOST_AUTO_TEST_CASE(FuzzerMultipleInstancesForkMode) {
  // 出力を入れないと、複数テストケースある場合、切れ目がどこかが分からず、どっちが失敗しているか分からない事に気づいた
  std::cout << "[*] FuzzerMultipleInstancesForkMode started\n";
  DelayedLaunchInstances(true);
  std::cout << "[*] FuzzerMultipleInstancesForkMode ended\n";
}
