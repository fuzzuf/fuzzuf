/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
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
#include "fuzzuf/executor/proxy_executor.hpp"
#include <chrono>
#include <cstddef>
#include <cassert>
#include <memory>
#include <optional>
#include <boost/container/static_vector.hpp>
#include <sched.h>

#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/exceptions.hpp"
#include "fuzzuf/executor/executor.hpp"
#include "fuzzuf/utils/workspace.hpp"
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/utils/which.hpp"
#include "fuzzuf/utils/is_executable.hpp"
#include "fuzzuf/utils/interprocess_shared_object.hpp"
#include "fuzzuf/utils/errno_to_system_error.hpp"
#include "fuzzuf/feedback/inplace_memory_feedback.hpp"
#include "fuzzuf/feedback/exit_status_feedback.hpp"
#include "fuzzuf/feedback/put_exit_reason_type.hpp"
#include "fuzzuf/logger/logger.hpp"

bool ProxyExecutor::has_setup_sighandlers = false;

ProxyExecutor* ProxyExecutor::active_instance = nullptr;

// 前提: 
//    - path_to_write_inputで指定されるパスにファイルが作成できる状態になっていること
//    - fork server modeの場合はproxy_pathで指定されるプロキシはfork serverとして振る舞うこと
// 責務：
//    - proxy_pathにあるプロキシに渡すコマンドライン引数の作成
//      * `proxy_path pargv[] -- argv[]`の形でcargvに作成
//    - ProxyExecutorはproxy_pathを直接実行し、proxy_pathのプロキシがargv[0]をなんらかの形で実行することを期待する
//      * ProxyExecutorはargv[0]がどのように実行されるかは関知しない
//      * fork server modeではproxy_pathはfork serverとして振る舞うことが期待されている
//    - メンバの初期化をしつつ、以下の処理を順に行う
//      * 引数次第では、このプロセスとその子孫が実行されるCPUのコアを指定する。指定の仕方は3種類ある:
//         1. cpu_to_bindにProxyExecutor::CPUID_DO_NOT_BINDを渡して指定しない
//         2. cpu_to_bindに0以上 cpu_core_count-1以下の整数値を渡して、コアの番号を指定する
//         3. cpu_to_bindにProxyExecutor::CPUID_BIND_WHICHEVERを渡し、
//            空いているCPUコアを本クラスに検索させ、それに指定する
//         - 備考1（定義）:
//           * プロセスp（とその子孫）をコアaにbindするとは、プロセスp（とその子孫）がコアaで実行されることを保証し、
//             かつコアaでp（とその子孫）以外のFUZZUF関係のプロセスが動作しないことを意味する
//           * 現状では、これはLinuxのsched_setaffinity依存の機能でしかなく、厳密に言うならば
//             「sched_setaffinityを使って実行を許可するコアを1つに絞る」という機能。
//              本当に定義通りに動作するのかを気になる場合はmanページとUtil::GetFreeCpuを参照すること
//           * したがって、Linuxじゃない場合は、この処理はそもそも実行されない
//         - 備考2（ProxyExecutorがこの機能を持つ理由）
//           * CPUコアの限定はProxy特有の操作で、本来アルゴリズムが気にすることではない
//           * したがって、このExecutorが持っているべき処理である
//           * 一方、この処理はプロセス全体に影響を与える。単純には「1プロセスに1 executor」を意味する
//           * 将来的には、これを解決するためにCPUコア・Executorを管理するクラスができるべきである
//           * 当座はどの状況についても対応可能な3種類の選択肢を設けている
//      * シグナルハンドラを設定する（non fork server mode向けの暫定の措置。消しますこれは）
//      * PUTのコマンドライン引数の解析と前処理
//      * PUTに対して入力を送るために使うファイルを生成
//      * 共有メモリの設定
//        - afl_shm_sizeには、AFL系のccでビルドされたPUTが使用する共有メモリのサイズを指定する。
//        - bb_shm_sizeには、fuzzuf-ccでビルドされた、
//          Basic Block Coverageを記録するPUTが使用する共有メモリのサイズを指定する。
//        - 両者ともに、0に指定された場合は、使用しないものとみなし、確保を行わない
//        - 両者ともに、kernel内部ではPAGE_SIZEの倍数に切り上げられてメモリが確保される
//      * PUT向けの環境変数の設定
//      * fork server modeの場合はfork serverの起動
ProxyExecutor::ProxyExecutor(  
    const fs::path &proxy_path,
    const std::vector<std::string> &pargv,
    const std::vector<std::string> &argv,
    u32 exec_timelimit_ms,
    u64 exec_memlimit,
    bool forksrv,
    const fs::path &path_to_write_input,
    u32 afl_shm_size,
    u32  bb_shm_size,
    int cpuid_to_bind,  // FIXME: bindに関するテストを足す(どうテストする？）
    bool record_stdout_and_err
) :
    Executor( argv, exec_timelimit_ms, exec_memlimit, path_to_write_input.string() ),
    proxy_path ( proxy_path ),
    pargv ( pargv ),
    forksrv( forksrv ),
    afl_shm_size( afl_shm_size ),
    bb_shm_size( bb_shm_size ),
    binded_cpuid( std::nullopt ),

    // cargv, stdin_modeはSetCArgvAndDecideInputModeで設定
    cpu_core_count( Util::GetCpuCore() ), // これは暫定の実装です。ユーザー側から指定したい場合などは適宜実装を変更してください
    bb_shmid( INVALID_SHMID ),
    afl_shmid( INVALID_SHMID ),
    forksrv_pid( 0 ),
    forksrv_read_fd( -1 ),
    forksrv_write_fd( -1 ),
    bb_trace_bits( nullptr ),
    afl_trace_bits( nullptr ),
    child_timed_out( false ),
    record_stdout_and_err( record_stdout_and_err )
{

#ifdef __linux__
    // If cpuid_to_bind is not CPUID_DO_NOT_BIND,
    // then the executor tries to bind this process to a cpu core somehow
    if (cpuid_to_bind != CPUID_DO_NOT_BIND) {
        std::set<int> vacant_cpus = Util::GetFreeCpu(cpu_core_count); 

        if (cpuid_to_bind == CPUID_BIND_WHICHEVER) { 
            // this means "don't care which cpu core, but should bind"

            if (vacant_cpus.empty()) {
                ERROR("No more free CPU cores");
            }

            binded_cpuid = *vacant_cpus.begin(); // just return a random number
        } else { 
            if (cpuid_to_bind < 0 || cpu_core_count <= cpuid_to_bind) {
                ERROR("The CPU core id to bind should be between 0 and %d", cpu_core_count - 1);
            }

            if (vacant_cpus.count(cpuid_to_bind) == 0) {
                ERROR("The CPU core #%d to bind is not free!", cpuid_to_bind);
            }

            binded_cpuid = cpuid_to_bind;
        }

        cpu_set_t c;
        CPU_ZERO(&c);
        CPU_SET(binded_cpuid.value(), &c);

        if (sched_setaffinity(0, sizeof(c), &c)) ERROR("sched_setaffinity failed");
    }
#else 
    if (cpuid_to_bind != CPUID_DO_NOT_BIND) {
        DEBUG("In this environment, processes cannot be binded to a cpu core.");
    }
#endif /* __linux__ */

    if (!has_setup_sighandlers) {
        // 当座はグローバルにシグナルハンドラをセットするので、これはstaticなメソッド
        // なのでhas_setup_handlersがtrueなら二度とセットする必要がない
        SetupSignalHandlers();
        has_setup_sighandlers = true;
    }

    // シグナルハンドラが参照できるように、自分自身をstaticなポインタに入れておく
    // 複数のProxyExecutorが存在する場合にはactive_instanceが自分自身以外を指している場合があるため
    // 以下のassert文を入れることができない
    // assert(active_instance == nullptr);
    active_instance = this;

    SetCArgvAndDecideInputMode();
    OpenExecutorDependantFiles();

    // Executorの初期化をするこのタイミングで共有メモリを確保する
    // 各 ProxyExecutor::Run() でそのメモリを参照できればよい
    SetupSharedMemories();
    SetupEnvironmentVariablesForTarget();

    if (forksrv) {
        SetupForkServer();
    }
}

// 責務：
//  - 自クラスが扱うリソースを解放し、データを無効化する
//      - input_fd のファイルディスクリプタは閉じる。また、当該値を無効化する（誤動作防止）
//      - fork server modeで動作しているときは、fork serverとの通信に使っていたpipeを閉じ、fork serverプロセスを殺す
//  - 暫定的な役目: シグナルハンドラが参照するactive_instanceに自分が設定されている場合はそれをnullptrにして取り消す
ProxyExecutor::~ProxyExecutor() {
    // 複数のProxyExecutorが存在する場合にはactive_instanceが自分自身以外を指している場合があるため
    // 「active_instanceが自分ではなかったら、それはFuzzerHandle::Resetが呼ばれている」
    // と判断し、何もしない。逆に、active_instanceが自分だったら、nullptrにする。
    // 念の為nullptrとしているが、そもそもデストラクタが呼ばれる時点でハンドラが呼ばれることは現状ではありえないので、基本問題はない
    if (active_instance == this) {
        active_instance = nullptr;
    }

    if (input_fd != -1) {
        Util::CloseFile(input_fd);
        input_fd = -1;
    }

    if (null_fd != -1) {
        Util::CloseFile(null_fd);
        null_fd = -1;
    }

    EraseSharedMemories();

    if (forksrv) {
        TerminateForkServer();

        // 実際のPUTのプロセス(child_pid)はfork serverが管理すべきだが、
        // 念の為killしてあげる（fork serverがkillで終了しているはずなのでゾンビにならない。したがってwaitしない）
        KillChildWithoutWait();
    }
}

void ProxyExecutor::SetCArgvAndDecideInputMode() {
    assert(!argv.empty()); // 流石におかしい

    stdin_mode = true; // if we find @@, then assign false to stdin_mode

    cargv.emplace_back(proxy_path.c_str());

    // プロキシアプリケーションに与えるオプションの追加
    for (const auto& v : pargv ) {
        cargv.emplace_back(v.c_str());
    }

    // PUTのコマンドラインオプションは"--"以降に追加
    cargv.emplace_back("--");

    for (const auto& v : argv ) {
        if ( v == "@@" ) {
            stdin_mode = false;
            cargv.emplace_back(path_str_to_write_input.c_str());
        } else {
            cargv.emplace_back(v.c_str());
        }
    }
    cargv.emplace_back(nullptr);
}

// fork serverを停止させ関連する値をすべて適切に消去する
// 責務：
//  - forksrv_{read,write}_fd が有効な値であるとき、
//      - それらをcloseする
//      - 値を無効化する（誤動作防止）
//  - forksrv_pid が有効な値であるとき、
//      - forksrv_pid が指すプロセスを終了する
//      - waitpidによりforksrv_pidが指すプロセスの終了を刈り取る
//      - また、forksrv_pid の値を無効化する（誤動作防止）
void ProxyExecutor::TerminateForkServer() {
    if (fork_server_epoll_fd != -1) {
        close( fork_server_epoll_fd );
        fork_server_epoll_fd = -1;
    }

    if (forksrv_read_fd != -1) {
        Util::CloseFile(forksrv_read_fd);
        forksrv_read_fd = -1;
    }

    if (forksrv_write_fd != -1) {
        Util::CloseFile(forksrv_write_fd);
        forksrv_write_fd = -1;
    }

    if (fork_server_stdout_fd != -1) {
        close( fork_server_stdout_fd );
        fork_server_stdout_fd = -1;
    }
    
    if (fork_server_stderr_fd != -1) {
        close( fork_server_stderr_fd );
        fork_server_stderr_fd = -1;
    }


    if (forksrv_pid > 0) {
        int status;
        kill(forksrv_pid, SIGKILL);
        waitpid(forksrv_pid, &status, 0);
        forksrv_pid = -1;
    }
}


// staticなメソッド
// 前提:
//  - この関数が呼び出される時点で、active_instanceが必ず非nullptrになっている
//  - active_instanceはExecutorのインスタンスの有効なアドレスを保持すること
//  - 自プロセスにグローバルタイマーが存在し、SIGALRMシグナルにより本関数が呼ばれること
// 責務：
//  - SIGALRMに対するシグナルハンドラとして動作する
//      - 呼び出されたら、PUTが実行時間超過したものとしてactive_instance->child_pidをkillする
//      - フラグactive_instance->child_timed_outをセットする
void ProxyExecutor::AlarmHandler(int signum) {
    assert (signum == SIGALRM);
    assert (active_instance != nullptr);
    active_instance->KillChildWithoutWait();
    active_instance->child_timed_out = true;
}

// staticなメソッド
// 責務：
//  - シグナルに対してfuzzufのプロセスがどう対応するのかを規定する
//  - シグナルハンドラを必要とする場合はシグナルハンドラをセットする
// FIXME: シグナルに対する設定はプロセス全体で共通となるため、
// このプロセスで動作するすべてのfuzzerインスタンスが影響を受ける。
// したがって場合によってはプロセスの設計を変更する可能性があり、
// 現時点では単一のfuzzerインスタンスしか同時には利用しないという前提のもとで
// 暫定的な対処としてこのstaticメソッドを入れている。
void ProxyExecutor::SetupSignalHandlers() {
    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

// 現状fuzzufでは以下のシグナルをどう処理するか等の取り決めがないので一旦無視
#if 0
    /* Various ways of saying "stop". */

    sa.sa_handler = handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Window resize */

    sa.sa_handler = handle_resize;
    sigaction(SIGWINCH, &sa, NULL);

    /* SIGUSR1: skip entry */

    sa.sa_handler = handle_skipreq;
    sigaction(SIGUSR1, &sa, NULL);
#endif

    /* Things we don't care about. */

    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

    sa.sa_handler = ProxyExecutor::AlarmHandler;
    sigaction(SIGALRM, &sa, NULL);
}

namespace detail {
    template< typename Dest >
    bool read_chunk( Dest &dest, int fd ) {
        std::size_t cur_size = dest.size();
        dest.resize(
            cur_size + fuzzuf::executor::output_block_size
        );
        auto read_stat = read(
            fd,
            std::next( dest.data(), cur_size ),
            fuzzuf::executor::output_block_size
        );
        if( read_stat < 0 ) {
            dest.resize(cur_size); // reset dest, whatever the error is

            int e = errno;
            if( e == EAGAIN || e == EWOULDBLOCK )
                return false;
            else if( !( e == EINTR ) )
                throw fuzzuf::utils::errno_to_system_error(
                    e,
                    "read from child process failed during the execution"
                );
        }
	else
            dest.resize( cur_size + read_stat );
        return read_stat != 0;
    }
}

// 前提：
//  - input_fd は ProxyExecutor::SetupIO() で設定されたファイルを指すファイルディスクリプタであること
// 責務：
//  - (1) input_fd が指すファイルの中身がファズ（長さが len である buf の中身）と一致すること
//  - (2) 以下の要件を満たしたプロセスを実行すること（以降、これを満たすプロセスを「当該プロセス」と表記する）
//      - コンストラクタ引数argv で指定されたコマンドおよびコマンド引数を与えること
//      - 環境変数について以下の条件を満たすこと:
//        * fuzzufのbasic blockカバレッジを利用する場合は環境変数__FUZZUF_SHM_IDを受け取り、指定されたidから共有メモリを開く。共有メモリにカバレッジを正しく書き込む（最悪満たしていなくてもカバレッジを取れないだけで動作自体はする）
//        * AFLのedgeカバレッジを利用する場合は環境変数__AFL_SHM_IDを受け取り、指定されたidから共有メモリを開く。。共有メモリにカバレッジを正しく書き込む（最悪満たしていなくてもカバレッジが取れないだけで動作自体はする）
//      - TODO: 環境変数についての要件を明記（Instrument toolに関わる事項。今挙げているのは主要なもののみなので、今後機能追加していったりすると増える可能性あり）
//      - もし Executor::stdin_mode が true であるとき、input_fd を標準入力とすること
//  - (3) 当該プロセスは引数 timeout_ms で指定された時間で実行が中止されること。ただし、この値が0である場合には、メンバ変数 exec_timelimit_ms の値を参考に制限時間を決める
//  - (4) 本メソッドを終了するとき、当該プロセスは自発的に、または第三者のシグナルを契機に終了していること
//  - (5) child_pid に当該プロセスのプロセスIDを代入すること
//      - この責務の必要性は、本メソッド以外の第三者が当該プロセスを終了できるようにするため。
//        今後は第三者が当該プロセスを終了することはあるか？→Signal handlerを使う場合などがありうる
//        今後の拡張性のためこの責務を残しておく
void ProxyExecutor::Run(const u8 *buf, u32 len, u32 timeout_ms) {
    // locked until std::shared_ptr<u8> lock is used in other places
    while (lock.use_count() > 1) {
        usleep(100);
    }

    // if timeout_ms is 0, then we use exec_timelimit_ms;
    if (timeout_ms == 0) timeout_ms = exec_timelimit_ms;

    // Aliases
    ResetSharedMemories();
    if (record_stdout_and_err) {
        stdout_buffer.clear();
        stderr_buffer.clear();
    }

    WriteTestInputToFile(buf, len);

    //#if 0
    // TODO: 本来はDebugよりも重要度が低いTraceレベルの情報なので、ランレベルがDebugのときは表示されないようにしたい。
    DEBUG("Run: ");
    DEBUG("%s ", cargv[0]);
    std::for_each( cargv.begin(), cargv.end(), []( const char* v ) { DEBUG("%s ", v); } );
    DEBUG("\n")
    //#endif

    // この構造体は親プロセスと子プロセスで共有される
    // execvは成功した場合返って来ないので、初期値を成功(0)とし、失敗時に値をセットする
    auto child_state = fuzzuf::utils::interprocess::create_shared_object(
      fuzzuf::executor::child_state_t{ 0, 0 }
    );

    std::array< int, 2u > stdout_fd{ 0, 0 };
    std::array< int, 2u > stderr_fd{ 0, 0 };
    constexpr std::size_t read_size = 8u;
    boost::container::static_vector< std::uint8_t, read_size > read_buffer;
    bool timeout = true;
    if (forksrv) {
        // 現在実装されていないpersistent modeでのみ必要な値tmp。
        static u8 tmp[4];

        // fork server にPUTのプロセスの生成をリクエスト
        // fork serverに対して4バイトの値をpipeにwriteすることにより、PUTの実行の新しい開始をリクエストできる
        // PUTが正常に起動した場合はpipeでPUTのプロセスのpidが返ってくる
        // WriteFile, ReadFileは指定したバイト数だけ書き込み・読み込みができなかったら例外を吐く
        try {
            // FIXME: persistent mode実装時は、このtmpは前回の実行がタイムアウトしたかどうかを表す値にする必要がある
            Util::WriteFile(forksrv_write_fd, tmp, 4);

            read_buffer.resize( 4u );
            Util::ReadFile( forksrv_read_fd, read_buffer.data(), 4u, false );

            epoll_event event;
            auto left_ms = timeout_ms;
            while (left_ms > 0) {
                const auto begin_date = std::chrono::steady_clock::now();
                auto event_count = epoll_wait( fork_server_epoll_fd, &event, 1, left_ms );
                if ( event_count < 0 ) {
                    int e = errno;
                    if ( e != EINTR )
                        throw fuzzuf::utils::errno_to_system_error(
                                e,
                                "epoll_wait failed during the execution"
                              );
                }
                else if ( event_count == 0 ) break;
                else {
                    if ( event.events & EPOLLIN ) {
                        if ( event.data.fd == fork_server_stdout_fd )
                            // バッファにはoutput_block_size以上のデータがある可能性があるが、レベルトリガなので問題ない
                            detail::read_chunk( stdout_buffer, fork_server_stdout_fd );
                        else if ( event.data.fd == fork_server_stderr_fd )
                            // バッファにはoutput_block_size以上のデータがある可能性があるが、レベルトリガなので問題ない
                            detail::read_chunk( stderr_buffer, fork_server_stderr_fd );
                        else if ( event.data.fd == forksrv_read_fd ) {
                            std::size_t cur_size = read_buffer.size();
                            read_buffer.resize( read_size );
                            auto read_stat = read(
                                    forksrv_read_fd,
                                    std::next( read_buffer.data(), cur_size ),
                                    read_size - cur_size
                                 );
                            if( read_stat < 0 ) {
                                int e = errno;
                                if ( !( e == EAGAIN || e == EINTR || e == EWOULDBLOCK ) )
                                    throw fuzzuf::utils::errno_to_system_error(
                                            e,
                                            "read pid from child process failed during the execution"
                                          );
                            }
                            else {
                                read_buffer.resize( cur_size + read_stat );
                                if ( read_buffer.size() == read_size ) {
                                    left_ms = 0;
                                    timeout = false;
                                }
                            }
                        }
                    }
                    if ( event.events == EPOLLHUP || event.events == EPOLLERR )
                        ERROR("pipe to the child process was unexpectedly closed");
                }
                const auto end_date = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast< std::chrono::milliseconds >( end_date - begin_date ).count();
                if ( left_ms < elapsed ) left_ms = 0;
                else left_ms -= elapsed;
            }
        } catch(const FileError &e) {
            ERROR("Unable to request new process from fork server (OOM?)");
        }
        if( read_buffer.size() >= 4u )
            child_pid = *reinterpret_cast< std::uint32_t* >( read_buffer.data() );

        if (child_pid <= 0) ERROR("Fork server is misbehaving (OOM?)");
    } else {
        if (record_stdout_and_err) {
            if( pipe( stdout_fd.data() ) < 0 ) {
                throw fuzzuf::utils::errno_to_system_error(
                    errno,
                    "Unable to create stdout pipe"
                );
            }
            if( pipe( stderr_fd.data() ) < 0 ) {
                throw fuzzuf::utils::errno_to_system_error(
                    errno,
                    "Unable to create stderr pipe"
                );
            }
        }

        child_pid = Util::Fork();
        if (child_pid < 0) ERROR("fork() failed");

        if (!child_pid) {
            struct rlimit r;
            if (exec_memlimit) {
                r.rlim_max = r.rlim_cur = ((rlim_t)exec_memlimit) << 20;
            #ifdef RLIMIT_AS
                setrlimit(RLIMIT_AS, &r); /* Ignore errors */
            #else
                setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
            #endif /* ^RLIMIT_AS */
            }

            r.rlim_max = r.rlim_cur = 0;

            setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

            /* Isolate the process and configure standard descriptors. If out_file is
                specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
            setsid();

            if (record_stdout_and_err) { 
                dup2(stdout_fd[ 1 ], 1);
                dup2(stderr_fd[ 1 ], 2);
                close( stdout_fd[ 0 ] );
                close( stdout_fd[ 1 ] );
                close( stderr_fd[ 0 ] );
                close( stderr_fd[ 1 ] );
            } else {
                dup2(null_fd, 1);
                dup2(null_fd, 2);
            }

            if (stdin_mode) {
                dup2(input_fd, 0);
            } else {
                // stdin は /dev/null を割り当てる（「無」の入力を与える）
                dup2(null_fd, 0);
            }
	    // 子プロセスで新しい実行可能バイナリを実行する
	    // 失敗した場合はその事をchild_stateに記録する
            child_state->exec_result = execv(cargv[0], (char**)cargv.data());
            child_state->exec_errno = errno;

            /* Use a distinctive bitmap value to tell the parent about execv()
                falling through. */

            exit(0);
        }
    }
    
    int put_status; // PUT's status(retrieved via waitpid)
    if (forksrv) {
        if( timeout ) { // hangするような入力が渡り、実行時間超過したと思われる
            KillChildWithoutWait(); // タイムアウトしたPUTを殺した後、再度put_statusをfork serverからもらう
            child_timed_out = true;
        }

        if( read_buffer.size() < 8u ) {
            std::size_t cur_size = read_buffer.size();
            read_buffer.resize( read_size );
            Util::ReadFile(
                    forksrv_read_fd,
                    std::next( read_buffer.data(), cur_size ),
                    read_size - cur_size,
                    false
            );
        }

        if (record_stdout_and_err) {
            while( detail::read_chunk( stdout_buffer, fork_server_stdout_fd ) );
            while( detail::read_chunk( stderr_buffer, fork_server_stderr_fd ) );
        }

        if( read_buffer.size() >= 8u )
            put_status = *reinterpret_cast< std::uint32_t* >( std::next( read_buffer.data(), 4u ) );
        else
            ERROR("Unable to communicate with fork server (OOM?)");
    } else {
        // PUTがhangしたかどうかのフラグを初期化
        // シグナルハンドラ内でセットされる
        child_timed_out = false;

        static struct itimerval it;

        // タイマーをセットし、timeoutした場合にはSIGALRMが発生するようにする
        // SIGALRMのハンドラはProxyExecutor::AlarmHandlerに設定されており、
        // 内部でPUTがキルされる
        // ただしexec_timelimit_msが0に設定されている場合はSIGALRMを設定しない
        if (exec_timelimit_ms) {        
            it.it_value.tv_sec = (timeout_ms / 1000);
            it.it_value.tv_usec = (timeout_ms % 1000) * 1000;
            setitimer(ITIMER_REAL, &it, NULL);
        }

        // If record_stdout_and_err is true, here starts the loop for saving outputs to buffers.
        if (record_stdout_and_err) {
            close( stdout_fd[ 1 ] );
            close( stderr_fd[ 1 ] );

            auto epoll_fd = epoll_create( 1 );
            epoll_event stdout_event;
            stdout_event.data.fd = stdout_fd[ 0 ];
            stdout_event.events = EPOLLIN|EPOLLRDHUP;
            if( epoll_ctl(
                        epoll_fd,
                        EPOLL_CTL_ADD,
                        stdout_fd[ 0 ],
                        &stdout_event
                        ) < 0 ) {
                throw fuzzuf::utils::errno_to_system_error(
                        errno,
                        "Unable to epoll stdout pipe"
                        );
            }

            epoll_event stderr_event;
            stderr_event.data.fd = stderr_fd[ 0 ];
            stderr_event.events = EPOLLIN|EPOLLRDHUP;
            if( epoll_ctl(
                        epoll_fd,
                        EPOLL_CTL_ADD,
                        stderr_fd[ 0 ],
                        &stderr_event
                        ) < 0 ) {
                throw fuzzuf::utils::errno_to_system_error(
                        errno,
                        "Unable to epoll stdout pipe"
                        );
            }

            epoll_event event;
            auto left_ms = timeout_ms;
            unsigned int closed_count = 0u;
            fcntl( stdout_fd[ 0 ], F_SETFL, O_NONBLOCK );
            fcntl( stderr_fd[ 0 ], F_SETFL, O_NONBLOCK );
            while (left_ms > 0) {
                const auto begin_date = std::chrono::steady_clock::now();
                auto event_count = epoll_wait( epoll_fd, &event, 1, left_ms );
                if ( event_count < 0 ) {
                    int e = errno;
                    if( e != EINTR ) {
                        throw fuzzuf::utils::errno_to_system_error(
                                e,
                                "epoll_wait failed during the execution"
                              );
                    }
                }
                else if ( event_count == 0 ) break;
                else {
                    if ( event.events & EPOLLIN ) {
                        if ( event.data.fd == stdout_fd[ 0 ] )
                            // バッファにはoutput_block_size以上のデータがある可能性があるが、レベルトリガなので問題ない
                            detail::read_chunk( stdout_buffer, stdout_fd[ 0 ] );
                        else if ( event.data.fd == stderr_fd[ 0 ] )
                            // バッファにはoutput_block_size以上のデータがある可能性があるが、レベルトリガなので問題ない
                            detail::read_chunk( stderr_buffer, stderr_fd[ 0 ] );
                    }
                    if ( event.events == EPOLLHUP || event.events == EPOLLERR ) {
                        ++closed_count;
                        if ( closed_count == 2u )
                            break;
                    }
                }
                const auto end_date = std::chrono::steady_clock::now();
                const auto elapsed = std::chrono::duration_cast< std::chrono::milliseconds >( end_date - begin_date ).count();
                if ( left_ms < elapsed ) left_ms = 0;
                else left_ms -= elapsed;
            }
            close( epoll_fd );
        }

        if (waitpid(child_pid, &put_status, 0) <= 0) ERROR("waitpid() failed");

        if (record_stdout_and_err) {
            {
            bool cont = true;
            while( cont ) {
              cont = detail::read_chunk( stdout_buffer, stdout_fd[ 0 ] );
            }
            }
            {
            bool cont = true;
            while( cont ) {
              cont = detail::read_chunk( stderr_buffer, stderr_fd[ 0 ] );
            }
            }
            close( stdout_fd[ 0 ] );
            close( stderr_fd[ 0 ] );
        }

        // タイマーをリセット        
        if (exec_timelimit_ms) {
            it.it_value.tv_sec = 0;
            it.it_value.tv_usec = 0;
            setitimer(ITIMER_REAL, &it, NULL);
        }
    }
    
    // PUTのプロセスが停止しているわけではなく、終了している場合は（persistent mode以外はそうなるはず）child_pidがもういらないので0クリアでよい
    if (!WIFSTOPPED(put_status)) child_pid = 0; 
    DEBUG("Exec Status %d (pid %d)\n", put_status, child_pid);

    /* Any subsequent operations on trace_bits must not be moved by the
        compiler below this point. Past this location, trace_bits[] behave
        very normally and do not have to be treated as volatile. */

    MEM_BARRIER();

    // ここから先の実装が汚い。
    // これ多分aflから残り続けてる実装で汚い気もするし直してもいいかも

    u32 tb4 = 0;

    // 子プロセスのexecvが失敗している場合実行が失敗したことにする
    if( child_state->exec_result < 0 )
        tb4 = EXEC_FAIL_SIG;

    last_exit_reason = PUTExitReasonType::FAULT_NONE;
    last_signal = 0;

    /* Report outcome to caller. */
    if (WIFSIGNALED(put_status)) {
        last_signal = WTERMSIG(put_status);
        
        if (child_timed_out && last_signal == SIGKILL) 
            last_exit_reason = PUTExitReasonType::FAULT_TMOUT;
        else 
            last_exit_reason = PUTExitReasonType::FAULT_CRASH;
 
        return ;
    }

    /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
    must use a special exit code. */

    if (uses_asan && WEXITSTATUS(put_status) == MSAN_ERROR) {
        last_exit_reason = PUTExitReasonType::FAULT_CRASH;
        return;
    }

    if ( !forksrv && tb4 == EXEC_FAIL_SIG) {
        last_exit_reason = PUTExitReasonType::FAULT_ERROR;
        return;
    }

    last_exit_reason = PUTExitReasonType::FAULT_NONE;
    return;
}

InplaceMemoryFeedback ProxyExecutor::GetAFLFeedback() {
    return InplaceMemoryFeedback(afl_trace_bits, afl_shm_size, lock);
}

InplaceMemoryFeedback ProxyExecutor::GetBBFeedback() {
    return InplaceMemoryFeedback( bb_trace_bits,  bb_shm_size, lock);
}

InplaceMemoryFeedback ProxyExecutor::GetStdOut() {
    return InplaceMemoryFeedback( stdout_buffer.data(), stdout_buffer.size(), lock);
}

InplaceMemoryFeedback ProxyExecutor::GetStdErr() {
    return InplaceMemoryFeedback( stderr_buffer.data(), stderr_buffer.size(), lock);
}

ExitStatusFeedback ProxyExecutor::GetExitStatusFeedback() {
    return ExitStatusFeedback(last_exit_reason, last_signal);
}

// PUTに渡してconverage書き込んでもらうための共有メモリ群の初期化。
// どのPUTに対してもこれらの共有メモリ渡して使い回す（毎回各PUT向けに確保すると重い）
void ProxyExecutor::SetupSharedMemories() {
    if (afl_shm_size > 0) {
        afl_shmid = shmget(IPC_PRIVATE, afl_shm_size, IPC_CREAT | IPC_EXCL | 0600);
        if (afl_shmid < 0) ERROR("shmget() failed");

        afl_trace_bits = (u8 *)shmat(afl_shmid, nullptr, 0);
        if (afl_trace_bits == (u8 *)-1) ERROR("shmat() failed");
    }

    if (bb_shm_size > 0) {
        bb_shmid = shmget(IPC_PRIVATE, bb_shm_size, IPC_CREAT | IPC_EXCL | 0600);
        if (bb_shmid < 0) ERROR("shmget() failed");

        bb_trace_bits = (u8 *)shmat(bb_shmid, nullptr, 0);
        if (bb_trace_bits == (u8 *)-1) ERROR("shmat() failed");
    }
}

// 共有メモリは使い回すので、PUTに渡す前に毎回初期化してあげる
void ProxyExecutor::ResetSharedMemories() {
    if (afl_shm_size > 0) {
        std::memset(afl_trace_bits, 0, afl_shm_size);
    }

    if (bb_shm_size > 0) {
        std::memset(bb_trace_bits, 0, bb_shm_size);
    }

    MEM_BARRIER();
}

// Executorが死ぬときにSharedMemoryも消す
void ProxyExecutor::EraseSharedMemories() {
    if (afl_shm_size > 0) {
        if (shmdt(afl_trace_bits) == -1) ERROR("shmdt() failed");
        afl_trace_bits = nullptr;
        if (shmctl(afl_shmid, IPC_RMID, 0) == -1) ERROR("shmctl() failed");
        afl_shmid = INVALID_SHMID;
    }

    if (bb_shm_size > 0) {
        if (shmdt(bb_trace_bits) == -1) ERROR("shmdt() failed");
        bb_trace_bits = nullptr;
        if (shmctl(bb_shmid, IPC_RMID, 0) == -1) ERROR("shmctl() failed");
        bb_shmid = INVALID_SHMID;
    }
}

// afl-clang-fastやfuzzuf-ccでinsturmentを挿入されたPUTは、
// 環境変数で色々解釈することが多く、その設定。
// これは本来PUTを実行する子プロセスでやるべきことだが、
// 現状ではPUTを実行するたびに変更しなければならない環境変数は存在せず
// 親プロセスの環境変数を引き継ぐという性質を利用すると1回だけやっておくと良いことが分かる（まずければ移そう）
// これの利点として、StrPrintfのせいでheap領域のCopy on Writeが無駄になるとかが避けられるとかもある
void ProxyExecutor::SetupEnvironmentVariablesForTarget() {
    // 共有メモリのIDをPUTに渡す
    if (afl_shm_size > 0) {
        std::string afl_shmstr = std::to_string(afl_shmid);
        setenv(AFL_SHM_ENV_VAR, afl_shmstr.c_str(), 1);
    } else {
        // make sure to unset the environmental variable if it's unused
        unsetenv(AFL_SHM_ENV_VAR);
    }

    if (bb_shm_size > 0) {
        std::string bb_shmstr = std::to_string(bb_shmid);
        setenv(FUZZUF_SHM_ENV_VAR, bb_shmstr.c_str(), 1);
    } else {
        // make sure to unset the environmental variable if it's unused
        unsetenv(FUZZUF_SHM_ENV_VAR);
    }

    /* This should improve performance a bit, since it stops the linker from
        doing extra work post-fork(). */
    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 1); 

    // 以下のMSAN, ASAN, UBSAN向けの設定はそもそもAFL由来でfuzzufでは使っていないものなのであまり必要ないが、今後fuzzufにも競合せず組み込める機能だと思うので一応残しておく
    setenv("ASAN_OPTIONS",
        "abort_on_error=1:"
        "detect_leaks=0:"
        "malloc_context_size=0:"
        "symbolize=0:"
        "allocator_may_return_null=1:"
        "detect_odr_violation=0:"
        "handle_segv=0:"
        "handle_sigbus=0:"
        "handle_abort=0:"
        "handle_sigfpe=0:"
        "handle_sigill=0",
        0);

    setenv("MSAN_OPTIONS",
        Util::StrPrintf(
           "exit_code=%d:"
           "symbolize=0:"
           "abort_on_error=1:"
           "malloc_context_size=0:"
           "allocator_may_return_null=1:"
           "msan_track_origins=0:"
           "handle_segv=0:"
           "handle_sigbus=0:"
           "handle_abort=0:"
           "handle_sigfpe=0:"
           "handle_sigill=0",
           MSAN_ERROR
        ).c_str(),
        0);

    setenv("UBSAN_OPTIONS",
        "halt_on_error=1:"
        "abort_on_error=1:"
        "malloc_context_size=0:"
        "allocator_may_return_null=1:"
        "symbolize=0:"
        "handle_segv=0:"
        "handle_sigbus=0:"
        "handle_abort=0:"
        "handle_sigfpe=0:"
        "handle_sigill=0",
        0);

}

// 前提：
//  - 対象としているPUTがfork server modeに対応しているバイナリであること
// 責務：
//  - 子プロセスを生成し、子プロセス側でPUTをfork server modeで起動する
//  - PUTに対して適切な制限（メモリ制限など）を設ける
//  - 親プロセス（fuzzufが動く方のプロセス）と子プロセスのpipeのセットアップ
void ProxyExecutor::SetupForkServer() {

    // pipeのfdのセット。
    // それぞれ、parent -> child, child -> parent方向へのデータ送信に使う
    int par2chld[2], chld2par[2];

    if (pipe(par2chld) || pipe(chld2par)) ERROR("pipe() failed");

    std::array< int, 2u > stdout_fd{ -1, -1 };
    std::array< int, 2u > stderr_fd{ -1, -1 };

    if (record_stdout_and_err) {
        if( pipe( stdout_fd.data() ) < 0 ) {
            ERROR("Unable to create stdout pipe");
        }
        if( pipe( stderr_fd.data() ) < 0 ) {
            ERROR("Unable to create stderr pipe");
        }
    }

    forksrv_pid = fork();
    if (forksrv_pid < 0) ERROR("fork() failed");

    if (!forksrv_pid) {
        struct rlimit r;
        /* Umpf. On OpenBSD, the default fd limit for root users is set to
           soft 128. Let's try to fix that... */

        // FORKSRV_FD_WRITE=199, FORKSRV_FD_READ=198なので必要なlimitは200だが
        // 今後これらの定数が変更される可能性も考慮し、念の為std::max() + 1にしている
        long unsigned int needed_fd_lim = std::max(FORKSRV_FD_WRITE, FORKSRV_FD_READ) + 1;
        if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < needed_fd_lim) {

            r.rlim_cur = needed_fd_lim;
            setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
        }

        if (exec_memlimit) {
            r.rlim_max = r.rlim_cur = ((rlim_t)exec_memlimit) << 20;

#ifdef RLIMIT_AS
            setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
          /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
             according to reliable sources, RLIMIT_DATA covers anonymous
             maps - so we should be getting good protection against OOM bugs. */
            setrlimit(RLIMIT_DATA, &r); /* Ignore errors */
#endif /* ^RLIMIT_AS */


        }

        r.rlim_max = r.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &r);

        setsid();

        if (record_stdout_and_err) {
            dup2(stdout_fd[ 1 ], 1);
            dup2(stderr_fd[ 1 ], 2);
            close( stdout_fd[ 0 ] );
            close( stderr_fd[ 0 ] );
        } else {
            dup2(null_fd, 1);
            dup2(null_fd, 2);
        }

        if (stdin_mode) {
            dup2(input_fd, 0);
        } else {
            dup2(null_fd, 0);
        }

        if (dup2(par2chld[0], FORKSRV_FD_READ) < 0) ERROR("dup2() failed");
        if (dup2(chld2par[1], FORKSRV_FD_WRITE) < 0) ERROR("dup2() failed");

        close(par2chld[0]);
        close(par2chld[1]);
        close(chld2par[0]);
        close(chld2par[1]);

        execve(cargv[0], (char**)cargv.data(), environ);
        // TODO: fork server modeでないときに使われているEXEC_FAIL_SIGに相当するものは必要か検討
        exit(0);
    }

    DEBUG("cargv[0]: %s", cargv[0]);
    close(par2chld[0]);
    close(chld2par[1]);

    if (record_stdout_and_err) {
        close( stdout_fd[ 1 ] );
        close( stderr_fd[ 1 ] );
        fork_server_stdout_fd = stdout_fd[ 0 ];
        fork_server_stderr_fd = stderr_fd[ 0 ];
        fcntl( fork_server_stdout_fd, F_SETFL, O_NONBLOCK );
        fcntl( fork_server_stderr_fd, F_SETFL, O_NONBLOCK );
    }

    fork_server_epoll_fd = epoll_create( 1 );

    if (record_stdout_and_err) {
        fork_server_stdout_event.data.fd = fork_server_stdout_fd;
        fork_server_stdout_event.events = EPOLLIN|EPOLLRDHUP;
        if ( epoll_ctl(
                fork_server_epoll_fd,
                EPOLL_CTL_ADD,
                fork_server_stdout_fd,
                &fork_server_stdout_event
             ) < 0 ) {
    
            ERROR("Unable to epoll stdout pipe");
        }

        fork_server_stderr_event.data.fd = fork_server_stderr_fd;
        fork_server_stderr_event.events = EPOLLIN|EPOLLRDHUP;
        if ( epoll_ctl(
                fork_server_epoll_fd,
                EPOLL_CTL_ADD,
                fork_server_stderr_fd,
                &fork_server_stderr_event
             ) < 0 ) {

            ERROR("Unable to epoll stderr pipe");
        }
    }

    forksrv_write_fd = par2chld[1];
    forksrv_read_fd = chld2par[0];
    fork_server_read_event.data.fd = forksrv_read_fd;
    fork_server_read_event.events = EPOLLIN|EPOLLRDHUP;
    if( epoll_ctl(
          fork_server_epoll_fd,
          EPOLL_CTL_ADD,
          forksrv_read_fd,
          &fork_server_read_event
        ) < 0 ) {
    
        ERROR("Unable to epoll read pipe");
    }

    // 10秒の時間制限付き（AFL++が10秒に見えるのでそれに準拠）でfork serverの起動を待つ
    // 起動したらhandshakeを向こうが送ってくる
    u8 tmp[4];
    u32 time_limit = 10000;
    u32 res = Util::ReadFileTimed(forksrv_read_fd, &tmp, 4, time_limit);
    
    // FIXME: fork serverが失敗する原因は様々で、それぞれ応答が違って識別できたりするので、ちゃんと区別してあげたほうが親切
    if (res == 0 || res > time_limit) { 
        TerminateForkServer();
        ERROR("Fork server crashed");
    }

    return;
}

// this function may be called in signal handlers.
// use only async-signal-safe functions inside.
// basically, we care about only the case where ProxyExecutor::Run is running.
// in that case, we should kill the child process(of PUT) so that ProxyExecutor could halt without waiting the timeout.
// if this function is called during the call of other functions, then the child process is not active.
// we can call KillChildWithoutWait() anyways because the function checks if the child process is active.
void ProxyExecutor::ReceiveStopSignal(void) {
    // kill is async-signal-safe
    // the child process is active only in ProxyExecutor::Run and Run always uses waitpid, so we don't need to use waitpid here
    KillChildWithoutWait();
}

fuzzuf::executor::output_t ProxyExecutor::MoveStdOut() {
    return std::move( stdout_buffer );
}

fuzzuf::executor::output_t ProxyExecutor::MoveStdErr() {
    return std::move( stderr_buffer );
}
