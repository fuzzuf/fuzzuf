
fs::path SelectTracer( const fs::path &libexec_path, Tracer tracer, Arch arch ) {
  if( tracer == Tracer::Coverage && arch == Arch::X86 ) return libexec_path / "qemu-trace-coverage-x86";
  else if( tracer == Tracer::Coverage && arch == Arch::X64 ) return libexec_path / "qemu-trace-coverage-x64";
  else if( tracer == Tracer::Branch && arch == Arch::X86 ) return libexec_path / "qemu-trace-branch-x86";
  else if( tracer == Tracer::Branch && arch == Arch::X64 ) return libexec_path / "qemu-trace-branch-x64";
  else if( tracer == Tracer::BBCount && arch == Arch::X86 ) return libexec_path / "qemu-trace-bbcount-x86";
  else if( tracer == Tracer::BBCount && arch == Arch::X64 ) return libexec_path / "qemu-trace-bbcount-x64";
  else throw -1;
}

int GetBranchTrace( const fs::path &libexec_path, const seed::Seed &seed ) {
  SetupFile( seed );
  const auto tracer = SelectTracer( libexec_path, Tracer::Branch, arch );

  constexpr std::size_t chunk_size = 512u;
  std::vector<std::string> args;
  std::vector< char* > argv;
  args.push_back( tracer.string() );
  args.push_back( "/bin/cat" );
  std::transform(args.begin(), args.end(), std::back_inserter(argv),
                 [](auto& v) { return v.data(); });
  argv.push_back(nullptr);
  std::vector<std::string> env;
  std::vector< char* > envp;
  fs::path branch_log = out_dir / ".branch";
  env.push_back( std::string( "ECL_BRANCH_LOG=" ) + branch_log.string() );
  fs::path coverage_log = out_dir / ".coverage";
  env.push_back( std::string( "ECL_COVERAGE_LOG=cov" ) + coverage_log.string() );
  fs::path bitmap_log = out_dir / ".bitmap";
  env.push_back( std::string( "ECL_BITMAP_LOG=" ) + bitmap_log.string() );
  fs::path dbg_log = out_dir / ".debug";
  env.push_back( "ECL_FORK_SERVER=0" );
  env.push_back( "ECL_BRANCH_ADDR=0" );
  env.push_back( "ECL_BRANCH_IDX=0" );
  env.push_back( "ECL_MEASURE_COV=0" );
  std::transform(env.begin(), env.end(), std::back_inserter(envp),
                 [](auto& v) { return v.data(); });
  envp.push_back(nullptr);

  Pipe target_stdin;
  Pipe target_stdout;
  Pipe target_stderr;

  int epoll_fd = -1;
  epoll_event stdin_event;
  epoll_event stdout_event;
  epoll_event stderr_event;

  auto child_pid = fork();
  if (child_pid < 0) {
    std::abort();
  }
  if (child_pid == 0) {
    target_stdin.PipeToFd(0);
    target_stdout.FdToPipe(1);
    target_stderr.FdToPipe(2);
    execvpe(argv.front(), argv.data(), envp.data() );
    exit(-1);
  }
  target_stdin.Writeonly();
  target_stdout.Readonly();
  target_stderr.Readonly();
  
  epoll_fd = epoll_create(1);
  stdin_event.data.fd = target_stdin.GetFd();
  stdin_event.events = EPOLLOUT | EPOLLRDHUP;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_stdin.GetFd(), &stdin_event) <
      0) {
    std::abort();
  }

  stdout_event.data.fd = target_stdout.GetFd();
  stdout_event.events = EPOLLIN | EPOLLRDHUP;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_stdout.GetFd(), &stdout_event) <
      0) {
    std::abort();
  }

  stderr_event.data.fd = target_stderr.GetFd();
  stderr_event.events = EPOLLIN | EPOLLRDHUP;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, target_stderr.GetFd(), &stderr_event) <
      0) {
    std::abort();
  }

  std::size_t standard_input_written_bytes = 0u;
  std::vector<std::byte> standard_input;
  std::visit(
    [&]( const auto &v ) {
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, StdInput > ) {
	standard_input = seed.Concretize();
      }
    },
    seed.source
  );
  std::vector<std::byte> standard_output;
  std::vector<std::byte> standard_error;

  epoll_event event;
  int wait_for = -1;
  int active_fds = 3;
  while (1) {
    auto event_count = epoll_wait(epoll_fd, &event, 1, wait_for);
    if (event_count < 0) {
      int e = errno;
      if (e != EINTR) {
        std::abort();
      }
    } else if (event_count == 0) {
      break;
    } else {
      if (event.events & EPOLLIN) {
        if (event.data.fd == target_stdout.GetFd()) {
          const auto old_size = standard_output.size();
          standard_output.resize(old_size + chunk_size);
          int read_size = 0u;
          if ((read_size = read(target_stdout.GetFd(),
                                std::next(standard_output.data(), old_size),
                                chunk_size)) < 0) {
            std::abort();
          }
          standard_output.resize(old_size + read_size);
        } else if (event.data.fd == target_stderr.GetFd()) {
          const auto old_size = standard_error.size();
          standard_error.resize(old_size + chunk_size);
          int read_size = 0u;
          if ((read_size = read(target_stderr.GetFd(),
                                std::next(standard_error.data(), old_size),
                                chunk_size)) < 0) {
            std::abort();
          }
          standard_error.resize(old_size + read_size);
        }
      } else if (event.events & EPOLLOUT) {
        if (event.data.fd == target_stdin.GetFd()) {
          if (standard_input_written_bytes != standard_input.size()) {
            const auto count = write(
                target_stdin.GetFd(),
                std::next(standard_input.data(), standard_input_written_bytes),
                standard_input.size() - standard_input_written_bytes);
            if (count < 0) {
              std::abort();
            }
            standard_input_written_bytes += count;
          }
          if (standard_input_written_bytes == standard_input.size()) {
            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, target_stdin.GetFd(),
                          &stdin_event) < 0) {
              std::abort();
            }
            target_stdin.CloseBoth();
	    --active_fds;
	    if( active_fds == 0 ) {
              wait_for = 0;
	    }
          }
        }
      } else if (event.events == EPOLLHUP || event.events == EPOLLERR) {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event.data.fd, nullptr) < 0) {
          std::abort();
        }
	--active_fds;
	if( active_fds == 0 ) {
          wait_for = 0;
	}
      } else if(event.events == EPOLLRDHUP) {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event.data.fd, nullptr) < 0) {
          std::abort();
        }
	--active_fds;
	if( active_fds == 0 ) {
          wait_for = 0;
	}
      }
    }
  }

  //timeout_flag = 0; // Reset timeout_flag
 
  int wstatus = 0u;
  if (waitpid(child_pid, &wstatus, 0) < 0) {
    std::abort();
  }

  std::string standard_output_str;
  std::transform( standard_output.begin(), standard_output.end(), std::back_inserter( standard_output_str ), []( auto c ) { return char( c ); } );
  std::string standard_error_str;
  std::transform( standard_error.begin(), standard_error.end(), std::back_inserter( standard_error_str ), []( auto c ) { return char( c ); } );
  const auto branch_trace = ParseBranchTrace( "./branch", 0u, true );
}
