#include <string>
#include <type_traits>
#include <nlohmann/json.hpp>
#include <fuzzuf/algorithms/eclipser/core/typedef.hpp>
#include <fuzzuf/utils/type_traits/remove_cvr.hpp>

namespace fuzzuf::algorithm::eclipser {

std::ostream &operator<<( std::ostream &stream, Direction src ) {
  if( src == Direction::Stay ) {
    stream << "Stay";
  }
  else if( src == Direction::Left ) {
    stream << "Left";
  }
  else if( src == Direction::Right ) {
    stream << "Right";
  }
  return stream;
}

std::string ToString( Direction src ) {
  if( src == Direction::Stay ) {
    return "Stay";
  }
  else if( src == Direction::Left ) {
    return "Left";
  }
  else if( src == Direction::Right ) {
    return "Right";
  }
  return "Unknown";
}

void to_json( nlohmann::json &dest, const Direction &src ) {
  if( src == Direction::Stay ) {
    dest = "Stay";
  }
  else if( src == Direction::Left ) {
    dest = "Left";
  }
  else if( src == Direction::Right ) {
    dest = "Right";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Direction &dest ) {
  if( src.is_string() ) {
    if( src == "Stay" ) {
      dest = Direction::Stay;
    }
    else if( src == "Left" ) {
      dest = Direction::Left;
    }
    else if( src == "Right" ) {
      dest = Direction::Right;
    }
    else {
      dest = Direction::Right;
    }
  }
  else if( src.is_number() ) {
    dest = Direction( int( src ) );
  }
  else {
    dest = Direction::Right;
  }
}

void to_json( nlohmann::json &dest, const InputSource &src ) {
  dest = std::visit(
    []( const auto &v ) -> nlohmann::json {
      auto root = nlohmann::json::object();
      if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, StdInput > ) {
        root[ "type" ] = "StdInput";
      }
      else if constexpr ( std::is_same_v< utils::type_traits::RemoveCvrT< decltype( v ) >, FileInput > ) {
        root[ "type" ] = "FileInput";
	root[ "filepath" ] = v.filepath;
      }
      else {
        root[ "type" ] = "Unknown";
      }
      return root;
    },
    src
  );
}

void from_json( const nlohmann::json &src, InputSource &dest ) {
  if( !src.is_object() ) dest = StdInput();
  else if( src.find( "type" ) == src.end() ) dest = StdInput();
  else if( ( src[ "type" ] == "FileInput" ) && ( src.find( "filepath" ) != src.end() ) ) {
    dest = FileInput{  src[ "filepath" ]. template get< std::string >() };
  }
  else dest = StdInput();
}

void to_json( nlohmann::json &dest, const CoverageGain &src ) {
  if( src == CoverageGain::NoGain ) {
    dest = "NoGain";
  }
  else if( src == CoverageGain::NewPath ) {
    dest = "NewPath";
  }
  else if( src == CoverageGain::NewEdge ) {
    dest = "NewEdge";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, CoverageGain &dest ) {
  if( src.is_string() ) {
    if( src == "NoGain" ) {
      dest = CoverageGain::NoGain;
    }
    else if( src == "NewPath" ) {
      dest = CoverageGain::NewPath;
    }
    else if( src == "NewEdge" ) {
      dest = CoverageGain::NewEdge;
    }
    else {
      dest = CoverageGain::NoGain;
    }
  }
  else if( src.is_number() ) {
    dest = CoverageGain( int( src ) );
  }
  else {
    dest = CoverageGain::NoGain;
  }
}

std::string to_string( Tracer src ) {
  if( src == Tracer::Coverage ) {
    return "Coverage";
  }
  else if( src == Tracer::Branch ) {
    return "Branch";
  }
  else if( src == Tracer::BBCount ) {
    return "BBCount";
  }
  else {
    return "Unknown";
  }
}

void to_json( nlohmann::json &dest, const Tracer &src ) {
  if( src == Tracer::Coverage ) {
    dest = "Coverage";
  }
  else if( src == Tracer::Branch ) {
    dest = "Branch";
  }
  else if( src == Tracer::BBCount ) {
    dest = "BBCount";
  }
  else {
    dest = int( src );
  }
}
void from_json( const nlohmann::json &src, Tracer &dest ) {
  if( src.is_string() ) {
    if( src == "Coverage" ) {
      dest = Tracer::Coverage;
    }
    else if( src == "Branch" ) {
      dest = Tracer::Branch;
    }
    else if( src == "BBCount" ) {
      dest = Tracer::BBCount;
    }
    else {
      dest = Tracer::Coverage;
    }
  }
  else if( src.is_number() ) {
    dest = Tracer( int( src ) );
  }
  else {
    dest = Tracer::Coverage;
  }
}

void to_json( nlohmann::json &dest, const Priority &src ) {
  if( src == Priority::Favored ) {
    dest = "Favored";
  }
  else if( src == Priority::Normal ) {
    dest = "Normal";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Priority &dest ) {
  if( src.is_string() ) {
    if( src == "Favored" ) {
      dest = Priority::Favored;
    }
    else if( src == "Normal" ) {
      dest = Priority::Normal;
    }
    else {
      dest = Priority::Favored;
    }
  }
  else if( src.is_number() ) {
    dest = Priority( int( src ) );
  }
  else {
    dest = Priority::Favored;
  }
}

namespace priority {

std::optional< Priority > OfCoverageGain( CoverageGain v ) {
  if( v == CoverageGain::NoGain ) {
    return std::nullopt;
  }
  else if( v == CoverageGain::NewPath ) {
    return Priority::Normal;
  }
  else if( v == CoverageGain::NewEdge ) {
    return Priority::Favored;
  }
  return std::nullopt;
}

}

void to_json( nlohmann::json &dest, const Arch &src ) {
  if( src == Arch::X86 ) {
    dest = "X86";
  }
  else if( src == Arch::X64 ) {
    dest = "X64";
  }
  else {
    dest = int( src );
  }
}
void from_json( const nlohmann::json &src, Arch &dest ) {
  if( src.is_string() ) {
    if( src == "X86" ) {
      dest = Arch::X86;
    }
    else if( src == "X64" ) {
      dest = Arch::X64;
    }
    else {
      dest = Arch::X86;
    }
  }
  else if( src.is_number() ) {
    dest = Arch( int( src ) );
  }
  else {
    dest = Arch::X86;
  }
}

void to_json( nlohmann::json &dest, const Signal &src ) {
  if( src == Signal::ERROR ) {
    dest = "ERROR";
  }
  else if( src == Signal::NORMAL ) {
    dest = "NORMAL";
  }
  else if( src == Signal::SIGILL ) {
    dest = "SIGILL";
  }
  else if( src == Signal::SIGABRT ) {
    dest = "SIGABRT";
  }
  else if( src == Signal::SIGFPE ) {
    dest = "SIGFPE";
  }
  else if( src == Signal::SIGSEGV ) {
    dest = "SIGSEGV";
  }
  else if( src == Signal::SIGALRM ) {
    dest = "SIGALRM";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Signal &dest ) {
  if( src.is_string() ) {
    if( src == "ERROR" ) {
      dest = Signal::ERROR;
    }
    else if( src == "NORMAL" ) {
      dest = Signal::NORMAL;
    }
    else if( src == "SIGILL" ) {
      dest = Signal::SIGILL;
    }
    else if( src == "SIGABRT" ) {
      dest = Signal::SIGABRT;
    }
    else if( src == "SIGFPE" ) {
      dest = Signal::SIGFPE;
    }
    else if( src == "SIGSEGV" ) {
      dest = Signal::SIGSEGV;
    }
    else if( src == "SIGALRM" ) {
      dest = Signal::SIGALRM;
    }
    else {
      dest = Signal::ERROR;
    }
  }
  else if( src.is_number() ) {
    dest = Signal( int( src ) );
  }
  else {
    dest = Signal::ERROR;
  }
}

void to_json( nlohmann::json &dest, const Signedness &src ) {
  if( src == Signedness::Signed ) {
    dest = "Signed";
  }
  else if( src == Signedness::Unsigned ) {
    dest = "Unsigned";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Signedness &dest ) {
  if( src.is_string() ) {
    if( src == "Signed" ) {
      dest = Signedness::Signed;
    }
    else if( src == "Unsigned" ) {
      dest = Signedness::Unsigned;
    }
    else {
      dest = Signedness::Signed;
    }
  }
  else if( src.is_number() ) {
    dest = Signedness( int( src ) );
  }
  else {
    dest = Signedness::Signed;
  }
}

void to_json( nlohmann::json &dest, const Sign &src ) {
  if( src == Sign::Positive ) {
    dest = "Positive";
  }
  else if( src == Sign::Negative ) {
    dest = "Negative";
  }
  else if( src == Sign::Zero ) {
    dest = "Zero";
  }
  else {
    dest = int( src );
  }
}

void from_json( const nlohmann::json &src, Sign &dest ) {
  if( src.is_string() ) {
    if( src == "Positive" ) {
      dest = Sign::Positive;
    }
    else if( src == "Negative" ) {
      dest = Sign::Negative;
    }
    else if( src == "Zero" ) {
      dest = Sign::Zero;
    }
    else {
      dest = Sign::Positive;
    }
  }
  else if( src.is_number() ) {
    dest = Sign( int( src ) );
  }
  else {
    dest = Sign::Positive;
  }
}

namespace signal {

bool IsCrash( Signal signal ) {
  if(
    signal == Signal::SIGSEGV ||
    signal == Signal::SIGILL ||
    signal == Signal::SIGABRT
  ) {
    return true;
  }
  else {
    return false;
  }
}
bool IsSegfault( Signal signal ) {
  return signal == Signal::SIGSEGV;
}
bool IsIllegal( Signal signal ) {
  return signal == Signal::SIGILL;
}
bool IsFPE( Signal signal ) {
  return signal == Signal::SIGFPE;
}
bool IsAbort( Signal signal ) {
  return signal == Signal::SIGABRT;
}
bool IsTimeout( Signal signal ) {
  return signal == Signal::SIGALRM;
}

}

}

