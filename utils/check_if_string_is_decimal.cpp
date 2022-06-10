#include "fuzzuf/utils/check_if_string_is_decimal.hpp"
namespace fuzzuf::utils {
bool CheckIfStringIsDecimal(std::string &str) {
  if (str.find_first_not_of("0123456789") != std::string::npos) {
    return false;
  }
  return true;
}

bool CheckIfStringIsDecimal(const char *cstr) {
  std::string str(cstr);
  return CheckIfStringIsDecimal(str);
}
}  // namespace fuzzuf::utils
