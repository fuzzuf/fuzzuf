#include "fuzzuf/utils/get_external_seeds.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#if __GNUC__ >= 8
#include <charconv>
#else
#include <boost/spirit/include/qi.hpp>
#endif
#include <cstdint>
#include <fstream>
#include <vector>

#include "fuzzuf/utils/mmap_range.hpp"
#include "fuzzuf/utils/shared_range.hpp"

namespace fuzzuf::utils {
range::mmap_range<range::shared_range<std::vector<fs::path>>> GetExternalSeeds(
    const fs::path &sync_dir, const std::string &sync_id, bool update_synced) {
  constexpr std::string_view CASE_PREFIX("id:");
  std::shared_ptr<std::vector<fs::path>> new_seeds(new std::vector<fs::path>());
  const auto synced_dir = sync_dir / sync_id / ".synced";
  if (!fs::exists(synced_dir)) {
    fs::create_directories(synced_dir);
  }
  for (const auto &instance : fs::directory_iterator(sync_dir)) {
    const auto &instance_path = instance.path();
    if (instance_path.filename().string() != sync_id) {
      const auto queue_path = instance_path / "queue";
      if (fs::exists(queue_path) && fs::is_directory(queue_path)) {
        const auto id_file_path = synced_dir / instance_path.filename();
        std::uint32_t min_id = 0u;
        std::uint32_t max_id = 0u;
        std::fstream id_file;
        if (fs::exists(id_file_path) && fs::is_regular_file(id_file_path) &&
            fs::file_size(id_file_path) == 4u) {
          if (update_synced) {
            id_file =
                std::fstream(id_file_path.string(),
                             std::ios::in | std::ios::out | std::ios::binary);
          } else {
            id_file = std::fstream(id_file_path.string(),
                                   std::ios::in | std::ios::binary);
          }
          id_file.read(reinterpret_cast<char *>(&min_id), sizeof(min_id));
          max_id = min_id;
        } else {
          if (update_synced) {
            if (fs::exists(id_file_path)) {
              fs::remove_all(id_file_path);
            }
            id_file = std::fstream(id_file_path.string(),
                                   std::ios::out | std::ios::binary);
          }
        }
        for (const auto &seed : fs::directory_iterator(queue_path)) {
          const auto filename = seed.path().filename().string();
          if (filename.size() >= CASE_PREFIX.size() + 6) {
            if (std::string_view(filename.c_str(), 3) == CASE_PREFIX) {
              std::uint32_t id = 0u;
#if __GNUC__ >= 8
              const auto [last, e] =
                  std::from_chars(std::next(filename.c_str(), 3),
                                  std::next(filename.c_str(), 9), id, 10);
              if (e == std::errc{} && last == std::next(filename.c_str(), 9)) {
                if (id > min_id) {
                  new_seeds->push_back(seed.path());
                  max_id = std::max(max_id, id);
                }
              }
#else
              namespace qi = boost::spirit::qi;
              auto iter = std::next(filename.c_str(), 3);
              const auto end = std::next(filename.c_str(), 9);
              if (qi::parse(iter, end, qi::uint_, id) && iter == end) {
                if (id > min_id) {
                  new_seeds->push_back(seed.path());
                  max_id = std::max(max_id, id);
                }
              }
#endif
            }
          }
        }
        if (update_synced) {
          id_file.seekg(0, std::ios::beg);
          id_file.write(reinterpret_cast<char *>(&max_id), sizeof(max_id));
        }
      }
    }
  }
  return new_seeds | range::adaptor::shared |
         range::adaptor::mmap(O_RDONLY, true);
}

}  // namespace fuzzuf::utils
