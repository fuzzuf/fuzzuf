#include <algorithm>
#include <fuzzuf/exceptions.hpp>
#include <fuzzuf/utils/filesystem.hpp>
#include <fuzzuf/utils/vfs/vfs.hpp>
namespace fuzzuf::utils::vfs {

VFS::VFS(std::vector<fs::path> &&allowed_path_) {
  if (allowed_path_.empty()) {
    allowed_path.reset(new std::vector<fs::path>{});
    current_workdir = "/nowhere";
    return;
  }
  std::vector<fs::path> duplicated_allowed_path;
  duplicated_allowed_path.reserve(allowed_path_.size());
  if (!allowed_path_[0].has_root_directory())
    throw exceptions::invalid_argument(
        "First allowed path must contain root directory", __FILE__, __LINE__);
  {
    auto can = allowed_path_[0].lexically_normal();
    current_workdir = can;
  }
  std::transform(allowed_path_.begin(), allowed_path_.end(),
                 std::back_inserter(duplicated_allowed_path),
                 [this](const auto &v) {
                   auto abs = Absolute(v);
                   auto can = abs.lexically_normal();
                   return can;
                 });
  std::sort(duplicated_allowed_path.begin(), duplicated_allowed_path.end());
  allowed_path.reset(new std::vector<fs::path>{});
  allowed_path->push_back(std::move(duplicated_allowed_path[0]));
  current_workdir = (*allowed_path)[0];
  fs::path prev = duplicated_allowed_path[0];
  auto prev_len = std::distance(prev.begin(), prev.end());
  /*
   * Remove duplicated or included paths.
   */
  for (auto cur = std::next(duplicated_allowed_path.begin());
       cur != duplicated_allowed_path.end(); ++cur) {
    auto cur_len = std::distance(cur->begin(), cur->end());
    /*
     * Since the paths are sorted, the path shorter than previous one definitely
     * means no inclusion nor duplication. So the path should be left.
     */
    if (prev_len > cur_len) {
      prev = *cur;
      allowed_path->push_back(std::move(*cur));
      prev_len = std::distance(prev.begin(), prev.end());
    }
    /*
     * If the path doesn't contain previous path as prefix, the path is not
     * included nor duplicated. So the path should be left.
     */
    else if (!std::equal(prev.begin(), prev.end(), cur->begin(),
                         std::next(cur->begin(), prev_len))) {
      prev = *cur;
      allowed_path->push_back(std::move(*cur));
      prev_len = std::distance(prev.begin(), prev.end());
    }
    /*
     * Otherwise, the path is same as or included by previous one.
     * So the path should be discarded.
     */
  }
  /*
   * Although Windows has current directory for each drives, VFS provides *NIX
   * style single current directory. As the result, accepting multiple drives
   * causes confusing result on windows environment. Instead, multiple drives as
   * accessible paths is forbidden in current implementation.
   */
  if (std::find_if(allowed_path->begin(), allowed_path->end(),
                   [rn = (*allowed_path)[0].root_name()](const auto &p) {
                     return p.root_name() != rn;
                   }) != allowed_path->end())
    throw exceptions::invalid_argument("Inconsistent root name", __FILE__,
                                       __LINE__);
}

std::optional<fs::path> VFS::IsAllowedPath(const fs::path &p) const {
  const auto abs = Absolute(p);
  auto requested = abs.lexically_normal();
  const auto ge =
      std::upper_bound(allowed_path->begin(), allowed_path->end(), requested);
  if (ge == allowed_path->begin()) {
    return std::nullopt;
  }
  const auto closest = std::prev(ge);
  const auto closest_len = std::distance(closest->begin(), closest->end());
  const auto requested_len = std::distance(requested.begin(), requested.end());
  if (closest_len > requested_len) {
    return std::nullopt;
  }
  if (!std::equal(closest->begin(), closest->end(), requested.begin(),
                  std::next(requested.begin(), closest_len))) {
    return std::nullopt;
  }
  return requested;
}
fs::path VFS::SanitizePath(const fs::path &p) const {
  auto sanitized = IsAllowedPath(p);
  if (!sanitized)
    throw exceptions::invalid_file("Access to the path is not allowed.",
                                   __FILE__, __LINE__);
  return *sanitized;
}

fs::path VFS::CurrentPath() const { return current_workdir; }
void VFS::CurrentPath(const fs::path &p) { current_workdir = SanitizePath(p); }
fs::path VFS::Absolute(const fs::path &p) const {
  if (p.has_root_directory())
    return p;
  return current_workdir / p;
}
fs::path VFS::Relative(const fs::path &p) const {
  if (p.is_relative())
    return p;
  return p.lexically_relative(current_workdir);
}

} // namespace fuzzuf::utils::vfs
