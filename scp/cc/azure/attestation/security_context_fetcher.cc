#include "security_context_fetcher.h"

std::vector<uint8_t> fetchSecurityContextFile(std::string file_path) {
  const char* dir = std::getenv("UVM_SECURITY_CONTEXT_DIR");
  if (!dir) {
    throw std::runtime_error(
        "UVM_SECURITY_CONTEXT_DIR environment variable is not set");
  }

  std::string full_path = std::string(dir) + file_path;
  std::ifstream file(full_path, std::ios::binary);

  if (!file) {
    throw std::runtime_error("Unable to open file at full_path: " + full_path);
  }

  return {std::istreambuf_iterator<char>(file),
          std::istreambuf_iterator<char>()};
}