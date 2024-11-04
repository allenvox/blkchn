#pragma once

#include <openssl/sha.h>

#include <iostream>
#include <sstream>

std::string calculateHash(const std::string &data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char *>(data.c_str()), data.size(),
         hash);

  std::stringstream ss;
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    ss << std::hex << (int)hash[i];
  }

  return ss.str();
}
