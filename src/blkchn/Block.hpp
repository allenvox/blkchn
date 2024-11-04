#pragma once

#include "Utils.hpp"

#include <ctime>
#include <string>

struct Block {
  int index;
  std::string data;
  std::string prevHash;
  std::string hash;
  time_t timestamp;

  std::string getSignature() {
    return std::to_string(index) + std::to_string(timestamp) + data + prevHash;
  }

  Block(int idx, const std::string &info, const std::string &previousHash)
      : index(idx), data(info), prevHash(previousHash),
        timestamp(time(nullptr)) {
    hash = calculateHash(getSignature());
  }
};
