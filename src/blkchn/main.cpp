#include <openssl/sha.h>

#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

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

class Blockchain {
public:
  Blockchain() { chain.push_back(createGenesisBlock()); }

  void addBlock(const std::string &data) {
    Block newBlock(chain.size(), data, chain.back().hash);
    chain.push_back(newBlock);
  }

  bool isChainValid() {
    for (size_t i = 1; i < chain.size(); ++i) {
      auto result = calculateHash(chain[i].getSignature());
      auto expected = chain[i].hash;
      if (expected != result) {
        return false;
      }
    }
    return true;
  }

  void printChain() const {
    for (const auto &block : chain) {
      std::cout << "Index: " << block.index
                << ", Timestamp: " << block.timestamp
                << "\nData: " << block.data << "\nHash: " << block.hash
                << "\nPrevious Hash: " << block.prevHash
                << "\n----------------\n";
    }
  }

private:
  std::vector<Block> chain;

  Block createGenesisBlock() { return Block(0, "Genesis Block", "0"); }
};

int main() {
  Blockchain myBlockchain;

  myBlockchain.addBlock("Alexei paid Yuriy $50");
  myBlockchain.addBlock("Yuriy paid Mikhail $30");

  std::cout << "Blockchain is " << (myBlockchain.isChainValid() ? "" : " not ")
            << "valid\n";

  std::cout << "\nThe blockchain is:\n----------------\n";
  myBlockchain.printChain();

  return 0;
}
