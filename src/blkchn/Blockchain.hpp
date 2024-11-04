#pragma once

#include "Block.hpp"
#include "Node.hpp"

#include <map>
#include <string>
#include <vector>

const int BLOCKADD_REWARD = 1;

class Blockchain {
public:
  Blockchain() { chain.push_back(createGenesisBlock()); }

  void addBlock(const std::string &data, BlockchainNode &node) {
    Block newBlock(chain.size(), data, chain.back().hash);
    chain.push_back(newBlock);
    node.setBalance(node.getBalance() + BLOCKADD_REWARD);
    std::cout << "new block " << newBlock.hash.substr(0, 16) + "..." << "\tby\t"
              << node.getId() << "\t(reward " << BLOCKADD_REWARD << " coins)\n";
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

  BlockchainNode &
  chooseNodeForBlock(std::map<std::string, BlockchainNode> &nodes) {
    int totalBalance = 0;
    for (auto &[_, node] : nodes) {
      totalBalance += node.getBalance();
    }

    int randomPick = std::rand() % totalBalance;
    int cumulativeBalance = 0;

    for (auto &[_, node] : nodes) {
      cumulativeBalance += node.getBalance();
      if (randomPick < cumulativeBalance) {
        return node;
      }
    }
    throw std::runtime_error("No node selected");
  }

private:
  std::vector<Block> chain;

  Block createGenesisBlock() { return Block(0, "Genesis Block", "0"); }
};
