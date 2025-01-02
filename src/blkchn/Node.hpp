#pragma once

#include <iostream>
#include <map>
#include <string>

class BlockchainNode;

using NodeId = std::string;
using Username = std::string;
using NodesMap = std::map<Username, BlockchainNode>;

class BlockchainNode {
public:
  BlockchainNode(const NodeId &nodeId, int initialBalance)
      : id(nodeId), balance(initialBalance) {}

  NodeId getId() { return id; }
  void setId(const NodeId &nodeId) { id = nodeId; }

  int getBalance() { return balance; }
  void setBalance(const int newBalance) { balance = newBalance; }

  static void printNodesInfo(NodesMap &nodesMap) {
    std::cout << "Node\t\tBalance\t\tUser\n";
    for (auto &elem : nodesMap) {
      Username username = elem.first;
      BlockchainNode node = elem.second;
      std::cout << node.getId() << "\t" << node.getBalance() << "\t\t"
                << username << '\n';
    }
  }

private:
  NodeId id;
  int balance;
};
