#include "Blockchain.hpp"
#include "Node.hpp"

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <vector>

int main() {
  std::srand(std::time(NULL));

  NodesMap nodes = {{"Yuriy", BlockchainNode("intel560", 10)},
                    {"Mikhail", BlockchainNode("macbookpro", 20)},
                    {"Nikolay", BlockchainNode("thinkpad", 70)}};
  std::vector<std::string> blocksData = {"Yuriy paid Mikhail 50 coins",
                                         "Mikhail paid Nikolay 30 coins"};

  Blockchain myBlockchain;
  for (const auto &block : blocksData) {
    myBlockchain.addBlock(block, myBlockchain.chooseNodeForBlock(nodes));
  }

  std::cout << "Blockchain is " << (myBlockchain.isChainValid() ? "" : " not ")
            << "valid\n";

  std::cout << "\nThe blockchain is:\n----------------\n";
  myBlockchain.printChain();

  std::cout << "\nThe users are:\n";
  BlockchainNode::printNodesInfo(nodes);

  return 0;
}
