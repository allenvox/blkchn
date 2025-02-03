#include <boost/asio.hpp>
#include <openssl/sha.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

using boost::asio::ip::tcp;

// Структура транзакции
struct Transaction {
    std::string senderAddress;
    std::string receiverAddress;
    double amount;
    std::string signature;
};

// Класс для управления блокчейном
class Blockchain {
private:
    struct Block {
        int index;
        std::vector<Transaction> transactions;
        std::string previousHash;
        std::string hash;
        uint64_t nonce;  // For mining simulation
    };

    std::vector<Block> chain;
    std::vector<Transaction> pendingTransactions;
    std::unordered_map<std::string, double> balances;

    std::string calculateHash(const Block& block) {
        std::string data = std::to_string(block.index) 
            + block.previousHash 
            + std::to_string(block.nonce);
        
        for (const auto& tx : block.transactions) {
            data += tx.senderAddress + tx.receiverAddress 
                  + std::to_string(tx.amount) + tx.signature;
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
        
        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

public:
    Blockchain() {
        // Create genesis block with system transaction
        Block genesis;
        genesis.index = 0;
        genesis.previousHash = "0";
        genesis.nonce = 0;
        
        // System transaction: issue initial coins
        Transaction genesisTx;
        genesisTx.senderAddress = "system";
        genesisTx.receiverAddress = "foundation";
        genesisTx.amount = 1000000;
        genesisTx.signature = "genesis_signature";
        genesis.transactions.push_back(genesisTx);
        
        genesis.hash = calculateHash(genesis);
        chain.push_back(genesis);
        
        // Update balances
        balances["foundation"] = 1000000;
    }

    void addTransaction(const Transaction& tx) {
        if (tx.senderAddress != "system" && getBalance(tx.senderAddress) < tx.amount) {
            throw std::runtime_error("Insufficient balance!");
        }
        pendingTransactions.push_back(tx);
    }

    void mineBlock() {
        Block newBlock;
        newBlock.index = chain.size();
        newBlock.previousHash = chain.back().hash;
        newBlock.transactions = pendingTransactions;
        newBlock.nonce = 0;

        // Simple "mining" simulation (find hash starting with "00")
        do {
            newBlock.nonce++;
            newBlock.hash = calculateHash(newBlock);
        } while (newBlock.hash.substr(0, 2) != "00");

        chain.push_back(newBlock);
        
        // Update balances
        for (const auto& tx : newBlock.transactions) {
            if (tx.senderAddress != "system") {
                balances[tx.senderAddress] -= tx.amount;
            }
            balances[tx.receiverAddress] += tx.amount;
        }
        
        pendingTransactions.clear();
    }

    void addBlock() {
        // Создаем новый блок
        Block newBlock = {
            static_cast<int>(chain.size()), 
            {}, 
            chain.back().hash, 
            ""
        };
        newBlock.hash = calculateHash(newBlock);
        chain.push_back(newBlock);
    }

    void issueCoins(const std::string& address, double amount) {
        balances[address] += amount;
    }

    const std::vector<Block>& getChain() const {
        return chain;
    }

    double getBalance(const std::string& address) const {
        auto it = balances.find(address);
        if (it != balances.end()) {
            return it->second;
        }
        return 0.0;
    }
};

// Сервер для обработки запросов
class AdminServer {
private:
    boost::asio::io_context ioContext;
    tcp::acceptor acceptor;
    Blockchain blockchain;

    void startAccept() {
        auto socket = std::make_shared<tcp::socket>(ioContext);
        acceptor.async_accept(*socket, [this, socket](boost::system::error_code ec) {
            if (!ec) {
                handleClient(socket);
            }
            startAccept();
        });
    }

    void handleClient(std::shared_ptr<tcp::socket> socket) {
        auto buffer = std::make_shared<boost::asio::streambuf>();
        boost::asio::async_read_until(*socket, *buffer, '\n',
            [this, socket, buffer](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    std::istream stream(buffer.get());
                    std::string request;
                    std::getline(stream, request); // Read until newline
                    
                    std::string response = processRequest(request);
                    
                    boost::asio::async_write(*socket, boost::asio::buffer(response),
                        [this, socket](boost::system::error_code ec, std::size_t) {
                            if (!ec) handleClient(socket); // Continue listening
                        });
                }
            });
    }

    std::string processRequest(const std::string& request) {
        std::istringstream iss(request);
        std::string command;
        iss >> command;

        if (command == "MINE_BLOCK") {
            blockchain.mineBlock();
            return "Block mined with " 
                 + std::to_string(blockchain.getChain().back().transactions.size()) 
                 + " transactions\n";
        }
        else if (command == "ADD_TRANSACTION") {
            Transaction tx;
            if (!(iss >> tx.senderAddress >> tx.receiverAddress >> tx.amount >> tx.signature)) {
                return "ERROR: Invalid transaction format\n";
            }
            try {
                blockchain.addTransaction(tx);
                return "Transaction added to pending pool\n";
            } catch (const std::exception& e) {
                return "Error: " + std::string(e.what()) + "\n";
            }
        }
        else if (command == "GET_CHAIN") {
            std::string response;
            for (const auto& block : blockchain.getChain()) {
                response += "Block #" + std::to_string(block.index) 
                          + " Hash: " + block.hash + "\n";
            }
            return response;
        } 
        else if (command == "ISSUE_COINS") {
            std::string address;
            double amount;
            if (!(iss >> address >> amount)) {
                return "ERROR: Invalid format. Use: ISSUE_COINS <address> <amount>\n";
            }
            blockchain.issueCoins(address, amount);
            return "Coins issued successfully.\n";
        } 
        else if (command == "GET_BALANCE") {
            std::string address;
            if (!(iss >> address)) {
                return "ERROR: Invalid format. Use: GET_BALANCE <address>\n";
            }
            double balance = blockchain.getBalance(address);
            return "Balance: " + std::to_string(balance) + "\n";
        }
        return "Unknown command.\n";
    }

public:
    AdminServer(short port) 
        : acceptor(ioContext, tcp::endpoint(tcp::v4(), port)) {}

    void run() {
        startAccept();
        ioContext.run();
    }
};

int main() {
    short port = 12345;
    try {
        AdminServer server(port);
        std::cout << "Admin server is running on port " << port << std::endl;
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
