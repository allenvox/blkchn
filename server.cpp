#include <boost/asio.hpp>
#include <openssl/sha.h>

#include <iomanip>
#include <iostream>
#include <mutex>
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

    std::unordered_map<std::string, double> getBalances() const {
        return balances;
    }
};

// ================== Authentication System ==================
class UserManager {
private:
    struct User {
        std::string password_hash;
        bool is_admin;
    };

    std::unordered_map<std::string, User> users;
    std::mutex users_mutex;

    std::string hashPassword(const std::string& password) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), 
              password.length(), digest);
        
        std::stringstream ss;
        for(int i=0; i<SHA256_DIGEST_LENGTH; i++)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        return ss.str();
    }

public:
    UserManager() {
        // Add admin user (username, password, is_admin)
        addUser("admin", "1234", true);
    }

    bool addUser(const std::string& username, const std::string& password, bool is_admin=false) {
        std::lock_guard<std::mutex> lock(users_mutex);
        if(users.count(username)) return false;
        
        users[username] = {
            hashPassword(password),
            is_admin
        };
        return true;
    }

    std::pair<bool, bool> authenticate(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(users_mutex);
        auto it = users.find(username);
        if(it == users.end()) return {false, false};
        
        if(it->second.password_hash == hashPassword(password))
            return {true, it->second.is_admin};
        return {false, false};
    }
};

// ================== Modified Session Class ==================
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, Blockchain& blockchain, UserManager& auth)
        : socket_(std::move(socket)), 
          blockchain_(blockchain),
          auth_(auth),
          authenticated_(false),
          is_admin_(false) {}

    void start() {
        sendPrompt("Please login with: LOGIN <username> <password>\n");
        readCommand();
    }

private:
    tcp::socket socket_;
    Blockchain& blockchain_;
    UserManager& auth_;
    bool authenticated_;
    bool is_admin_;
    boost::asio::streambuf buffer_;

    void readCommand() {
        auto self(shared_from_this());
        boost::asio::async_read_until(socket_, buffer_, '\n',
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    std::istream is(&buffer_);
                    std::string command;
                    std::getline(is, command);
                    processCommand(command);
                    readCommand();
                }
            });
    }

    void processCommand(const std::string& command) {
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;

        std::string response;

        if (!authenticated_) {
            if (cmd == "LOGIN") {
                std::string username, password;
                if (iss >> username >> password) {
                    auto [success, is_admin] = auth_.authenticate(username, password);
                    if(success) {
                        authenticated_ = true;
                        is_admin_ = is_admin;
                        response = "Authentication successful. Role: " + 
                                  std::string(is_admin ? "admin" : "user") + "\n";
                    } else {
                        response = "Invalid credentials\n";
                    }
                } else {
                    response = "Usage: LOGIN <username> <password>\n";
                }
            } else {
                response = "You must login first\n";
            }
        } else {
            if (cmd == "ISSUE_COINS" && is_admin_) {
                std::string address;
                double amount;
                if (!(iss >> address >> amount)) {
                    response = "ERROR: Invalid format. Use: ISSUE_COINS <address> <amount>\n";
                }
                blockchain_.issueCoins(address, amount);
                response = "Coins issued successfully.\n";
            }
            else if (cmd == "ADD_TRANSACTION") {
                Transaction tx;
                if (!(iss >> tx.senderAddress >> tx.receiverAddress >> tx.amount >> tx.signature)) {
                    response = "ERROR: Invalid transaction format\n";
                }
                try {
                    blockchain_.addTransaction(tx);
                    response = "Transaction added to pending pool\n";
                } catch (const std::exception& e) {
                    response = "Error: " + std::string(e.what()) + "\n";
                }
            }
            else if (cmd == "MINE_BLOCK") {
                blockchain_.mineBlock();
                response = "Block mined with " 
                    + std::to_string(blockchain_.getChain().back().transactions.size()) 
                    + " transactions\n";
            }
            else if (command == "GET_CHAIN") {
                for (const auto& block : blockchain_.getChain()) {
                    response += "Block #" + std::to_string(block.index) 
                             + " Hash: " + block.hash + "\n";
                }
            } 
            else if (command == "GET_BALANCE") {
                std::string address;
                if (!(iss >> address)) {
                    response = "ERROR: Invalid format. Use: GET_BALANCE <address>\n";
                }
                double balance = blockchain_.getBalance(address);
                response = "Balance: " + std::to_string(balance) + "\n";
            }
            else if (cmd == "ADD_USER" && is_admin_) {
                std::string username, password;
                if (iss >> username >> password) {
                    if(auth_.addUser(username, password)) {
                        response = "User added successfully\n";
                    } else {
                        response = "Username already exists\n";
                    }
                }
            }
            else if (cmd == "VIEW_ALL_BALANCES" && is_admin_) {
                response = "All balances:\n";
                for (const auto& [address, balance] : blockchain_.getBalances()) {
                    response += address + ": " + std::to_string(balance) + "\n";
                }
            }
            else {
                response = "Unknown command\n";
            }
        }

        sendResponse(response);
    }

    void sendResponse(const std::string& response) {
        auto self(shared_from_this());
        boost::asio::async_write(socket_, boost::asio::buffer(response + "> "),
            [](boost::system::error_code, std::size_t) {});
    }

    void sendPrompt(const std::string& prompt) {
        auto self(shared_from_this());
        boost::asio::async_write(socket_, boost::asio::buffer(prompt),
            [](boost::system::error_code, std::size_t) {});
    }
};

// ================== Modified AdminServer ==================
class AdminServer {
private:
    boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    Blockchain blockchain_;
    UserManager auth_manager_;

    void startAccept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket), 
                                            blockchain_, 
                                            auth_manager_)->start();
                }
                startAccept();
            });
    }

public:
    AdminServer(boost::asio::io_context& io_context, short port)
        : io_context_(io_context),
          acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        startAccept();
    }
};

int main() {
    short port = 12345;
    try {
        boost::asio::io_context io_context;
        AdminServer server(io_context, port);
        std::cout << "Admin server is running on port " << port << std::endl;
        io_context.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
