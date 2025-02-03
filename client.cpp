#include <boost/asio.hpp>
#include <iostream>
#include <string>

using boost::asio::ip::tcp;

class Client {
public:
    Client(const std::string& host, const std::string& port)
        : ioContext(), socket(ioContext) {
        tcp::resolver resolver(ioContext);
        boost::asio::connect(socket, resolver.resolve(host, port));
    }

    std::string sendRequest(const std::string& request) {
        boost::asio::write(socket, boost::asio::buffer(request + "\n"));

        boost::asio::streambuf response_buf;
        boost::asio::read_until(socket, response_buf, '\n');
        
        std::istream response_stream(&response_buf);
        std::string response;
        std::getline(response_stream, response);
        
        return response;
    }

private:
    boost::asio::io_context ioContext;
    tcp::socket socket;
};

int main() {
    try {
        Client client("127.0.0.1", "12345"); // Connect to the server on localhost:12345

        while (true) {
            std::cout << "Enter command (HELP for help) or EXIT: ";
            std::string command;
            std::getline(std::cin, command);

            if (command == "EXIT") {
                break;
            } else if (command == "HELP") {
                std::cout << "Client Commands   Server Actions\n"
                             "---------------- ----------------\n"
                             "ISSUE_COINS     → Creates system transaction\n"
                             "ADD_TRANSACTION → Adds to pending pool\n"
                             "MINE_BLOCK      → Packages transactions into block\n"
                             "                → Performs mining (SHA-256 PoW)\n"
                             "                → Updates balances\n"
                             "GET_CHAIN       → Shows all blocks with hashes\n";
                continue;
            }

            std::string response = client.sendRequest(command);
            std::cout << "Server response: " << response << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
