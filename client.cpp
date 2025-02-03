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
        
        // Read welcome message
        std::cout << readResponse() << '\n';
    }

    void authenticate(const std::string& username, const std::string& password) {
        sendCommand("LOGIN " + username + " " + password);
        std::cout << readResponse();
    }

    std::string sendCommand(const std::string& command) {
        boost::asio::write(socket, boost::asio::buffer(command + "\n"));
        return readResponse();
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

    std::string readResponse() {
        boost::asio::streambuf buf;
        boost::asio::read_until(socket, buf, '>');
        std::istream is(&buf);
        std::string response;
        std::getline(is, response);
        return response;
    }
};

std::string HELP_MSG = "Client Commands   Server Actions\n---------------- ----------------\nISSUE_COINS     → Creates system transaction\nADD_TRANSACTION → Adds to pending pool\nMINE_BLOCK      → Packages transactions into block\n                → Performs mining (SHA-256 PoW)\n                → Updates balances\nGET_CHAIN       → Shows all blocks with hashes\nEXIT\n";

int main() {
    try {
        Client client("127.0.0.1", "12345"); // Connect to the server on localhost:12345
        std::cout << HELP_MSG;

        while (true) {
            std::cout << "> ";
            std::string command;
            std::getline(std::cin, command);

            if (command == "EXIT") {
                break;
            } else if (command == "HELP") {
                std::cout << HELP_MSG;
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
