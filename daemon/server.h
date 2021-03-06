#pragma once

#include <queue>
#include <boost/function.hpp>

class socket_base
{
public:
    struct message
    {
        message()
            : messageId(0), xml(false) {}

        uint64_t messageId;
        std::string to;
        std::string cc;
        std::string subject;
        std::string body;
        bool xml;
    };
    typedef std::queue<message> message_queue;
    struct response
    {
        response()
            : messageId(0), success(false) {}

        uint64_t messageId;
        bool success;
        std::string error_message;
    };

protected:
    socket_base(boost::asio::io_service& io_service, const std::string& file, bool debug=false);

protected:
    boost::asio::io_service& io_service_;
    std::string _socket_file;
    bool _debug;
};

class server : public socket_base
{
public:
    class server_callback
    {
    public:
        virtual bool onMessage(const message & msg, response & resp) = 0;
    };

    server(boost::asio::io_service& io_service, int socketHandle, server_callback & callback, bool debug=false);
    server(boost::asio::io_service& io_service, const std::string& file, server_callback & callback, bool debug=false);

private:
    class session;
    typedef boost::shared_ptr<session> session_ptr;

    void handle_accept(session_ptr new_session, const boost::system::error_code& error);

private:
    boost::asio::local::stream_protocol::acceptor acceptor_;
    server_callback & _callback;
};

class client : public socket_base
{
public:
    client(boost::asio::io_service& io_service, const std::string& file, bool debug=false);

    bool send(const message & msg, const boost::function<void(client* client)> & completeHandler, unsigned timeout=5000);

private:
    void handle_connect(const boost::system::error_code& err);
    void handle_write(const boost::system::error_code& err);
    void handle_read(const boost::system::error_code& err, size_t bytes_transferred);
    void handle_deadline();

    bool send_next_message();

private:
    boost::asio::local::stream_protocol::socket _socket;
    boost::asio::streambuf response_;
    message_queue _messages;
    message_queue _send_messages;
    boost::asio::deadline_timer deadline_;
    boost::function<void(client* client)> _completeHandler;
    boost::array<char, 1024> data_;
    std::string pending_data_;
    bool _connected;
};
