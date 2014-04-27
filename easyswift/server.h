#pragma once

#include <queue>

class socket_base
{
public:
    struct message
    {
        message()
            : xml(false) {}

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
            : success(false) {}

        bool success;
        std::string error_message;
    };

public:
    socket_base(boost::asio::io_service& io_service, const std::string& file);

protected:
    boost::asio::io_service& io_service_;
    std::string _socket_file;
};

class server : public socket_base
{
public:
    class server_callback
    {
    public:
        virtual bool onMessage(const message & msg) = 0;
    };

    server(boost::asio::io_service& io_service, const std::string& file, server_callback & callback);

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
    client(boost::asio::io_service& io_service, const std::string& file);

    bool send(const message & msg, unsigned timeout=5000);

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
    boost::asio::deadline_timer deadline_;
    boost::array<char, 1024> data_;
    std::string pending_data_;
    bool _connected;
};
