#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "server.h"

using boost::asio::local::stream_protocol;

#pragma pack(1)
struct unix_socket_package_header
{
    uint32_t    magic;
    uint32_t    length_;

    unix_socket_package_header()
        : magic(0x87633bba), length_(0)
    {}
    bool isValid() const {
        return (magic == 0x87633bba);
    }
    size_t length() const {
        return ntohl(length_);
    }
    void setLength(size_t len) {
        length_ = htonl(len);
    }
};
#pragma pack()

std::ostream& operator <<(std::ostream& stream, const unix_socket_package_header& header)
{
    stream.write((const char*)&header, sizeof(header));
    return stream;
}

void write_message(const socket_base::message & msg, boost::asio::streambuf & buf)
{
    boost::property_tree::ptree pt;
    pt.put("messageid", msg.messageId);
    pt.put("xml", msg.xml);
    if(!msg.to.empty())
        pt.put("to", msg.to);
    if(!msg.cc.empty())
        pt.put("cc", msg.cc);
    if(!msg.subject.empty())
        pt.put("subject", msg.subject);
    if(!msg.body.empty())
        pt.put("body", msg.body);

    std::ostringstream os;
    boost::property_tree::write_json (os, pt, false);
    std::string json = os.str(); // {"foo":"bar"}

    unix_socket_package_header header;
    header.setLength(json.length());

    std::ostream bufstream(&buf);
    bufstream << header;
    bufstream << json;
}

void read_message(socket_base::message & msg, const std::string & buf)
{
    // Read json.
    boost::property_tree::ptree pt;

    std::istringstream json_message_stream (buf);
    boost::property_tree::read_json (json_message_stream, pt);
    msg.messageId = pt.get<uint64_t>("messageid", 0u);
    msg.body = pt.get<std::string>("body", std::string());
    msg.subject = pt.get<std::string>("subject", std::string());
    msg.to = pt.get<std::string>("to", std::string());
    msg.cc = pt.get<std::string>("cc", std::string());
    msg.xml = pt.get<bool>("xml", false);

}

void write_response(const socket_base::response & response, boost::asio::streambuf & buf)
{
    boost::property_tree::ptree pt;
    pt.put("messageid", response.messageId);
    pt.put("success", response.success);
    pt.put("message", response.error_message);

    std::ostringstream os;
    boost::property_tree::write_json (os, pt, false);
    std::string json = os.str(); // {"foo":"bar"}

    unix_socket_package_header header;
    header.setLength(json.length());

    std::ostream bufstream(&buf);
    bufstream << header;
    bufstream << json;
}

void read_response(socket_base::response & response, const std::string & buf)
{
    // Read json.
    boost::property_tree::ptree pt;

    std::istringstream json_message_stream (buf);
    boost::property_tree::read_json (json_message_stream, pt);
    response.messageId = pt.get<uint64_t>("messageid", 0u);
    response.error_message = pt.get<std::string>("message", std::string());
    response.success = pt.get<bool>("success", false);

}

class server::session : public boost::enable_shared_from_this<session>
{
public:
    session(boost::asio::io_service& io_service, server_callback & callback, bool debug)
        : socket_(io_service), _callback(callback), _debug(debug)
    {
    }

    stream_protocol::socket& socket()
    {
        return socket_;
    }

    void start()
    {
        socket_.async_read_some(boost::asio::buffer(data_),
                                boost::bind(&session::handle_read,
                                            shared_from_this(),
                                            boost::asio::placeholders::error,
                                            boost::asio::placeholders::bytes_transferred));
    }

    void handle_read(const boost::system::error_code& error, size_t bytes_transferred)
    {
        if (!error)
        {
            pending_data_.append(data_.data(), bytes_transferred);
            const unix_socket_package_header * current_header = (const unix_socket_package_header *)pending_data_.data();
            while(current_header && current_header->isValid() && pending_data_.length() >= current_header->length() + sizeof(unix_socket_package_header))
            {
                message msg;
                std::string json_message(pending_data_.data() + sizeof(unix_socket_package_header), current_header->length());
                read_message(msg, json_message);

                // goto to next message
                pending_data_ = pending_data_.substr(current_header->length() + sizeof(unix_socket_package_header));
                if(!pending_data_.empty())
                    current_header = (const unix_socket_package_header *)pending_data_.data();
                else
                    current_header = NULL;

                if(_debug)
                    std::cout << "got message id=" << msg.messageId << " to=" << msg.to << " cc=" << msg.cc << " xml=" << msg.xml << " sub=" << msg.subject << " body=" << msg.body << std::endl;

                response resp;
                resp.messageId = msg.messageId;
                bool success = _callback.onMessage(msg, resp);

                if(_debug)
                    std::cout << "send response id=" << resp.messageId << " success=" << resp.success << std::endl;

                boost::asio::streambuf buf;
                write_response(resp, buf);

                // The connection was successful. Send the request.
                boost::asio::async_write(socket_, buf,
                                    boost::bind(&session::handle_write,
                                    shared_from_this(),
                                    boost::asio::placeholders::error,
                                    boost::asio::placeholders::bytes_transferred));
            }
        }
    }

    void handle_write(const boost::system::error_code& error, size_t bytes_transferred)
    {
        if(_debug)
            std::cout << " handle_write " << error << " bytes=" << bytes_transferred << std::endl;
        // re-start read
        socket_.async_read_some(boost::asio::buffer(data_),
                                boost::bind(&session::handle_read,
                                            shared_from_this(),
                                            boost::asio::placeholders::error,
                                            boost::asio::placeholders::bytes_transferred));
    }

private:
    // The socket used to communicate with the client.
    stream_protocol::socket socket_;

    // Buffer used to store data received from the client.
    std::string pending_data_;
    boost::array<char, 1024> data_;
    server_callback & _callback;
    bool _debug;
};

socket_base::socket_base(boost::asio::io_service& io_service, const std::string& file, bool debug)
    : io_service_(io_service)
    , _socket_file(file)
    , _debug(debug)
{

}

server::server(boost::asio::io_service& io_service, const std::string& file, server_callback & callback, bool debug)
    : socket_base(io_service, file, debug)
    , acceptor_(io_service, stream_protocol::endpoint(file))
    , _callback(callback)
{
    ::chmod(file.c_str(), 0777);
    session_ptr new_session(new session(io_service_, _callback, _debug));
    acceptor_.async_accept(new_session->socket(),
                           boost::bind(&server::handle_accept, this, new_session,
                                       boost::asio::placeholders::error));
}

void server::handle_accept(session_ptr new_session, const boost::system::error_code& error)
{
    if (!error)
    {
        new_session->start();
        new_session.reset(new session(io_service_, _callback, _debug));
        acceptor_.async_accept(new_session->socket(),
                               boost::bind(&server::handle_accept, this, new_session,
                                           boost::asio::placeholders::error));
    }
}


client::client(boost::asio::io_service& io_service, const std::string& file, bool debug)
    : socket_base(io_service, file, debug)
    , _socket(io_service)
    , deadline_(io_service)
    , _connected(false)
{
    stream_protocol::endpoint ep(_socket_file);
    // Attempt a connection to each endpoint in the list until we
    // successfully establish a connection.
    _socket.async_connect(ep, boost::bind(&client::handle_connect, this,
                                          boost::asio::placeholders::error));

    // Start the deadline actor. You will note that we're not setting any
    // particular deadline here. Instead, the connect and input actors will
    // update the deadline prior to each asynchronous operation.
    deadline_.async_wait(boost::bind(&client::handle_deadline, this));
}

bool client::send_next_message()
{
    bool ret = false;
    if(!_messages.empty())
    {
        message msg = _messages.front();
        _messages.pop();

        boost::asio::streambuf buf;
        write_message(msg, buf);

        _send_messages.push(msg);

        if(_debug)
            std::cout << "send next message id=" << msg.messageId << std::endl;

        // The connection was successful. Send the request.
        boost::asio::async_write(_socket, buf,
                                 boost::bind(&client::handle_write, this,
                                             boost::asio::placeholders::error));

        ret = true;
    }
    else
    {
        if(_debug)
            std::cout << "no more messages\n";
    }
    return ret;
}


void client::handle_connect(const boost::system::error_code& err)
{
    if (!err)
    {
        _connected = true;
        if(_debug)
            std::cout << "client connected\n";

        _socket.async_read_some(boost::asio::buffer(data_),
                                boost::bind(&client::handle_read,
                                            this,
                                            boost::asio::placeholders::error,
                                            boost::asio::placeholders::bytes_transferred));

        send_next_message();;
    }
    else
    {
        std::cerr << "Connect to " << _socket_file << " error: " << err.message() << std::endl;

        _socket.close();

        // There is no longer an active deadline. The expiry is set to positive
        // infinity so that the actor takes no action until a new deadline is set.
        deadline_.expires_at(boost::posix_time::pos_infin);

        _completeHandler(this);
    }
}

void client::handle_read(const boost::system::error_code& err, size_t bytes_transferred)
{
    if(_debug)
        std::cout << "handle_read " << err << "\n";

    pending_data_.append(data_.data(), bytes_transferred);
    const unix_socket_package_header * current_header = (const unix_socket_package_header *)pending_data_.data();
    while(current_header && current_header->isValid() && pending_data_.length() >= current_header->length() + sizeof(unix_socket_package_header))
    {
        response resp;
        std::string json_message(pending_data_.data() + sizeof(unix_socket_package_header), current_header->length());
        read_response(resp, json_message);

        // goto to next message
        pending_data_ = pending_data_.substr(current_header->length() + sizeof(unix_socket_package_header));
        if(!pending_data_.empty())
            current_header = (const unix_socket_package_header *)pending_data_.data();
        else
            current_header = NULL;

        message first_sent_msg = _send_messages.front();
        _send_messages.pop();

        if(first_sent_msg.messageId == resp.messageId)
        {
            if(_debug)
                std::cout << "response id=" << resp.messageId << " success=" << resp.success << " msg=" << resp.error_message << "\n";
        }
    }

    if(_messages.empty() && _send_messages.empty())
    {
        if(_debug)
            std::cout << "All messages sent" << std::endl;
        // The deadline has passed. The socket is closed so that any outstanding
        // asynchronous operations are cancelled.
        _completeHandler(this);
    }
}

void client::handle_write(const boost::system::error_code& err)
{
    if (!err)
    {
        if(_debug)
            std::cout << "handle_write\n";
        if(!send_next_message())
        {
            if(_debug)
                std::cout << "handle_write no more messages\n";
        }
    }
    else
    {
        if(_debug)
            std::cout << "handle_write Error: " << err.message() << "\n";
    }
}

void client::handle_deadline()
{
    // Check whether the deadline has passed. We compare the deadline against
    // the current time since a new asynchronous operation may have moved the
    // deadline before this actor had a chance to run.
    if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now())
    {
        // The deadline has passed. The socket is closed so that any outstanding
        // asynchronous operations are cancelled.
        _socket.close();

        // There is no longer an active deadline. The expiry is set to positive
        // infinity so that the actor takes no action until a new deadline is set.
        deadline_.expires_at(boost::posix_time::pos_infin);

        _completeHandler(this);
    }

    // Put the actor back to sleep.
    deadline_.async_wait(boost::bind(&client::handle_deadline, this));
}

bool client::send(const message & msg, const boost::function<void(client* client)> & completeHandler, unsigned timeout)
{
    bool was_empty = _messages.empty();
    _completeHandler = completeHandler;
    _messages.push(msg);
    if(was_empty && _connected)
        send_next_message();
    // Set a deadline for the connect operation.
    deadline_.expires_from_now(boost::posix_time::milliseconds(timeout));

    return true;
}
