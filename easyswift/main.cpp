#include <boost/bind.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <Swiften/Swiften.h>

using namespace Swift;

class xmpp_sender
{
public:
    xmpp_sender(const JID& jid, const SafeString& password, NetworkFactories* networkFactories, Storages* storages = NULL);
    virtual ~xmpp_sender();

    bool sendMessage(const std::string & to, const std::string & message);

protected:
    void handleConnected();
    void handleRosterReceived(ErrorPayload::ref error);
    void handlePresenceReceived(Presence::ref presence);
    void handleMessageReceived(Message::ref message);

private:
    Swift::Client *     _client;
};

xmpp_sender::xmpp_sender(const JID& jid, const SafeString& password, NetworkFactories* networkFactories, Storages* storages)
{
    _client = new Swift::Client(jid, password, networkFactories, storages);
    _client->onConnected.connect(boost::bind(&xmpp_sender::handleConnected, this));
    _client->onMessageReceived.connect(boost::bind(&xmpp_sender::handleMessageReceived, this, _1));
    _client->onPresenceReceived.connect(boost::bind(&xmpp_sender::handlePresenceReceived, this, _1));
    _client->setAlwaysTrustCertificates();
    _client->connect();
}

xmpp_sender::~xmpp_sender()
{
    delete _client;
}

void xmpp_sender::handleConnected()
{
    std::cout << "Connected" << std::endl;
    // Request the roster
    GetRosterRequest::ref rosterRequest =
        GetRosterRequest::create(_client->getIQRouter());
    rosterRequest->onResponse.connect( boost::bind(&xmpp_sender::handleRosterReceived, this, _2));
    rosterRequest->send();
}

void xmpp_sender::handleRosterReceived(ErrorPayload::ref error)
{
    if (error) {
        std::cerr << "Error receiving roster. Continuing anyway.";
    }
    // Send initial available presence
    _client->sendPresence(Presence::create("Send me a message"));
}

void xmpp_sender::handleMessageReceived(Message::ref message)
{
    // Echo back the incoming message
    message->setTo(message->getFrom());
    message->setFrom(JID());
    _client->sendMessage(message);
}

void xmpp_sender::handlePresenceReceived(Presence::ref presence) {
    // Automatically approve subscription requests
    if (presence->getType() == Presence::Subscribe) {
        Presence::ref response = Presence::create();
        response->setTo(presence->getFrom());
        response->setType(Presence::Subscribed);
        _client->sendPresence(response);
    }
}

bool xmpp_sender::sendMessage(const std::string & to, const std::string & message)
{
    Message::ref msgobj(new Message);
    // Echo back the incoming message
    msgobj->setTo(to);
    msgobj->setFrom(JID());
    msgobj->setBody(message);

    _client->sendMessage(msgobj);
    return true;
}

class xmpp_target_sender
{
public:
    xmpp_target_sender(xmpp_sender & sender, const std::string & to)
        : _sender(sender)
        , _to(to)
        {}

    bool send(const std::string & message)
    {
        return _sender.sendMessage(_to, message);
    }

private:
    xmpp_sender & _sender;
    std::string _to;
};

using boost::asio::local::stream_protocol;

class session
  : public boost::enable_shared_from_this<session>
{
public:
  session(boost::asio::io_service& io_service, xmpp_target_sender & sender)
    : socket_(io_service), _sender(sender)
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

  void handle_read(const boost::system::error_code& error,
      size_t bytes_transferred)
  {
    if (!error)
    {
      boost::asio::async_write(socket_,
          boost::asio::buffer(data_, bytes_transferred),
          boost::bind(&session::handle_write,
            shared_from_this(),
            boost::asio::placeholders::error));
    }
  }

  void handle_write(const boost::system::error_code& error)
  {
      std::cout << " got message " << data_.c_array() << std::endl;

    if (!error)
    {
        _sender.send(data_.c_array());
      socket_.async_read_some(boost::asio::buffer(data_),
          boost::bind(&session::handle_read,
            shared_from_this(),
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));
    }
  }

private:
  // The socket used to communicate with the client.
  stream_protocol::socket socket_;

  // Buffer used to store data received from the client.
  boost::array<char, 1024> data_;
  xmpp_target_sender & _sender;
};

typedef boost::shared_ptr<session> session_ptr;

class server
{
public:
  server(boost::asio::io_service& io_service, const std::string& file, xmpp_target_sender & sender)
    : io_service_(io_service)
    , acceptor_(io_service, stream_protocol::endpoint(file))
    , _sender(sender)
  {
    session_ptr new_session(new session(io_service_, _sender));
    acceptor_.async_accept(new_session->socket(),
        boost::bind(&server::handle_accept, this, new_session,
          boost::asio::placeholders::error));
  }

  void handle_accept(session_ptr new_session,
      const boost::system::error_code& error)
  {
    if (!error)
    {
      new_session->start();
      new_session.reset(new session(io_service_, _sender));
      acceptor_.async_accept(new_session->socket(),
          boost::bind(&server::handle_accept, this, new_session,
            boost::asio::placeholders::error));
    }
  }

private:
  boost::asio::io_service& io_service_;
  stream_protocol::acceptor acceptor_;
  xmpp_target_sender & _sender;
};

namespace {
    std::string expand_user(const std::string & path)
    {
        std::string ret = path;
        if (!ret.empty() && ret[0] == '~')
        {
            char const* home = getenv("HOME");
            if(!home)
                home = getenv("USERPROFILE");

            if (home)
                ret.replace(0, 1, home);
        }
        return ret;
    }
}

class Config
{
public:
    Config(const std::string & configFile="~/.swifter.conf");
    virtual ~Config();


    const std::string & socketFile() const { return _socket_file; }
    const std::string & xmppJid() const { return _xmpp_jid; }
    const std::string & xmppPassword() const { return _xmpp_password; }
    const std::string & xmppRecipient() const { return _xmpp_recipient; }

private:
    void            load();
private:
    std::string _configFile;

    std::string _socket_file;
    std::string _xmpp_jid;
    std::string _xmpp_recipient;
    std::string _xmpp_password;
};

Config::Config(const std::string & configFile)
{
    _configFile = expand_user(configFile);

    load();
}

Config::~Config()
{
}

void Config::load()
{
    boost::property_tree::ptree pt;
    boost::property_tree::ini_parser::read_ini(_configFile, pt);
    _socket_file = pt.get<std::string>("Socket", "/tmp/swifter.socket");
    _xmpp_jid = pt.get<std::string>("JID");
    _xmpp_recipient = pt.get<std::string>("Recipient");
    _xmpp_password = pt.get<std::string>("Password");
}



int main(int argc, char** argv)
{
    Config config;
    SimpleEventLoop eventLoop;
    BoostNetworkFactories networkFactories(&eventLoop);

    boost::shared_ptr<boost::asio::io_service> io_service = networkFactories.getIOServiceThread()->getIOService();

    xmpp_sender sender(config.xmppJid(), config.xmppPassword(), &networkFactories);
    xmpp_target_sender target_sender(sender, config.xmppRecipient());

    std::remove(config.socketFile().c_str());
    server s(*io_service, config.socketFile(), target_sender);

    eventLoop.run();

    return 0;
}
