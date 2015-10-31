#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <boost/bind.hpp>

#include <Swiften/Client/Client.h>
#include <Swiften/Client/ClientOptions.h>
#include <Swiften/Elements/Presence.h>
#include <Swiften/Roster/GetRosterRequest.h>
#include <Swiften/Parser/GenericPayloadParserFactory.h>
#include <Swiften/Network/NetworkFactories.h>
#include <Swiften/Network/TimerFactory.h>

#include "xmpp_agent.h"
#include "xhtml_payload.h"
#include "daemon_config.h"
#include "arsoft-xmpp-daemon-version.h"

#undef AGENT_DEBUG_COMMANDS

using namespace Swift;

class xmpp_agent::Callbacks
{
public:
    Callbacks(xmpp_agent * owner, const std::string & statusMessage)
        : _owner(owner)
        , _statusMessage(statusMessage)
        {
            _owner->_client->onConnected.connect(boost::bind(&xmpp_agent::Callbacks::handleConnected, this));
            _owner->_client->onDisconnected.connect(boost::bind(&xmpp_agent::Callbacks::handleDisconnected, this, _1));
            _owner->_client->onMessageReceived.connect(boost::bind(&xmpp_agent::Callbacks::handleMessageReceived, this, _1));
            _owner->_client->onPresenceReceived.connect(boost::bind(&xmpp_agent::Callbacks::handlePresenceReceived, this, _1));
        }

    void handleConnected()
    {
        std::cout << "Connected as " << _owner->_client->getJID() << " encryption=" << _owner->_client->isStreamEncrypted() << std::endl;
        // Request the roster
        GetRosterRequest::ref rosterRequest = GetRosterRequest::create(_owner->_client->getIQRouter());
        rosterRequest->onResponse.connect( boost::bind(&xmpp_agent::Callbacks::handleRosterReceived, this, _2));
        rosterRequest->send();
    }
    void handleDisconnected(const boost::optional<Swift::ClientError> &error)
    {
        std::string message;
        bool reconnect = false;
        if (error) {
            switch(error->getType()) {
                case Swift::ClientError::UnknownError: message = ("Unknown Error"); reconnect = true; break;
                case Swift::ClientError::DomainNameResolveError: message = ("Unable to find server"); break;
                case Swift::ClientError::ConnectionError: message = ("Error connecting to server"); break;
                case Swift::ClientError::ConnectionReadError: message = ("Error while receiving server data"); reconnect = true; break;
                case Swift::ClientError::ConnectionWriteError: message = ("Error while sending data to the server"); reconnect = true; break;
                case Swift::ClientError::XMLError: message = ("Error parsing server data"); reconnect = true; break;
                case Swift::ClientError::AuthenticationFailedError: message = ("Login/password invalid"); break;
                case Swift::ClientError::CompressionFailedError: message = ("Error while compressing stream"); break;
                case Swift::ClientError::ServerVerificationFailedError: message = ("Server verification failed"); break;
                case Swift::ClientError::NoSupportedAuthMechanismsError: message = ("Authentication mechanisms not supported"); break;
                case Swift::ClientError::UnexpectedElementError: message = ("Unexpected response"); break;
                case Swift::ClientError::ResourceBindError: message = ("Error binding resource"); break;
                case Swift::ClientError::SessionStartError: message = ("Error starting session"); break;
                case Swift::ClientError::StreamError: message = ("Stream error"); break;
                case Swift::ClientError::TLSError: message = ("Encryption error"); break;
                case Swift::ClientError::ClientCertificateLoadError: message = ("Error loading certificate (Invalid password?)"); break;
                case Swift::ClientError::ClientCertificateError: message = ("Certificate not authorized"); break;

                case Swift::ClientError::UnknownCertificateError: message = ("Unknown certificate"); break;
                case Swift::ClientError::CertificateExpiredError: message = ("Certificate has expired"); break;
                case Swift::ClientError::CertificateNotYetValidError: message = ("Certificate is not yet valid"); break;
                case Swift::ClientError::CertificateSelfSignedError: message = ("Certificate is self-signed"); break;
                case Swift::ClientError::CertificateRejectedError: message = ("Certificate has been rejected"); break;
                case Swift::ClientError::CertificateUntrustedError: message = ("Certificate is not trusted"); break;
                case Swift::ClientError::InvalidCertificatePurposeError: message = ("Certificate cannot be used for encrypting your connection"); break;
                case Swift::ClientError::CertificatePathLengthExceededError: message = ("Certificate path length constraint exceeded"); break;
                case Swift::ClientError::InvalidCertificateSignatureError: message = ("Invalid certificate signature"); break;
                case Swift::ClientError::InvalidCAError: message = ("Invalid Certificate Authority"); break;
                case Swift::ClientError::InvalidServerIdentityError: message = ("Certificate does not match the host identity"); break;
                default:
                    {
                        std::stringstream ss;
                        ss << ("Unknown error type") << error->getType();
                        message = ss.str();
                    }
                    break;
            }
        }
        else
        {
            message = ("Triggered manually");
            if(_owner->_reconnectAfterDisconnect)
                reconnect = true;
        }
        if(reconnect)
        {
            std::cerr << "Disconnected and reconnect; " << message << std::endl;
            _owner->reconnect();
        }
        else
        {
            std::cerr << "Disconnected and unable to reconnect; " << message << std::endl;
        }
    }

    void handleRosterReceived(ErrorPayload::ref error)
    {
        if (error) {
            std::cerr << "Error receiving roster. Continuing anyway.";
        }
        std::cout << "set presence for " << _owner->_client->getJID() << " to " << _statusMessage << std::endl;
        // Send initial available presence
        _owner->_client->sendPresence(Presence::create(_statusMessage));
    }

    void handleMessageReceived(Message::ref message)
    {
        _owner->incomingMessage(message);
    }

    void handlePresenceReceived(Presence::ref presence) {
        // Automatically approve subscription requests
        if (presence->getType() == Presence::Subscribe) {
            Presence::ref response = Presence::create();
            response->setTo(presence->getFrom());
            response->setType(Presence::Subscribed);
            _owner->_client->sendPresence(response);
        }
        _owner->sendPendingMessages();
    }

private:
    xmpp_agent * _owner;
    std::string _statusMessage;
};

xmpp_agent::xmpp_agent(const Config & config, NetworkFactories* networkFactories, Storages* storages)
    : _config(config)
    , _networkFactories(networkFactories)
    , _reconnect_timer()
    , _reconnectAfterDisconnect(true)
    , _clientOptions(NULL)
{
    _clientOptions = new ClientOptions;
    switch(_config.useTls())
    {
    case Config::NeverUseTLS: _clientOptions->useTLS = ClientOptions::NeverUseTLS; break;
    case Config::RequireTLS: _clientOptions->useTLS = ClientOptions::RequireTLS; break;
    default:
    case Config::UseTLSWhenAvailable: _clientOptions->useTLS = ClientOptions::UseTLSWhenAvailable; break;
    }

    _client = new Client(_config.xmppJid(), _config.xmppPassword(), networkFactories, storages);
    _client->addPayloadParserFactory(new GenericPayloadParserFactory<Swift::XHTMLIMParser>("html", "http://jabber.org/protocol/xhtml-im"));
    _client->addPayloadSerializer(new Swift::XHTMLIMSerializer());
    _client->setAlwaysTrustCertificates();
    _client->setSoftwareVersion(ARSOFT_XMPP_DAEMON_NAME, ARSOFT_XMPP_DAEMON_VERSION_STR);
    _callbacks = new Callbacks(this, _config.xmppStatusMessage());
}

xmpp_agent::~xmpp_agent()
{
    _reconnect_timer.reset();
    if(_client->isActive())
        _client->disconnect();
    delete _client;
    delete _clientOptions;
}

bool xmpp_agent::connect()
{
    _client->connect(*_clientOptions);
    return _client->isActive();
}

bool xmpp_agent::reconnect()
{
    _reconnect_timer = _networkFactories->getTimerFactory()->createTimer(800);
    _reconnect_timer->onTick.connect(boost::bind(&xmpp_agent::handleReconnectTimer, this));
    _reconnect_timer->start();
    return true;
}

void xmpp_agent::handleReconnectTimer()
{
    connect();
}

bool xmpp_agent::sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml)
{
    bool ret;
    Message::ref msgobj(new Message);
    // Echo back the incoming message
    msgobj->setTo(to);
    msgobj->setFrom(JID());
    msgobj->setSubject(subject);
    if(xml)
        msgobj->addPayload(boost::make_shared<Swift::XHTMLIMPayload>(message));
    else
        msgobj->setBody(message);
    msgobj->setType(Message::Chat);

    if(_client->isAvailable())
    {
        _client->sendMessage(msgobj);
        ret = true;
    }
    else
    {
        _pendingMessages.push(msgobj);
        std::cerr << "XMPP client not connected; attempt to reconnect" << std::endl;
        ret = reconnect();
    }
    return ret;
}

namespace {
    static std::string get_fqdn()
    {
        std::string ret;
        struct addrinfo hints, *info, *p;
        int gai_result;

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_CANONNAME;

        char hostname[256];
        gethostname(hostname, sizeof(hostname));

        gai_result = getaddrinfo(hostname, "http", &hints, &info);
        if(gai_result == 0)
        {
            for(p = info; p != NULL && ret.empty(); p = p->ai_next) {
                ret = p->ai_canonname;
            }
            freeaddrinfo(info);
        }
        return ret;
    }
} // namespace

void xmpp_agent::incomingMessage(Swift::Message::ref message)
{
    std::string command = message->getBody();
    if(!command.empty())
    {
#ifdef AGENT_DEBUG_COMMANDS
        bool disconnectAfterResponse = false;
#endif // AGENT_DEBUG_COMMANDS

        Message::ref respobj(new Message);
        respobj->setType(message->getType());
        respobj->setSubject(message->getSubject());
        respobj->setTo(message->getFrom());
        respobj->setFrom(JID());

        if(command == "version")
        {
            std::stringstream ss;
            ss << ARSOFT_XMPP_DAEMON_VERSION_STR << " on " << get_fqdn();
            respobj->setBody(ss.str());
        }
#ifdef AGENT_DEBUG_COMMANDS
        else if(command == "disconnect")
        {
            _reconnectAfterDisconnect = false;
            disconnectAfterResponse = true;
        }
        else if(command == "reconnect")
        {
            _reconnectAfterDisconnect = true;
            disconnectAfterResponse = true;
        }
#endif // AGENT_DEBUG_COMMANDS
        else
            respobj->setBody("unknown command \"" + command + "\"");

        // send response to this request/command
        _client->sendMessage(respobj);

#ifdef AGENT_DEBUG_COMMANDS
        if(disconnectAfterResponse)
        {
            _client->disconnect();
        }
#endif // AGENT_DEBUG_COMMANDS
    }
}

void xmpp_agent::sendPendingMessages()
{
    while(!_pendingMessages.empty())
    {
        Message::ref msgobj = _pendingMessages.front();
        if(_client->isAvailable())
        {
            std::cerr << "sendPendingMessage" << std::endl;
            _client->sendMessage(msgobj);
            _pendingMessages.pop();
        }
        else
            break;
    }
}
