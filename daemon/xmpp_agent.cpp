#include <Swiften/Swiften.h>
#include "xmpp_agent.h"
#include "xhtml_payload.h"
#include "arsoft-xmpp-daemon-version.h"

using namespace Swift;

class xmpp_agent::Callbacks
{
public:
    Callbacks(xmpp_agent * owner, const std::string & statusMessage)
        : _owner(owner)
        , _statusMessage(statusMessage)
        {
            _owner->_client->onConnected.connect(boost::bind(&xmpp_agent::Callbacks::handleConnected, this));
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
    }

private:
    xmpp_agent * _owner;
    std::string _statusMessage;
};

xmpp_agent::xmpp_agent(const JID& jid, const SafeString& password, const std::string & statusMessage, NetworkFactories* networkFactories, Storages* storages)
{
    _client = new Client(jid, password, networkFactories, storages);
    _client->addPayloadParserFactory(new GenericPayloadParserFactory<Swift::XHTMLIMParser>("html", "http://jabber.org/protocol/xhtml-im"));
    _client->addPayloadSerializer(new Swift::XHTMLIMSerializer());
    _client->setAlwaysTrustCertificates();
    _callbacks = new Callbacks(this, statusMessage);
}

xmpp_agent::~xmpp_agent()
{
    if(_client->isActive())
        _client->disconnect();
    delete _client;
}

bool xmpp_agent::connect()
{
    _client->connect();
    return _client->isActive();
}

bool xmpp_agent::sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml)
{
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

    _client->sendMessage(msgobj);
    return true;
}

void xmpp_agent::incomingMessage(Swift::Message::ref message)
{
    std::string command = message->getBody();
    if(!command.empty())
    {
        Message::ref respobj(new Message);
        respobj->setType(message->getType());
        respobj->setSubject(message->getSubject());
        respobj->setTo(message->getFrom());
        respobj->setFrom(JID());

        if(command == "version")
        {
            respobj->setBody(ARSOFT_XMPP_DAEMON_VERSION_STR);
        }
        else
            respobj->setBody("unknown command \"" + command + "\"");

        // send response to this request/command
        _client->sendMessage(respobj);
    }
}
