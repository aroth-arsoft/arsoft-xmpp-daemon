#include <Swiften/Swiften.h>
#include "xmpp_agent.h"

using namespace Swift;

class xmpp_agent::Callbacks
{
public:
    Callbacks(xmpp_agent * owner)
        : _owner(owner)
        {
            _owner->_client->onConnected.connect(boost::bind(&xmpp_agent::Callbacks::handleConnected, this));
            _owner->_client->onMessageReceived.connect(boost::bind(&xmpp_agent::Callbacks::handleMessageReceived, this, _1));
            _owner->_client->onPresenceReceived.connect(boost::bind(&xmpp_agent::Callbacks::handlePresenceReceived, this, _1));
        }

    void handleConnected()
    {
        std::cout << "Connected" << std::endl;
        // Request the roster
        GetRosterRequest::ref rosterRequest =
            GetRosterRequest::create(_owner->_client->getIQRouter());
        rosterRequest->onResponse.connect( boost::bind(&xmpp_agent::Callbacks::handleRosterReceived, this, _2));
        rosterRequest->send();
    }

    void handleRosterReceived(ErrorPayload::ref error)
    {
        if (error) {
            std::cerr << "Error receiving roster. Continuing anyway.";
        }
        // Send initial available presence
        _owner->_client->sendPresence(Presence::create("Send me a message"));
    }

    void handleMessageReceived(Message::ref message)
    {
        // Echo back the incoming message
        message->setTo(message->getFrom());
        message->setFrom(JID());
        _owner->_client->sendMessage(message);
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
};

xmpp_agent::xmpp_agent(const JID& jid, const SafeString& password, NetworkFactories* networkFactories, Storages* storages)
{
    _client = new Client(jid, password, networkFactories, storages);
    _client->setAlwaysTrustCertificates();
    _callbacks = new Callbacks(this);
    _client->connect();
}

xmpp_agent::~xmpp_agent()
{
    delete _client;
}


bool xmpp_agent::sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml)
{
    Message::ref msgobj(new Message);
    // Echo back the incoming message
    msgobj->setTo(to);
    msgobj->setFrom(JID());
    msgobj->setSubject(subject);
    msgobj->setBody(message);
    msgobj->setType(Message::Chat);

    _client->sendMessage(msgobj);
    return true;
}
