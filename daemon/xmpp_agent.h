#pragma once

namespace Swift {
    class JID;
    class SafeString;
    class NetworkFactories;
    class Storages;
    class Timer;
}

class xmpp_agent
{
public:
    xmpp_agent(const Swift::JID& jid, const Swift::SafeString& password, const std::string & statusMessage, Swift::NetworkFactories* networkFactories, Swift::Storages* storages = NULL);
    virtual ~xmpp_agent();

    bool connect();

    bool sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml=false);

protected:
    class Callbacks;

    void incomingMessage(Swift::Message::ref message);
    void handleReconnectTimer();

    bool reconnect();

    void sendPendingMessages();

private:
    Swift::NetworkFactories* _networkFactories;
    Swift::Client *     _client;
    Callbacks *         _callbacks;
    boost::shared_ptr<Swift::Timer> _reconnect_timer;
    typedef std::queue<Swift::Message::ref> MessageQueue;
    MessageQueue _pendingMessages;
    bool                _reconnectAfterDisconnect;
};

