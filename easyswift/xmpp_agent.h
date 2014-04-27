#pragma once

namespace Swift {
    class JID;
    class SafeString;
    class NetworkFactories;
    class Storages;
}

class xmpp_agent
{
public:
    xmpp_agent(const Swift::JID& jid, const Swift::SafeString& password, Swift::NetworkFactories* networkFactories, Swift::Storages* storages = NULL);
    virtual ~xmpp_agent();

    bool sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml=false);

protected:
    class Callbacks;

private:
    Swift::Client *     _client;
    Callbacks *         _callbacks;
};

