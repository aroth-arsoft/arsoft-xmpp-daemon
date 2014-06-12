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
    xmpp_agent(const Swift::JID& jid, const Swift::SafeString& password, const std::string & statusMessage, Swift::NetworkFactories* networkFactories, Swift::Storages* storages = NULL);
    virtual ~xmpp_agent();

    bool connect();

    bool sendMessage(const std::string & to, const std::string & subject, const std::string & message, bool xml=false);

protected:
    class Callbacks;

    static std::string encodeMessage(const std::string & msg);

private:
    Swift::Client *     _client;
    Callbacks *         _callbacks;
};

