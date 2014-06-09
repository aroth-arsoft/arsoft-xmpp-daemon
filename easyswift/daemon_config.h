#pragma once

#include <string>
#include <set>

class Config
{
public:
    typedef std::set<std::string>   string_set;

    Config(const std::string & configFile="~/.swifter.conf");
    virtual ~Config();

    const std::string & socketFile() const { return _socket_file; }
    const std::string & xmppJid() const { return _xmpp_jid; }
    const std::string & xmppPassword() const { return _xmpp_password; }
    const std::string & xmppDefaultRecipient() const { return _xmpp_default_recipient; }
    const string_set & allowedXmppRecipients() const { return _allowed_xmpp_recipients; }
    const std::string & xmppStatusMessage() const { return _xmpp_status_message; }

    friend std::ostream& operator<< (std::ostream& stream, const Config& config);

private:
    void            load();
private:
    std::string _configFile;

    std::string _socket_file;
    std::string _xmpp_jid;
    std::string _xmpp_default_recipient;
    string_set _allowed_xmpp_recipients;
    std::string _xmpp_password;
    std::string _xmpp_status_message;
};

std::ostream& operator<< (std::ostream& stream, const Config& config);

