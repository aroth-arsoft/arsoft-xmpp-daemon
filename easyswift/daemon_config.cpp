#include "daemon_config.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>

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
    _xmpp_jid = pt.get<std::string>("JID", std::string());
    std::string recipients = pt.get<std::string>("AllowedRecipients", std::string());
    if(!recipients.empty())
        boost::split(_allowed_xmpp_recipients, recipients, boost::is_any_of(","), boost::token_compress_on);
    else
        _allowed_xmpp_recipients.clear();
    _xmpp_default_recipient = pt.get<std::string>("DefaultRecipient", std::string());
    _xmpp_password = pt.get<std::string>("Password", std::string());
    _xmpp_status_message = pt.get<std::string>("StatusMessage", std::string());
}

std::ostream& operator<< (std::ostream& stream, const Config& config)
{
    stream << "socketFile=" << config.socketFile() << std::endl;
    stream << "xmppJid=" << config.xmppJid() << std::endl;
    stream << "xmppPassword=" << config.xmppPassword() << std::endl;
    stream << "xmppDefaultRecipient=" << config.xmppDefaultRecipient() << std::endl;
    stream << "allowedXmppRecipients=" << boost::join(config.allowedXmppRecipients(), ",") << std::endl;
    stream << "xmppStatusMessage=" << config.xmppStatusMessage() << std::endl;
    return stream;
}