#include "daemon_config.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>

#include <iostream>

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

const std::string & Config::defaultConfigFile()
{
    static std::string s_defaultConfigFile("~/.arsoft/xmpp-daemon.conf");
    return s_defaultConfigFile;
}

const std::string & Config::defaultSocketFile()
{
    static std::string s_defaultSocketFile("/run/arsoft-xmpp-daemon/socket");
    return s_defaultSocketFile;
}

Config::Config()
    : _configFile()
    , _socket_file(defaultSocketFile())
    , _xmpp_jid()
    , _xmpp_default_recipient()
    , _allowed_xmpp_recipients()
    , _xmpp_password()
    , _xmpp_status_message()
    , _use_tls(UseTLSWhenAvailable)
{
}

Config::Config(const std::string & configFile)
    : _configFile()
    , _socket_file(defaultSocketFile())
    , _xmpp_jid()
    , _xmpp_default_recipient()
    , _allowed_xmpp_recipients()
    , _xmpp_password()
    , _xmpp_status_message()
    , _use_tls(UseTLSWhenAvailable)
{
    bool configRequired = !configFile.empty();
    if(configFile.empty())
        _configFile = expand_user(defaultConfigFile());
    else
        _configFile = expand_user(configFile);

    load(configRequired);
}

Config::~Config()
{
}

bool Config::load(bool configRequired)
{
    bool ret = false;
    try
    {
        boost::property_tree::ptree pt;
        boost::property_tree::ini_parser::read_ini(_configFile, pt);
        _socket_file = pt.get<std::string>("Socket", defaultSocketFile());
        if(_socket_file.empty())
            _socket_file = defaultSocketFile();
        _xmpp_jid = pt.get<std::string>("JID", std::string());
        std::string recipients = pt.get<std::string>("AllowedRecipients", std::string());
        if(!recipients.empty())
            boost::split(_allowed_xmpp_recipients, recipients, boost::is_any_of(","), boost::token_compress_on);
        else
            _allowed_xmpp_recipients.clear();
        _xmpp_default_recipient = pt.get<std::string>("DefaultRecipient", std::string());
        _xmpp_password = pt.get<std::string>("Password", std::string());
        _xmpp_status_message = pt.get<std::string>("StatusMessage", std::string());
        std::string tls_str = boost::to_lower_copy(pt.get<std::string>("UseTLS", std::string()));
        if(tls_str == "never")
            _use_tls = NeverUseTLS;
        else if(tls_str == "auto")
            _use_tls = UseTLSWhenAvailable;
        else if(tls_str == "require")
            _use_tls = RequireTLS;
        else
        {
            if(boost::algorithm::ends_with(_xmpp_jid, "@gmail.com") || boost::algorithm::ends_with(_xmpp_jid, "@googlemail.com"))
                _use_tls = RequireTLS;
            else
                _use_tls = UseTLSWhenAvailable;
        }

        ret = true;
    }
    catch(const boost::property_tree::ptree_error &e)
    {
        if(configRequired)
            std::cerr << "Failed to read config file " << _configFile << "; Error " << e.what() << std::endl;
    }
    return ret;
}

std::ostream& operator<< (std::ostream& stream, const Config& config)
{
    stream << "socketFile=" << config.socketFile() << std::endl;
    stream << "xmppJid=" << config.xmppJid() << std::endl;
    stream << "xmppPassword=" << config.xmppPassword() << std::endl;
    stream << "xmppDefaultRecipient=" << config.xmppDefaultRecipient() << std::endl;
    stream << "allowedXmppRecipients=" << boost::join(config.allowedXmppRecipients(), ",") << std::endl;
    stream << "xmppStatusMessage=" << config.xmppStatusMessage() << std::endl;
    stream << "useTls=" << config.useTls() << std::endl;
    return stream;
}