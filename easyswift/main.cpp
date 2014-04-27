#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <Swiften/Swiften.h>

#include "xmpp_agent.h"
#include "server.h"
#include "daemon_config.h"

using namespace Swift;

class xmpp_target_sender : public server::server_callback
{
public:
    typedef std::set<std::string> string_set;
    xmpp_target_sender(xmpp_agent & sender, const std::string & defaultRecipient, const string_set & allowedRecipients=string_set())
        : _sender(sender)
        , _defaultRecipient(defaultRecipient)
    {}

    virtual bool onMessage(const server::message & msg)
    {
        return send(msg.to, msg.cc, msg.subject, msg.body, msg.xml);
    }

private:
    bool send(const std::string & to, const std::string & cc, const std::string & subject, const std::string & body, bool xml=false)
    {
        if(body.empty())
            return false;

        bool ret = false;
        string_set recipients;
        boost::split(recipients, to, boost::is_any_of(","));
        boost::split(recipients, cc, boost::is_any_of(","));

        if(recipients.empty() && !_defaultRecipient.empty())
            recipients.insert(_defaultRecipient);

        if(recipients.empty())
            ret = false;
        else
        {
            ret = true;
            for(string_set::const_iterator it = recipients.begin(); it != recipients.end(); it++)
            {
                const std::string & recipient = *it;
                if(!sendTo(_defaultRecipient, subject, body, xml))
                    ret = false;
            }
        }
        return ret;
    }

    bool sendTo(const std::string & to, const std::string & subject, const std::string & message, bool xml)
    {
        if(!isAllowed(to))
            return false;
        return _sender.sendMessage(to, subject, message, xml);
    }

    bool isAllowed(const std::string & to)
    {
        string_set::const_iterator it = _allowedRecipients.find(to);
        return (it != _allowedRecipients.end());
    }

private:
    xmpp_agent & _sender;
    std::string _defaultRecipient;
    string_set _allowedRecipients;
};

class xmpp_daemon
{
public:

    xmpp_daemon(bool debug)
        : _debug(debug)
        , _socket_server(NULL)
    {
    }

    bool prepare(bool upstart, bool daemon);
    int run();
    void cleanup();

    int forward_message(const std::string & subject, const std::string & body, bool xml=false);

private:
    void removeSocketFile();

private:
    bool _debug;
    Config _config;
    server * _socket_server;
};

void xmpp_daemon::removeSocketFile()
{
    if (boost::filesystem::exists(_config.socketFile()))
    {
        if(_debug)
            std::cout << "Remove old socket file " << _config.socketFile() << std::endl;
        boost::filesystem::remove(_config.socketFile());
    }

}

bool xmpp_daemon::prepare(bool upstart, bool daemon)
{
    removeSocketFile();
    return true;
}

int xmpp_daemon::run()
{
    SimpleEventLoop eventLoop;
    BoostNetworkFactories networkFactories(&eventLoop);
    boost::shared_ptr<boost::asio::io_service> io_service = networkFactories.getIOServiceThread()->getIOService();

    xmpp_agent agent(_config.xmppJid(), _config.xmppPassword(), &networkFactories);
    xmpp_target_sender target_sender(agent, _config.xmppDefaultRecipient(), _config.allowedXmppRecipients());

    _socket_server = new server(*io_service, _config.socketFile(), target_sender);

    eventLoop.run();
}

void xmpp_daemon::cleanup()
{
    removeSocketFile();
}
int xmpp_daemon::forward_message(const std::string & subject, const std::string& body, bool xml)
{
    SimpleEventLoop eventLoop;
    BoostNetworkFactories networkFactories(&eventLoop);
    boost::shared_ptr<boost::asio::io_service> io_service = networkFactories.getIOServiceThread()->getIOService();

    client * cl = new client(*io_service, _config.socketFile());
    client::message msg;
    msg.subject = subject;
    msg.body = body;
    msg.xml = xml;
    cl->send(msg);

    eventLoop.run();
    return 0;
}

namespace po = boost::program_options;

int main(int argc, char** argv)
{
    int ret;
    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
    ("help", "produce help message")
    ("debug", "enable debug mode")
    ("daemon", "run in the background as daemon.")
    ("upstart", "run in the inside upstart.")
    ("user", po::value<std::string>(), "user to run the daemon.")
    ("group", po::value<std::string>(), "group to run the daemon.")
    ("subject", po::value<std::string>(), "message subject to send through the daemon.")
    ("body", po::value<std::string>(), "message body to send through the daemon.")
    ("xml", "if specified the given message is treated as XML message instead of plain text.")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        std::cout << desc << "\n";
        ret = 0;
    }
    else
    {
        bool debug = vm.count("debug") != 0;
        bool daemon = vm.count("daemon") != 0;
        bool upstart = vm.count("upstart") != 0;
        bool xml_message = vm.count("xml") != 0;
        std::string body;
        std::string subject;
        if (vm.count("body"))
            body = vm["body"].as<std::string>();
        if (vm.count("subject"))
            subject = vm["subject"].as<std::string>();

        xmpp_daemon app(debug);

        std::cout << "body: " << body << std::endl;

        if(body.empty())
        {
            if(!app.prepare(upstart, daemon))
                ret = 1;
            else
            {
                ret = app.run();
                app.cleanup();
            }
        }
        else
        {
            app.forward_message(subject, body, xml_message);
        }
    }
    return ret;
}
