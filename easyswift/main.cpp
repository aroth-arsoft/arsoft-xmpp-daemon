#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/io_service.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <syslog.h>
#include <unistd.h>
#include <signal.h>

#include <Swiften/Swiften.h>

#include "xmpp_agent.h"
#include "server.h"
#include "daemon_config.h"

using namespace Swift;

class xmpp_target_sender : public server::server_callback
{
public:
    typedef std::set<std::string> string_set;
    xmpp_target_sender(xmpp_agent & sender, const Config & config)
        : _sender(sender)
        , _config(config)
        , _lastError()
    {}

    virtual bool onMessage(const server::message & msg, server::response & resp)
    {
        bool ret = send(msg.to, msg.cc, msg.subject, msg.body, msg.xml);
        resp.success = ret;
        resp.error_message = resp.success?"ok":_lastError;
        return ret;
    }

    const std::string & lastError() const { return _lastError; }

private:
    bool send(const std::string & to, const std::string & cc, const std::string & subject, const std::string & body, bool xml=false)
    {
        if(body.empty())
        {
            _lastError = "No body specified.";
            return false;
        }

        bool ret = false;
        string_set recipients;
        if(!to.empty())
            boost::split(recipients, to, boost::is_any_of(","), boost::token_compress_on);
        if(!cc.empty())
            boost::split(recipients, cc, boost::is_any_of(","), boost::token_compress_on);

        if(recipients.empty() && !_config.xmppDefaultRecipient().empty())
            recipients.insert(_config.xmppDefaultRecipient());

        std::cout << "num recp =" << recipients.size() << std::endl;

        if(recipients.empty())
        {
            _lastError = "No recipient specified.";
            ret = false;
        }
        else
        {
            ret = true;
            for(string_set::const_iterator it = recipients.begin(); it != recipients.end(); it++)
            {
                const std::string & recipient = *it;
                if(!sendTo(recipient, subject, body, xml))
                    ret = false;
            }
        }
        return ret;
    }

    bool sendTo(const std::string & to, const std::string & subject, const std::string & message, bool xml)
    {
        bool ret;
        if(!isAllowed(to))
        {
            _lastError = "Recipient " + to + " is not allowed.";
            ret = false;
        }
        else
        {
            ret = _sender.sendMessage(to, subject, message, xml);
        }
        return ret;
    }

    bool isAllowed(const std::string & to)
    {
        const string_set & allowedRecipients = _config.allowedXmppRecipients();
        string_set::const_iterator it = allowedRecipients.find(to);
        return (it != allowedRecipients.end());
    }

private:
    xmpp_agent & _sender;
    const Config & _config;
    std::string _lastError;
};

class xmpp_daemon
{
public:

    xmpp_daemon(bool debug)
        : _debug(debug)
        , _socket_server(NULL)
    {
        std::cout << _config;
    }

    bool prepare(bool upstart, bool daemon, bool foreground);
    int run();
    void cleanup();

    int forward_message(const std::string & to, const std::string & cc, const std::string & subject, const std::string & body, bool xml=false);

private:
    void removeSocketFile();
    void completeHandler(client * client);

private:
    bool _debug;
    Config _config;
    server * _socket_server;
    SimpleEventLoop * _eventLoop;
    BoostNetworkFactories * _networkFactories;
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

bool xmpp_daemon::prepare(bool upstart, bool daemon, bool foreground)
{
    removeSocketFile();

    _eventLoop = new SimpleEventLoop();
    _networkFactories = new BoostNetworkFactories(_eventLoop);

    boost::shared_ptr<boost::asio::io_service> io_service = _networkFactories->getIOServiceThread()->getIOService();

    if(daemon)
    {
        if(!foreground)
        {
            // Register signal handlers so that the daemon may be shut down. You may
            // also want to register for other signals, such as SIGHUP to trigger a
            // re-read of a configuration file.
            boost::asio::signal_set signals(*io_service.get(), SIGINT, SIGTERM);
            signals.async_wait(
                boost::bind(&boost::asio::io_service::stop, io_service.get()));

            // Inform the io_service that we are about to become a daemon. The
            // io_service cleans up any internal resources, such as threads, that may
            // interfere with forking.
            io_service->notify_fork(boost::asio::io_service::fork_prepare);

            // Fork the process and have the parent exit. If the process was started
            // from a shell, this returns control to the user. Forking a new process is
            // also a prerequisite for the subsequent call to setsid().
            if (pid_t pid = fork())
            {
                if (pid > 0)
                {
                    // We're in the parent process and need to exit.
                    //
                    // When the exit() function is used, the program terminates without
                    // invoking local variables' destructors. Only global variables are
                    // destroyed. As the io_service object is a local variable, this means
                    // we do not have to call:
                    //
                    //   io_service.notify_fork(boost::asio::io_service::fork_parent);
                    //
                    // However, this line should be added before each call to exit() if
                    // using a global io_service object. An additional call:
                    //
                    //   io_service.notify_fork(boost::asio::io_service::fork_prepare);
                    //
                    // should also precede the second fork().
                    exit(0);
                }
                else
                {
                    std::cerr << "First fork failed: " << errno << std::endl;
                    return false;
                }
            }

            // Make the process a new session leader. This detaches it from the
            // terminal.
            setsid();

            // A process inherits its working directory from its parent. This could be
            // on a mounted filesystem, which means that the running daemon would
            // prevent this filesystem from being unmounted. Changing to the root
            // directory avoids this problem.
            chdir("/");

            // The file mode creation mask is also inherited from the parent process.
            // We don't want to restrict the permissions on files created by the
            // daemon, so the mask is cleared.
            umask(0);

            // A second fork ensures the process cannot acquire a controlling terminal.
            if (pid_t pid = fork())
            {
                if (pid > 0)
                {
                    exit(0);
                }
                else
                {
                    std::cerr << "Second fork failed: " << errno << std::endl;
                    return false;
                }
            }

            // Close the standard streams. This decouples the daemon from the terminal
            // that started it.
            close(0);
            close(1);
            close(2);

            // We don't want the daemon to have any standard input.
            if (open("/dev/null", O_RDONLY) < 0)
            {
                syslog(LOG_ERR | LOG_USER, "Unable to open /dev/null: %m");
                return 1;
            }

            // Send standard output to a log file.
            const char* output = "/tmp/asio.daemon.out";
            const int flags = O_WRONLY | O_CREAT | O_APPEND;
            const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
            if (open(output, flags, mode) < 0)
            {
                syslog(LOG_ERR | LOG_USER, "Unable to open output file %s: %m", output);
                return false;
            }

            // Also send standard error to the same log file.
            if (dup(1) < 0)
            {
                syslog(LOG_ERR | LOG_USER, "Unable to dup output descriptor: %m");
                return false;
            }

            // Inform the io_service that we have finished becoming a daemon. The
            // io_service uses this opportunity to create any internal file descriptors
            // that need to be private to the new process.
            io_service->notify_fork(boost::asio::io_service::fork_child);
        }
    }

    return true;
}

int xmpp_daemon::run()
{
    boost::shared_ptr<boost::asio::io_service> io_service = _networkFactories->getIOServiceThread()->getIOService();

    xmpp_agent agent(_config.xmppJid(), _config.xmppPassword(), _config.xmppStatusMessage(), _networkFactories);
    xmpp_target_sender target_sender(agent, _config);

    _socket_server = new server(*io_service, _config.socketFile(), target_sender);

    _eventLoop->run();
}

void xmpp_daemon::cleanup()
{
    if(_networkFactories)
        delete _networkFactories;
    if(_eventLoop)
        delete _eventLoop;

    removeSocketFile();

}

void xmpp_daemon::completeHandler(client * client)
{
    _eventLoop->stop();
}

int xmpp_daemon::forward_message(const std::string & to, const std::string & cc, const std::string & subject, const std::string& body, bool xml)
{
    _eventLoop = new SimpleEventLoop;
    _networkFactories = new BoostNetworkFactories (_eventLoop);
    boost::shared_ptr<boost::asio::io_service> io_service = _networkFactories->getIOServiceThread()->getIOService();

    client * cl = new client(*io_service, _config.socketFile());
    client::message msg;
    msg.messageId = time(NULL);
    msg.to = to;
    msg.cc = cc;
    msg.subject = subject;
    msg.body = body;
    msg.xml = xml;
    cl->send(msg, boost::bind(&xmpp_daemon::completeHandler, this, _1));

    _eventLoop->run();
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
    ("foreground", "run in the foreground.")
    ("upstart", "run in the inside upstart.")
    ("user", po::value<std::string>(), "user to run the daemon.")
    ("group", po::value<std::string>(), "group to run the daemon.")
    ("to", po::value<std::string>(), "specify recipient of the message.")
    ("cc", po::value<std::string>(), "specify carbon copy recipient of the message.")
    ("subject", po::value<std::string>(), "message subject to send through the daemon.")
    ("body", po::value<std::string>(), "message body to send through the daemon.")
    ("xml", "if specified the given message is treated as XML message instead of plain text.")
    ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help"))
    {
        std::cout << desc << std::endl;
        ret = 0;
    }
    else
    {
        bool debug = vm.count("debug") != 0;
        bool daemon = vm.count("daemon") != 0;
        bool foreground = vm.count("foreground") != 0;
        bool upstart = vm.count("upstart") != 0;
        bool xml_message = vm.count("xml") != 0;
        std::string to;
        std::string cc;
        std::string body;
        std::string subject;
        if (vm.count("to"))
            to = vm["to"].as<std::string>();
        if (vm.count("cc"))
            cc = vm["cc"].as<std::string>();
        if (vm.count("body"))
            body = vm["body"].as<std::string>();
        if (vm.count("subject"))
            subject = vm["subject"].as<std::string>();

        xmpp_daemon app(debug);

        if(body.empty())
        {
            if(!app.prepare(upstart, daemon, foreground))
                ret = 1;
            else
            {
                ret = app.run();
                app.cleanup();
            }
        }
        else
        {
            app.forward_message(to, cc, subject, body, xml_message);
        }
    }
    return ret;
}
