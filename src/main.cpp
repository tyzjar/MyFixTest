#include <csignal>
#include <iostream>
#include <condition_variable>

#include <quickfix/FileStore.h>
#include <quickfix/FileLog.h>
#include <quickfix/Application.h>
#include <quickfix/MessageCracker.h>
#include <quickfix/SocketAcceptor.h>
#include <quickfix/SessionSettings.h>
#include <quickfix/Exceptions.h>
#include <quickfix/fix44/Logon.h>

namespace
{

constexpr auto c_passwordField = "Password";
constexpr auto c_defaultFileName = "server.cfg";
//constexpr std::chrono::milliseconds c_duration = std::chrono::milliseconds(3000);

class RouteState
{
public:
    RouteState() : m_routeState {false} {}

    void StartWait()
    {
        std::unique_lock<std::mutex> lock_(mutex);
        m_routeState = false;
        m_waiter.wait(lock_, [this](){ return m_routeState; });
    }

    void HandleEnd()
    {
        {
            std::unique_lock<std::mutex> lock_(mutex);
            std::cout << "Close server.\n";
            m_routeState = true;
        }
        m_waiter.notify_all();
    }

private:
    bool m_routeState;
    std::condition_variable m_waiter;
    mutable std::mutex mutex;
};

RouteState Route;

} // unnamed namespace

class MyFIXServer : public FIX::Application, public FIX::MessageCracker
{
public:
    MyFIXServer(const FIX::SessionSettings& settings) :
    m_settings {settings}
    {}

    void onCreate(const FIX::SessionID&) override {}
    void onLogon(const FIX::SessionID& sessionID) override {}
    void onLogout(const FIX::SessionID& sessionID) override {}
    void toAdmin(FIX::Message&, const FIX::SessionID&) EXCEPT ( FIX::DoNotSend ) override {}
    void toApp(FIX::Message&, const FIX::SessionID&) noexcept override {}
    void fromAdmin(const FIX::Message& message, const FIX::SessionID& sessionID)
        EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::RejectLogon ) override;
    void fromApp(const FIX::Message& message, const FIX::SessionID& sessionID)
        EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::UnsupportedMessageType ) override;

    void onMessage(const FIX44::Logon& message, const FIX::SessionID& sessionID) override;

private:
    const FIX::SessionSettings& m_settings;
};

void MyFIXServer::fromAdmin(const FIX::Message& message, const FIX::SessionID& sessionID)
    EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::RejectLogon )
{
    // Here we call onMessage for Logon.
    crack(message, sessionID);
}

void MyFIXServer::fromApp(const FIX::Message& message, const FIX::SessionID& sessionID)
    EXCEPT( FIX::FieldNotFound, FIX::IncorrectDataFormat, FIX::IncorrectTagValue, FIX::UnsupportedMessageType )
{
    crack(message, sessionID);
}

void MyFIXServer::onMessage(const FIX44::Logon& message, const FIX::SessionID& sessionID)
{
    auto&& session = m_settings.get(sessionID);
    if (!session.has(c_passwordField))
    {
        std::cout << "Cant auth session without password\n";
        throw FIX::RejectLogon("Server configuration error.\n");
    }

    if (!message.isSetField(FIX::FIELD::Password) ||
        session.getString(c_passwordField) != message.getField(FIX::FIELD::Password))
    {
        throw FIX::RejectLogon("Wrong password !\n");
    }
}

int main(int argc, char** argv) {
    try {
        signal(SIGTERM, [] (int signal) {
            Route.HandleEnd();
        });

        std::string fileName = argc < 2 ? c_defaultFileName : argv[1];
        FIX::SessionSettings settings(fileName);
        MyFIXServer application(settings);
        FIX::FileStoreFactory storeFactory(settings);
        FIX::FileLogFactory logFactory(settings);
        FIX::SocketAcceptor acceptor
            (application, storeFactory, settings, logFactory /*optional*/);

        acceptor.start();

        Route.StartWait();

        acceptor.stop();
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "Unhandled error. Terminate.\n";
        return 2;
    }
}
