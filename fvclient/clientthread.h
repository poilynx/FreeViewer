#ifndef CLIENTTHREAD_H
#define CLIENTTHREAD_H
#include <QThread>
#include <QObject>
#include <QTcpSocket>
#include <QQueue>
#include <QMutex>
#include "travclient.h"
#include "tunnel.h"

struct request_ctx_st;

class Request {
public:
    virtual QString name() = 0;
    virtual ~Request();
};

class TraverseRequest : public Request {
public:
    QString name() override {
        return "Traverse";
    }
    QString peerName;
};

class ClientThread : public QThread
{
    Q_OBJECT
public:
    explicit ClientThread(QString serverHost, quint16 serverPort,
                    QString caFile, QString certPath,
                    QObject *parent = nullptr);
    ~ClientThread();
    void traverse(QString userID);
    void setVNCServerPort(quint16 port);
    void enableListener(bool enable);
    void updateAdminPassword(QString password);
    void updateRandomPassword(QString password);
    void quit();
private:
    QString m_serverHost;
    QString m_serverPort;
    QString m_caFile;
    QString m_certPath;
    quint16 m_vncport;
    QString m_adminPassword = "";
    QString m_readonly;

    client_t *m_client = nullptr;
    tunnel_listener_t *m_tlistener = nullptr;
    struct event_base *m_base = nullptr;
    struct request_ctx_st *m_reqctx;

    struct ssl_ctx_st *m_listener_ctx;



    void signin_cb(client_t *client, int errcode, const char *name, void *arg);
    int listen_cb(client_t *client, struct sockaddr_in sa, const char *name, void *arg);
    void tun_listen_cb(tunnel_t *tun, const char *passwd, void *arg);
protected:
    void run();
signals:

    void joinServerSucceed(QString userID);
    void joinServerFailed(QString errMsg);
    void newTraverse();
    void traverseSucceed(QString userID, quint16 port);
    void traverseFailed(QString userID, QString errMsg);
    void disconneted();
    void stop();

public slots:

};

#endif // CLIENT_H
