#include <event2/event.h>
#include <event2/thread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <QThread>
#include <QMessageBox>

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "def.h"
#include "clientthread.h"
#include "travclient.h"
#include "tunnel.h"
#include "env.h"
#include "getcb.h"


static SSL_CTX *make_listen_ctx(QString keyfile, QString crtfile)
{
    SSL_CTX  *ctx = SSL_CTX_new(SSLv23_server_method());
    //SSL_CTX  *ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    QByteArray key = keyfile.toLocal8Bit();
    QByteArray crt = crtfile.toLocal8Bit();


    if (! SSL_CTX_use_certificate_file(ctx, crt.data(), SSL_FILETYPE_PEM) ||
            ! SSL_CTX_use_PrivateKey_file(ctx, key.data(), SSL_FILETYPE_PEM)) {

        ERR_print_errors_fp(stderr);
        return NULL;
    }
    //SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    return ctx;
}




struct request_ctx_st {
    struct event *event = nullptr;
    client_t *client = nullptr;

    QQueue<Request*> queue;
    QMutex mutex;
} ;

Request::~Request() {}

ClientThread::ClientThread(QString serverHost, quint16 serverPort,
                QString caFile, QString certPath,
                QObject *parent): QThread(parent)
{
    m_reqctx = new request_ctx_st;
    //m_tlistener = tunnel_listener_new()
}

ClientThread::~ClientThread() {
    delete m_reqctx;
}

void ClientThread::traverse(QString userID) {
    qDebug() << "ClientThread::traverse";
    TraverseRequest *req = new TraverseRequest();
    req->peerName = userID;


    m_reqctx->mutex.lock();
    m_reqctx->queue.enqueue(req);
    m_reqctx->mutex.unlock();
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    evtimer_add(m_reqctx->event, &tv);
}

void ClientThread::setVNCServerPort(quint16 port) {

}

void ClientThread::enableListener(bool enable) {

}

void ClientThread::updateAdminPassword(QString password) {

}

void ClientThread::updateRandomPassword(QString password) {

}

void ClientThread::quit() {

}


static tunnel_t *g_tun = NULL;
static void traverse_cb(client_t *client, int errcode, struct sockaddr_in *sa, void *arg) {
    qDebug() << "traverse_cb errcode = " << errcode;
    if(errcode == 0) {
    } else {

    }


}

static void request_cb(int fd, short events, void *arg) {
    qDebug() << "request_cb";
    (void)fd;
    (void)events;
    struct request_ctx_st *ctx = (struct request_ctx_st*) arg;
    ctx->mutex.lock();
    if(! ctx->queue.isEmpty()) {
        QString name = ctx->queue.head()->name();
        if(name == "Traverse") {
            qDebug() << "name == Traverse";
            TraverseRequest *req = static_cast<TraverseRequest*>(ctx->queue.dequeue());
            QByteArray peername = req->peerName.toUtf8();
            ctx->mutex.unlock();
            int ret = trav_client_traverse(ctx->client, peername.data(), traverse_cb, NULL);
            qDebug() << "trav_client_traverse ret = " << ret;
        }
    } else {
        ctx->mutex.unlock();
    }
}

void ClientThread::tun_listen_cb(tunnel_t *tun, const char *passwd, void *arg) {
    qDebug() << "tun_listen_cb";
    qDebug() << "password " << passwd;
    tunnel_accept(tun);
}

void ClientThread::signin_cb(client_t *client, int errcode, const char *name, void *arg) {
    //ClientThread *clientThread = static_cast<ClientThread*>(arg);
    if(errcode == 0) {
        quint16 localPort = trav_client_local_port(m_client);

        qDebug() << "localPort = " << localPort;
        QString keyfile, certfile;
        keyfile = Env::instance()->getLocalCertPath().append("/" KEY_FILENAME);
        certfile = Env::instance()->getLocalCertPath().append("/" CRT_FILENAME);

        m_listener_ctx = make_listen_ctx(keyfile, certfile);

        tunnel_listen_cb _tun_listen_cb = GETCB(tunnel_listen_cb, ClientThread)
            (std::bind(&ClientThread::tun_listen_cb, this,
                       std::placeholders::_1,
                       std::placeholders::_2,
                       std::placeholders::_3));

        m_tlistener = tunnel_listener_new(m_base, localPort, m_listener_ctx, _tun_listen_cb, nullptr);
        emit this->joinServerSucceed(name);
    }
    else
        emit this->joinServerFailed(QString("Can not join in, error %1").arg(errcode));
}


int ClientThread::listen_cb(client_t *client, struct sockaddr_in sa, const char *name, void *arg) {
    qDebug() << "listen_cb " << name;
    qDebug() << "Remote addr: " << inet_ntoa(sa.sin_addr) << " port: " << ntohs(sa.sin_port);

    tunnel_listener_punch(m_tlistener, &sa);
    return 1;

}

void ClientThread::run() {
    qDebug() << "Client thread started";
    qDebug() << Env::instance()->getCAFileName();
    qDebug() << Env::instance()->getLocalCertPath();
    m_base = event_base_new();

    m_reqctx->event = evtimer_new(m_base, request_cb, m_reqctx);
    //struct timeval tv = {0,0};
    //evtimer_add(m_reqctx->event, &tv);

    QByteArray keyfile, certfile, cafile;
    keyfile = Env::instance()->getLocalCertPath().append("/" KEY_FILENAME).toLocal8Bit();
    certfile = Env::instance()->getLocalCertPath().append("/" CRT_FILENAME).toLocal8Bit();
    cafile = Env::instance()->getCAFileName().toLocal8Bit();
    qDebug() << keyfile.data() ;
    qDebug() << certfile.data();
    qDebug() << cafile.data();

    char keyfile_buf[1024];
    char certfile_buf[1024];
    char cafile_buf[1024];
    strcpy(keyfile_buf, keyfile.data());
    strcpy(certfile_buf, certfile.data());
    strcpy(cafile_buf, cafile.data());
    qDebug() << "cafile: " << cafile_buf;

    client_signin_cb a;

    client_signin_cb _signin_cb = GETCB(client_signin_cb, ClientThread)
            (std::bind(&ClientThread::signin_cb, this,
                       std::placeholders::_1,
                       std::placeholders::_2,
                       std::placeholders::_3,
                       std::placeholders::_4));

    client_listen_cb _listen_cb =  GETCB(client_listen_cb, ClientThread)
            (std::bind(&ClientThread::listen_cb, this,
                       std::placeholders::_1,
                       std::placeholders::_2,
                       std::placeholders::_3,
                       std::placeholders::_4));


    m_client = trav_client_new(m_base,
                    cafile_buf,
                    keyfile_buf,
                    certfile_buf,
                    _signin_cb,
                    _listen_cb,
                    this);
    Q_ASSERT(m_client);

    m_reqctx->client = m_client;

    if(trav_client_connect(m_client, "127.0.0.1" /*"103.118.40.84"*/, 6363, 0) != 0) {
        emit this->joinServerFailed(strerror(errno));
    }

    event_base_loop(m_base, 0);

    event_base_free(m_base);
    emit this->disconneted();
    qDebug() << "Thread over";
}
