#include <QApplication>
#include <QStandardPaths>
//#include <QException>
#include "env.h"
#include "def.h"
Env::Env()
{
    QString homeDir = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
    QString dataDir = homeDir + "/." APP_NAME;

    m_dataPath = dataDir;
    m_localCertPath = dataDir;

    QString resourceDir;
#ifdef Q_OS_WIN32
#error "not support";
    resourceDir = QApplication::applicationDirPath();
    m_CAFileName = resourceDir + "/ca-certificates";
#elif defined (Q_OS_LINUX)
    resourceDir = QApplication::applicationDirPath();
    m_CAFileName = resourceDir + "/ca-certificates";
#elif defined (Q_OS_MAC)
#error "not support";
#endif

    m_CAFileName.append("/" CA_FILENAME);

}

Env *Env::m_instance = nullptr;

Env *Env::instance() {
    if(Env::m_instance == nullptr) {
        m_instance = new Env();
    }
    return m_instance;
}

QString Env::getCAFileName() const
{
    return m_CAFileName;
}

QString Env::getLocalCertPath() const
{
    return m_localCertPath;
}

QString Env::getDataPath() const
{
    return m_dataPath;
}

