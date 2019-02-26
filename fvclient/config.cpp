#include <QSettings>
#include <QCryptographicHash>
#include "config.h"
#include "def.h"
#include "env.h"
Config::Config()
{

}

Config *Config::m_instance = nullptr;

Config *Config::instance() {
    if(m_instance == nullptr) {
        m_instance = new Config();
    }
    return m_instance;
}

bool Config::load()
{
    //QSettings setting;
    //setting.NativeFormat
    QSettings setting(Env::instance()->getDataPath() + "/" CONFIG_FILENAME, QSettings::IniFormat);
    setting.beginGroup("SERVER");
    bool ok, failed;
    this->serverHost = setting.value("HOST", "").toString();
    quint32 server_port = setting.value("PORT", 6363).toUInt(&ok);
    if(ok && server_port < 65536) {
        this->serverPort = static_cast<quint16>(server_port);
    } else {
        this->serverPort = 6363;
        failed = true;
    }

    setting.beginGroup("VNC");
    quint32 vnc_port = setting.value("PORT", 5900).toUInt(&ok);
    if(ok || vnc_port < 65536) {
        this->vncPort = static_cast<quint16>(vnc_port);
    } else {
        this->vncPort = 5900;
        failed = true;
    }
    setting.beginGroup("PRIVILEGE");
    this->adminPassword = setting.value("PASSWORD", "").toString();



}

bool Config::save()
{
    QSettings setting(Env::instance()->getDataPath() + "/" CONFIG_FILENAME, QSettings::IniFormat);
}
