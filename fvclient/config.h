#ifndef CONFIG_H
#define CONFIG_H
#include <QObject>

class Config
{
private:
    Config();
    ~Config();
    static Config *m_instance;
    //bool changed = false;
public:
    QString serverHost;
    quint16 serverPort;
    quint16 localPort;
    quint16 vncPort;
    QString adminPassword;
    static Config *instance();
    bool load();
    bool save();
};

#endif // CONFIG_H
