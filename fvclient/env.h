#ifndef ENV_H
#define ENV_H
#include <QString>

class Env
{
private:
    Env();
    static Env *m_instance;
    QString m_CAFileName;
    QString m_localCertPath;
    QString m_dataPath;
public:
    static Env *instance();
    QString getCAFileName() const;
    QString getLocalCertPath() const;
    QString getDataPath() const;
};

//Config *Config::m_instance;

#endif // CONFIG_H
