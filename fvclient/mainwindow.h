#ifndef MAINWINDOW_H
#define MAINWINDOW_H
class ClientThread;
class QLabel;
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
private:
    ClientThread *m_client = nullptr;
    QLabel *m_statusLabel = nullptr;
    void setStatusText(QString str);

    void randomPassword();

private slots:
    //void on_pushButton_2_clicked();

    void on_btnRandomizePassword_clicked();

    void on_btnSetAdminPassword_clicked();

    void on_btnConnect_clicked();

    void joinServerSucceed(QString name);

    void joinServerFailed(QString err);

    void serverDisconnected();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
