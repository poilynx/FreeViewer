#include <QMessageBox>
#include <QTime>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "requirepassworddialog.h"
#include "clientthread.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    m_statusLabel = new QLabel();
    ui->statusBar->addWidget(m_statusLabel);

    randomPassword();

    m_client = new ClientThread("host", 6363, "ca", "certpath");
    connect(m_client, SIGNAL(joinServerSucceed(QString)), this, SLOT(joinServerSucceed(QString)));
    connect(m_client, SIGNAL(joinServerFailed(QString)), this, SLOT(joinServerFailed(QString)));
    connect(m_client, SIGNAL(disconnected()), this, SLOT(serverDisconnected()));

    m_client->start();


    setStatusText("Connecting server. . .");
}

MainWindow::~MainWindow()
{

    delete m_client;
    delete ui;
}

void MainWindow::randomPassword() {
     ui->btnRandomizePassword->setEnabled(false);
    qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
    /* passkey between a and z or between 0 and 9 */
    quint32 maxkey = (36U*36*36*36*36*36);
    Q_ASSERT(36U*36*36*36*36*36  < 0xFFFFFFFFU);
    QString password;
    quint32 ran = ((quint32)qrand() << 16 | qrand()) % maxkey;
    //quint32 ran = maxkey-1; //for test

    do {
        int mod = ran % 36;
        if(mod < 10)
            password.append('0' + mod);
        else
            password.append('A' + (mod-10));
    } while(ran/=36);
    ui->editPassword->setText(password);
    ui->btnRandomizePassword->setEnabled(true);
}

void MainWindow::on_btnRandomizePassword_clicked()
{
    this->randomPassword();
}

void MainWindow::on_btnSetAdminPassword_clicked()
{
    RequirePasswordDialog dialog;
    QString password;
    if(dialog.exec(password, 0, 5) == QDialog::Accepted) {
        //QMessageBox::information(this, "", password);
        ui->editAdminPassword->setText(password);
    }
}

void MainWindow::on_btnConnect_clicked()
{
    this->m_client->traverse("2");
}

void MainWindow::joinServerSucceed(QString name)
{
    //QMessageBox::information(this,"", name);
    ui->editUserID->setText(name);
    setStatusText("Ready");
}

void MainWindow::joinServerFailed(QString err) {
    //setStatusText("Connect server failed: " + err);
    //QMessageBox::critical(this, qApp->applicationDisplayName(), "Connect server failed: " + err);
    QMessageBox::critical(this, qApp->applicationName(), "Connect server failed: " + err);
    qApp->closeAllWindows();
    qApp->quit();
}

void MainWindow::serverDisconnected()
{
    qDebug() << "disconnect";
}

void MainWindow::setStatusText(QString str) {
    this->m_statusLabel->setText(str);
}
