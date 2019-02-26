#include "requirepassworddialog.h"
#include "ui_requirepassworddialog.h"
#include <QDebug>
#include <QWidget>
#include <QPushButton>
#include <QButtonGroup>

RequirePasswordDialog::RequirePasswordDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RequirePasswordDialog)
{
    ui->setupUi(this);
    //this->ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
}

RequirePasswordDialog::~RequirePasswordDialog()
{
    delete ui;
}

int RequirePasswordDialog::exec(QString &str, quint8 minLength, quint8 maxLength) {
    Q_ASSERT(minLength <= maxLength);
    m_passwordMinLength = minLength;
    m_passwordMaxLength = maxLength;
    updateOkButton();

    int res = this->QDialog::exec();
    if(res == QDialog::Accepted) {
        str = ui->editPassword->text();
    }

    return res;
}

void RequirePasswordDialog::updateOkButton() {
    QString password = ui->editPassword->text();
    if(password.length() >= m_passwordMinLength && password.length() <= m_passwordMaxLength
            && password == ui->editVerifyPassword->text()) {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
    } else {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
    }
}

void RequirePasswordDialog::on_editPassword_textChanged(const QString &arg1)
{
    updateOkButton();
}

void RequirePasswordDialog::on_editVerifyPassword_textChanged(const QString &arg1)
{
    updateOkButton();
}
