#ifndef REQUIREPASSWORDDIALOG_H
#define REQUIREPASSWORDDIALOG_H

#include <QDialog>

namespace Ui {
class RequirePasswordDialog;
}

class RequirePasswordDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RequirePasswordDialog(QWidget *parent = nullptr);
    ~RequirePasswordDialog();

    int exec(QString &str, quint8 minLength, quint8 maxLength);
private:
    quint8 m_passwordMinLength;
    quint8 m_passwordMaxLength;
    void updateOkButton();

private slots:
    void on_editPassword_textChanged(const QString &arg1);

    void on_editVerifyPassword_textChanged(const QString &arg1);

private:
    Ui::RequirePasswordDialog *ui;
};

#endif // REQUIREPASSWORDDIALOG_H
