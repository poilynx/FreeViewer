#include "mainwindow.h"
#include <QApplication>
#include "configdialog.h"
#include <event2/thread.h>

int main(int argc, char *argv[])
{
    evthread_use_pthreads();

    QApplication a(argc, argv);
    MainWindow w;

    w.setWindowFlags(Qt::WindowMinimizeButtonHint | Qt::WindowCloseButtonHint);
    w.setFixedSize(w.size());
    w.show();

    return a.exec();
}
