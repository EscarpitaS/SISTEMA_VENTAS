#include <QApplication>
#include "login_window.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    LoginWindow loginWindow;
    loginWindow.show();

    return app.exec();
}


