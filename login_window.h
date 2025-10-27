#ifndef LOGIN_WINDOW_H
#define LOGIN_WINDOW_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QObject>

class LoginWindow : public QWidget {
    Q_OBJECT

public:
    explicit LoginWindow(QWidget *parent = nullptr);

private slots:
    void onLoginClicked();
    void onCambiarPasswordClicked();      // NUEVA
    void onOlvidePasswordClicked();       // NUEVA

private:
    QLineEdit *usernameInput;
    QLineEdit *passwordInput;
    QPushButton *loginButton;
    QLabel *statusLabel;

    void switchToAdminWindow();
    void switchToCajeroWindow();
};

#endif // LOGIN_WINDOW_H