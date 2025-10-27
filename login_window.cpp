#include "login_window.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QMessageBox>
#include <QString>
#include <QTableWidget>
#include <QHeaderView>
#include <QGroupBox>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QCryptographicHash>
#include <QDebug>

// Configuración conexión
const QString HOST = "database-2.c8x408ogmb0e.us-east-1.rds.amazonaws.com";
const int PORT = 3306;
const QString DBNAME = "sistema_ventas";

// Credenciales para conexiones
const QString USER_LOGIN = "login_app";
const QString PASS_LOGIN = "plogin";
const QString USER_ADMIN = "app_admin";
const QString PASS_ADMIN = "padmin";

// Función SHA256 usando Qt
QString sha256_string(const QString &input) {
    QByteArray hash = QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha256);
    return hash.toHex();
}

// Función para crear conexión
QSqlDatabase createConnection(const QString &connectionName, const QString &user, const QString &pass) {
    QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL", connectionName);
    db.setHostName(HOST);
    db.setPort(PORT);
    db.setDatabaseName(DBNAME);
    db.setUserName(user);
    db.setPassword(pass);
    return db;
}

LoginWindow::LoginWindow(QWidget *parent) : QWidget(parent) {
    setWindowTitle("Sistema de Ventas - Login");
    setFixedSize(350, 250);

    QLabel *userLabel = new QLabel("Usuario:");
    usernameInput = new QLineEdit();
    QLabel *passLabel = new QLabel("Contraseña:");
    passwordInput = new QLineEdit();
    passwordInput->setEchoMode(QLineEdit::Password);
    loginButton = new QPushButton("Iniciar Sesión");
    statusLabel = new QLabel("");

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(userLabel);
    layout->addWidget(usernameInput);
    layout->addWidget(passLabel);
    layout->addWidget(passwordInput);
    layout->addWidget(loginButton);
    layout->addWidget(statusLabel);

    // Botones adicionales
    QHBoxLayout *extraButtonsLayout = new QHBoxLayout();
    QPushButton *btnCambiarPass = new QPushButton("Cambiar Contraseña");
    QPushButton *btnOlvidePass = new QPushButton("Olvidé mi Contraseña");
    btnCambiarPass->setStyleSheet("color: #1976D2;");
    btnOlvidePass->setStyleSheet("color: #D32F2F;");

    extraButtonsLayout->addWidget(btnCambiarPass);
    extraButtonsLayout->addWidget(btnOlvidePass);
    layout->addLayout(extraButtonsLayout);

    setLayout(layout);

    connect(loginButton, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
    connect(passwordInput, &QLineEdit::returnPressed, this, &LoginWindow::onLoginClicked);
    connect(btnCambiarPass, &QPushButton::clicked, this, &LoginWindow::onCambiarPasswordClicked);
    connect(btnOlvidePass, &QPushButton::clicked, this, &LoginWindow::onOlvidePasswordClicked);
}

void LoginWindow::onLoginClicked() {
    QString username = usernameInput->text().trimmed();
    QString password = passwordInput->text();

    if (username.isEmpty() || password.isEmpty()) {
        statusLabel->setText("Complete todos los campos");
        return;
    }

    loginButton->setEnabled(false);
    statusLabel->setText("Verificando conexión...");

    // Crear conexión con usuario de login
    QSqlDatabase db = createConnection("login_conn", USER_LOGIN, PASS_LOGIN);

    if (!db.open()) {
        statusLabel->setText("Error de conexión");
        QMessageBox::critical(this, "Error", "No se pudo conectar a la base de datos:\n" + db.lastError().text());
        loginButton->setEnabled(true);
        return;
    }

    statusLabel->setText("Conexión OK, verificando usuario...");

    QString passHash = sha256_string(password);

    QSqlQuery query(db);
    query.prepare("SELECT rol FROM usuarios WHERE username = :user AND password_hash = :pass AND activo = TRUE");
    query.bindValue(":user", username);
    query.bindValue(":pass", passHash);

    if (query.exec() && query.next()) {
        QString rol = query.value(0).toString();
        db.close();
        QSqlDatabase::removeDatabase("login_conn");

        if (rol == "admin") {
            statusLabel->setText("Bienvenido, administrador");
            this->hide();
            switchToAdminWindow();
        } else if (rol == "cajero") {
            statusLabel->setText("Bienvenido, cajero");
            this->hide();
            switchToCajeroWindow();
        } else {
            statusLabel->setText("Rol no soportado");
        }
    } else {
        statusLabel->setText("Usuario o contraseña incorrectos");
        passwordInput->clear();
        passwordInput->setFocus();
        db.close();
        QSqlDatabase::removeDatabase("login_conn");
    }

    loginButton->setEnabled(true);
}

void LoginWindow::switchToAdminWindow() {
    QWidget *adminPanel = new QWidget();
    adminPanel->setWindowTitle("Panel de Administrador");
    adminPanel->resize(900, 600);

    QVBoxLayout *mainLayout = new QVBoxLayout();

    // ===== SECCIÓN: CREAR NUEVO CAJERO =====
    QGroupBox *createGroup = new QGroupBox("Crear Nuevo Cajero");
    QFormLayout *formLayout = new QFormLayout();

    QLineEdit *newUsername = new QLineEdit();
    QLineEdit *newPassword = new QLineEdit();
    newPassword->setEchoMode(QLineEdit::Password);
    QLineEdit *confirmPassword = new QLineEdit();
    confirmPassword->setEchoMode(QLineEdit::Password);

    formLayout->addRow("Nombre de usuario:", newUsername);
    formLayout->addRow("Contraseña:", newPassword);
    formLayout->addRow("Confirmar contraseña:", confirmPassword);

    QPushButton *btnCrear = new QPushButton("Crear Cajero");
    btnCrear->setStyleSheet("background-color: #4CAF50; color: white; padding: 8px; font-weight: bold;");
    formLayout->addRow(btnCrear);

    createGroup->setLayout(formLayout);
    mainLayout->addWidget(createGroup);

    // ===== SECCIÓN: LISTA DE CAJEROS =====
    QGroupBox *listGroup = new QGroupBox("Lista de Cajeros");
    QVBoxLayout *listLayout = new QVBoxLayout();

    QTableWidget *tableCajeros = new QTableWidget();
    tableCajeros->setColumnCount(5);
    tableCajeros->setHorizontalHeaderLabels({"ID", "Usuario", "Rol", "Activo", "Fecha Creación"});
    tableCajeros->horizontalHeader()->setStretchLastSection(true);
    tableCajeros->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableCajeros->setEditTriggers(QAbstractItemView::NoEditTriggers);

    listLayout->addWidget(tableCajeros);

    QHBoxLayout *actionLayout = new QHBoxLayout();
    QPushButton *btnRefrescar = new QPushButton("Refrescar");
    QPushButton *btnEliminar = new QPushButton("Eliminar Cajero");
    btnEliminar->setStyleSheet("background-color: #f44336; color: white; padding: 8px; font-weight: bold;");
    QPushButton *btnActivarDesactivar = new QPushButton("Activar/Desactivar");

    actionLayout->addWidget(btnRefrescar);
    actionLayout->addWidget(btnActivarDesactivar);
    actionLayout->addWidget(btnEliminar);
    actionLayout->addStretch();

    listLayout->addLayout(actionLayout);
    listGroup->setLayout(listLayout);
    mainLayout->addWidget(listGroup);

    QPushButton *btnCerrarSesion = new QPushButton("Cerrar Sesión");
    mainLayout->addWidget(btnCerrarSesion);

    adminPanel->setLayout(mainLayout);

    // ===== FUNCIÓN: REFRESCAR TABLA =====
    auto refrescarTabla = [tableCajeros]() {
        QSqlDatabase db = createConnection("admin_refresh", USER_ADMIN, PASS_ADMIN);

        if (!db.open()) {
            QMessageBox::critical(nullptr, "Error", "Error al conectar: " + db.lastError().text());
            return;
        }

        QSqlQuery query("SELECT id, username, rol, activo, fecha_creacion FROM usuarios ORDER BY id DESC", db);

        tableCajeros->setRowCount(0);
        int row = 0;

        while (query.next()) {
            tableCajeros->insertRow(row);
            tableCajeros->setItem(row, 0, new QTableWidgetItem(query.value(0).toString()));
            tableCajeros->setItem(row, 1, new QTableWidgetItem(query.value(1).toString()));
            tableCajeros->setItem(row, 2, new QTableWidgetItem(query.value(2).toString()));
            tableCajeros->setItem(row, 3, new QTableWidgetItem(query.value(3).toBool() ? "Sí" : "No"));
            tableCajeros->setItem(row, 4, new QTableWidgetItem(query.value(4).toString()));
            row++;
        }

        tableCajeros->resizeColumnsToContents();
        db.close();
        QSqlDatabase::removeDatabase("admin_refresh");
    };

    refrescarTabla();

    QObject::connect(btnRefrescar, &QPushButton::clicked, refrescarTabla);

    // Crear cajero
    QObject::connect(btnCrear, &QPushButton::clicked, [newUsername, newPassword, confirmPassword, refrescarTabla]() {
        QString user = newUsername->text().trimmed();
        QString pass = newPassword->text();
        QString confirm = confirmPassword->text();

        if (user.isEmpty() || pass.isEmpty()) {
            QMessageBox::warning(nullptr, "Campos vacíos", "Complete todos los campos");
            return;
        }

        if (pass != confirm) {
            QMessageBox::warning(nullptr, "Error", "Las contraseñas no coinciden");
            return;
        }

        QSqlDatabase db = createConnection("admin_create", USER_ADMIN, PASS_ADMIN);

        if (!db.open()) {
            QMessageBox::critical(nullptr, "Error", "Error al conectar");
            return;
        }

        QString passHash = sha256_string(pass);

        QSqlQuery query(db);
        query.prepare("INSERT INTO usuarios (username, password_hash, rol, activo) VALUES (:user, :pass, 'cajero', TRUE)");
        query.bindValue(":user", user);
        query.bindValue(":pass", passHash);

        if (query.exec()) {
            QMessageBox::information(nullptr, "Éxito", "Cajero creado correctamente");
            newUsername->clear();
            newPassword->clear();
            confirmPassword->clear();
            refrescarTabla();
        } else {
            QString error = query.lastError().text();
            if (error.contains("Duplicate entry")) {
                QMessageBox::critical(nullptr, "Error", "El nombre de usuario ya existe");
            } else {
                QMessageBox::critical(nullptr, "Error", "Error al crear cajero: " + error);
            }
        }

        db.close();
        QSqlDatabase::removeDatabase("admin_create");
    });

    // Eliminar cajero
    QObject::connect(btnEliminar, &QPushButton::clicked, [tableCajeros, refrescarTabla]() {
        int row = tableCajeros->currentRow();
        if (row < 0) {
            QMessageBox::warning(nullptr, "Selección", "Seleccione un cajero para eliminar");
            return;
        }

        int userId = tableCajeros->item(row, 0)->text().toInt();
        QString username = tableCajeros->item(row, 1)->text();
        QString rol = tableCajeros->item(row, 2)->text();

        if (rol == "admin") {
            QMessageBox::warning(nullptr, "Operación no permitida", "No se puede eliminar un administrador");
            return;
        }

        auto reply = QMessageBox::question(nullptr, "Confirmar eliminación",
            QString("¿Está seguro de eliminar al cajero '%1'?").arg(username),
            QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            QSqlDatabase db = createConnection("admin_delete", USER_ADMIN, PASS_ADMIN);

            if (!db.open()) {
                QMessageBox::critical(nullptr, "Error", "Error al conectar");
                return;
            }

            QSqlQuery query(db);
            query.prepare("DELETE FROM usuarios WHERE id = :id");
            query.bindValue(":id", userId);

            if (query.exec()) {
                QMessageBox::information(nullptr, "Éxito", "Cajero eliminado correctamente");
                refrescarTabla();
            } else {
                QMessageBox::critical(nullptr, "Error", "Error al eliminar: " + query.lastError().text());
            }

            db.close();
            QSqlDatabase::removeDatabase("admin_delete");
        }
    });

    // Activar/Desactivar cajero
    QObject::connect(btnActivarDesactivar, &QPushButton::clicked, [tableCajeros, refrescarTabla]() {
        int row = tableCajeros->currentRow();
        if (row < 0) {
            QMessageBox::warning(nullptr, "Selección", "Seleccione un cajero");
            return;
        }

        int userId = tableCajeros->item(row, 0)->text().toInt();
        QString username = tableCajeros->item(row, 1)->text();
        QString activo = tableCajeros->item(row, 3)->text();
        QString rol = tableCajeros->item(row, 2)->text();

        if (rol == "admin") {
            QMessageBox::warning(nullptr, "Operación no permitida", "No se puede desactivar un administrador");
            return;
        }

        bool esActivo = (activo == "Sí");
        QString accion = esActivo ? "desactivar" : "activar";

        auto reply = QMessageBox::question(nullptr, "Confirmar",
            QString("¿Desea %1 al cajero '%2'?").arg(accion, username),
            QMessageBox::Yes | QMessageBox::No);

        if (reply == QMessageBox::Yes) {
            QSqlDatabase db = createConnection("admin_toggle", USER_ADMIN, PASS_ADMIN);

            if (!db.open()) {
                QMessageBox::critical(nullptr, "Error", "Error al conectar");
                return;
            }

            QSqlQuery query(db);
            query.prepare("UPDATE usuarios SET activo = :activo WHERE id = :id");
            query.bindValue(":activo", !esActivo);
            query.bindValue(":id", userId);

            if (query.exec()) {
                QMessageBox::information(nullptr, "Éxito",
                    QString("Cajero %1 correctamente").arg(esActivo ? "desactivado" : "activado"));
                refrescarTabla();
            } else {
                QMessageBox::critical(nullptr, "Error", "Error: " + query.lastError().text());
            }

            db.close();
            QSqlDatabase::removeDatabase("admin_toggle");
        }
    });

    // Cerrar sesión
    QObject::connect(btnCerrarSesion, &QPushButton::clicked, [this, adminPanel]() {
        adminPanel->close();
        this->show();
        this->usernameInput->clear();
        this->passwordInput->clear();
        this->statusLabel->clear();
    });

    adminPanel->show();
}

void LoginWindow::switchToCajeroWindow() {
    QWidget *cajeroPanel = new QWidget();
    cajeroPanel->setWindowTitle("Panel de Cajero");
    cajeroPanel->resize(600, 400);

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(new QLabel("Panel de cajero"));
    layout->addWidget(new QLabel("Funcionalidad próximamente..."));

    QPushButton *btnCerrar = new QPushButton("Cerrar Sesión");
    layout->addWidget(btnCerrar);

    cajeroPanel->setLayout(layout);

    QObject::connect(btnCerrar, &QPushButton::clicked, [this, cajeroPanel]() {
        cajeroPanel->close();
        this->show();
        this->usernameInput->clear();
        this->passwordInput->clear();
        this->statusLabel->clear();
    });

    cajeroPanel->show();
}

void LoginWindow::onCambiarPasswordClicked() {
    QDialog *cambiarPassDialog = new QDialog(this);
    cambiarPassDialog->setWindowTitle("Cambiar Contraseña");
    cambiarPassDialog->setModal(true);
    cambiarPassDialog->resize(400, 250);

    QVBoxLayout *mainLayout = new QVBoxLayout();
    QFormLayout *formLayout = new QFormLayout();

    QLineEdit *inputUsuario = new QLineEdit();
    QLineEdit *inputPassActual = new QLineEdit();
    inputPassActual->setEchoMode(QLineEdit::Password);
    QLineEdit *inputPassNueva = new QLineEdit();
    inputPassNueva->setEchoMode(QLineEdit::Password);
    QLineEdit *inputConfirmarNueva = new QLineEdit();
    inputConfirmarNueva->setEchoMode(QLineEdit::Password);

    formLayout->addRow("Usuario:", inputUsuario);
    formLayout->addRow("Contraseña actual:", inputPassActual);
    formLayout->addRow("Nueva contraseña:", inputPassNueva);
    formLayout->addRow("Confirmar nueva:", inputConfirmarNueva);

    mainLayout->addLayout(formLayout);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *btnCambiar = new QPushButton("Cambiar");
    QPushButton *btnCancelar = new QPushButton("Cancelar");
    btnCambiar->setStyleSheet("background-color: #1976D2; color: white; padding: 8px; font-weight: bold;");

    buttonLayout->addWidget(btnCambiar);
    buttonLayout->addWidget(btnCancelar);
    mainLayout->addLayout(buttonLayout);

    cambiarPassDialog->setLayout(mainLayout);

    connect(btnCancelar, &QPushButton::clicked, cambiarPassDialog, &QDialog::reject);

    connect(btnCambiar, &QPushButton::clicked, [=]() {
        QString usuario = inputUsuario->text().trimmed();
        QString passActual = inputPassActual->text();
        QString passNueva = inputPassNueva->text();
        QString confirmarNueva = inputConfirmarNueva->text();

        if (usuario.isEmpty() || passActual.isEmpty() || passNueva.isEmpty() || confirmarNueva.isEmpty()) {
            QMessageBox::warning(cambiarPassDialog, "Campos vacíos", "Complete todos los campos");
            return;
        }

        if (passNueva != confirmarNueva) {
            QMessageBox::warning(cambiarPassDialog, "Error", "Las contraseñas nuevas no coinciden");
            return;
        }

        if (passNueva.length() < 3) {
            QMessageBox::warning(cambiarPassDialog, "", "La nueva contraseña debe tener al menos 3 caracteres");
            return;
        }

        if (passActual == passNueva) {
            QMessageBox::warning(cambiarPassDialog, "Error", "La nueva contraseña debe ser diferente a la actual");
            return;
        }

        QSqlDatabase db = createConnection("change_pass_verify", USER_LOGIN, PASS_LOGIN);

        if (!db.open()) {
            QMessageBox::critical(cambiarPassDialog, "Error", "Error de conexión");
            return;
        }

        QString hashActual = sha256_string(passActual);

        QSqlQuery query(db);
        query.prepare("SELECT id FROM usuarios WHERE username = :user AND password_hash = :pass AND activo = TRUE");
        query.bindValue(":user", usuario);
        query.bindValue(":pass", hashActual);

        if (!query.exec() || !query.next()) {
            QMessageBox::critical(cambiarPassDialog, "Error", "Usuario o contraseña actual incorrectos");
            db.close();
            QSqlDatabase::removeDatabase("change_pass_verify");
            return;
        }

        int userId = query.value(0).toInt();
        db.close();
        QSqlDatabase::removeDatabase("change_pass_verify");

        // Actualizar con admin
        QSqlDatabase adminDb = createConnection("change_pass_update", USER_ADMIN, PASS_ADMIN);

        if (!adminDb.open()) {
            QMessageBox::critical(cambiarPassDialog, "Error", "Error de conexión");
            return;
        }

        QString hashNueva = sha256_string(passNueva);

        QSqlQuery updateQuery(adminDb);
        updateQuery.prepare("UPDATE usuarios SET password_hash = :pass WHERE id = :id");
        updateQuery.bindValue(":pass", hashNueva);
        updateQuery.bindValue(":id", userId);

        if (updateQuery.exec()) {
            QMessageBox::information(cambiarPassDialog, "Éxito", "Contraseña cambiada correctamente");
            cambiarPassDialog->accept();
        } else {
            QMessageBox::critical(cambiarPassDialog, "Error", "Error al cambiar contraseña: " + updateQuery.lastError().text());
        }

        adminDb.close();
        QSqlDatabase::removeDatabase("change_pass_update");
    });

    cambiarPassDialog->exec();
}

void LoginWindow::onOlvidePasswordClicked() {
    QMessageBox::information(this, "Recuperar Contraseña",
        "Funcionalidad de recuperación de contraseña próximamente...");
}