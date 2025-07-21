// -------------------------------------------------------------
// Autor: [JORDYS]
// Fecha: 21/07/2025
// Descripción: Sistema de gestión de usuarios en C++
// Derechos reservados © [JORDYS]
// -------------------------------------------------------------

#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iomanip>
#include <random>


using namespace std;

// Enumeracion para los niveles de acceso
enum class AccessLevel { ADMIN, USER, GUEST };

// Estructura para almacenar datos de usuario
struct User {
    string username;
    string salt;  // Salt en Base64
    string hash;  // Hash de la contrasena en Base64
    AccessLevel level;
};

// Estructura para el registro de accesos
struct AccessLog {
    string username;
    string timestamp;
    bool success;
};

// Funcion para obtener la fecha y hora actual como string
string getCurrentTimestamp() {
    time_t now = time(nullptr);
    string timestamp = ctime(&now);
    timestamp.pop_back(); // Eliminar salto de linea
    return timestamp;
}

// Funcion para verificar si la contrasena es debil
bool isWeakPassword(const string& password) {
    if (password.length() < 8) return true;
    bool hasUpper = false, hasLower = false, hasDigit = false;
    for (char c : password) {
        if (isupper(c)) hasUpper = true;
        else if (islower(c)) hasLower = true;
        else if (isdigit(c)) hasDigit = true;
    }
    return !(hasUpper && hasLower && hasDigit);
}

// Funcion para convertir un hash binario a Base64
string toBase64(const unsigned char* data, size_t length) {
    static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string result;
    size_t i = 0;
    while (i < length) {
        unsigned char octet_a = i < length ? data[i++] : 0;
        unsigned char octet_b = i < length ? data[i++] : 0;
        unsigned char octet_c = i < length ? data[i++] : 0;

        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        result += base64_chars[(triple >> 18) & 63];
        result += base64_chars[(triple >> 12) & 63];
        result += (i - 1 < length) ? base64_chars[(triple >> 6) & 63] : '=';
        result += (i < length) ? base64_chars[triple & 63] : '=';
    }
    return result;
}

// Funcion para generar un salt aleatorio
string generateSalt(size_t length = 16) {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    string salt;
    for (size_t i = 0; i < length; ++i) {
        salt += charset[dist(rng)];
    }
    return salt;
}

// Funcion para verificar si el usuario ya existe
bool userExists(const vector<User>& users, const string& username) {
    for (const auto& user : users) {
        if (user.username == username) return true;
    }
    return false;
}

// Funcion para hashear la contrasena usando SHA-256 y salt
string hashPassword(const string& password, const string& salt) {
    // Hash simple solo para pruebas (NO USAR EN PRODUCCIÓN)
    std::hash<string> hasher;
    size_t hashed = hasher(password + salt);
    stringstream ss;
    ss << hex << hashed;
    return ss.str();
}

// Funcion para guardar usuarios en un archivo
void saveUsers(const vector<User>& users) {
    ofstream file("users.txt");
    if (!file.is_open()) {
        cout << "Error: No se pudo abrir users.txt para escritura. Verifique los permisos del directorio.\n";
        return;
    }
    for (const auto& user : users) {
        string level;
        switch (user.level) {
            case AccessLevel::ADMIN: level = "ADMIN"; break;
            case AccessLevel::USER: level = "USER"; break;
            case AccessLevel::GUEST: level = "GUEST"; break;
        }
    
        file << user.username << "," << user.salt << "," << user.hash << "," << level << "\n";
    }
    file.close();
}

// Funcion para cargar usuarios desde un archivo
void loadUsers(vector<User>& users) {
    ifstream file("users.txt");
    if (!file.is_open()) {
        cout << "No se encontro users.txt. Iniciando con lista vacia.\n";
        return;
    }
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string username, salt, hash, levelStr;
        getline(ss, username, ',');
        getline(ss, salt, ',');
        getline(ss, hash, ',');
        getline(ss, levelStr, ',');
        AccessLevel level;
        if (levelStr == "ADMIN") level = AccessLevel::ADMIN;
        else if (levelStr == "USER") level = AccessLevel::USER;
        else if (levelStr == "GUEST") level = AccessLevel::GUEST;
        else {
            cout << "Advertencia: Linea invalida en users.txt: " << line << "\n";
            continue;
        }
        users.push_back({username, salt, hash, level});
    }
    file.close();
}

// Funcion para guardar registros de acceso en un archivo
void saveAccessLogs(const vector<AccessLog>& logs) {
    ofstream file("access_logs.txt");
    if (!file.is_open()) {
        cout << "Error: No se pudo abrir access_logs.txt para escritura. Verifique los permisos del directorio.\n";
        return;
    }
    for (const auto& log : logs) {
        file << log.username << "," << log.timestamp << "," << (log.success ? "true" : "false") << "\n";
    }
    file.close();
}

// Funcion para cargar registros de acceso desde un archivo
void loadAccessLogs(vector<AccessLog>& logs) {
    ifstream file("access_logs.txt");
    if (!file.is_open()) {
        cout << "No se encontro access_logs.txt. Iniciando con lista vacia.\n";
        return;
    }
    string line;
    while (getline(file, line)) {
        stringstream ss(line);
        string username, timestamp, successStr;
        getline(ss, username, ',');
        getline(ss, timestamp, ',');
        getline(ss, successStr, ',');
        bool success = (successStr == "true");
        logs.push_back({username, timestamp, success});
    }
    file.close();
}

// Funcion para registrar un nuevo usuario
void registerUser(vector<User>& users, vector<AccessLog>& logs) {
    string username, password;
    int levelChoice;
    AccessLevel level;

    cout << "\n--- Registro de Usuario ---\n";
    cout << "Ingrese nombre de usuario: ";
    cin >> username;

    if (userExists(users, username)) {
        cout << "El usuario ya existe. Intente con otro nombre.\n";
        logs.push_back({username, getCurrentTimestamp(), false});
        saveAccessLogs(logs);
        return;
    }

    cout << "Ingrese contrasena: ";
    cin >> password;

    if (isWeakPassword(password)) {
        cout << "La contrasena es debil. Debe tener al menos 8 caracteres, incluyendo mayusculas, minusculas y numeros.\n";
        cout << "Desea continuar con esta contrasena? (s/n): ";
        char choice;
        cin >> choice;
        if (tolower(choice) != 's') {
            cout << "Registro cancelado.\n";
            return;
        }
    }

    string salt = generateSalt();
    if (salt.empty()) {
        cout << "Error al registrar usuario debido a fallo en la generacion del salt.\n";
        logs.push_back({username, getCurrentTimestamp(), false});
        saveAccessLogs(logs);
        return;
    }
    string hash = hashPassword(password, salt);

    cout << "Seleccione nivel de acceso (1: Administrador, 2: Usuario, 3: Invitado): ";
    cin >> levelChoice;
    switch (levelChoice) {
        case 1: level = AccessLevel::ADMIN; break;
        case 2: level = AccessLevel::USER; break;
        case 3: level = AccessLevel::GUEST; break;
        default:
            cout << "Opcion invalida. Registro cancelado.\n";
            return;
    }

    users.push_back({username, salt, hash, level});
    logs.push_back({username, getCurrentTimestamp(), true});
    saveUsers(users);
    saveAccessLogs(logs);
    cout << "Usuario registrado correctamente.\n";
}

// Funcion para iniciar sesion
bool login(const vector<User>& users, vector<AccessLog>& logs, User& currentUser, int& attempts) {
    string username, password;
    cout << "\n--- Inicio de Sesion ---\n";
    cout << "Ingrese nombre de usuario: ";
    cin >> username;
    cout << "Ingrese contrasena: ";
    cin >> password;

    for (const auto& user : users) {
        if (user.username == username) {
            string hash = hashPassword(password, user.salt);
            if (hash == user.hash) {
                currentUser = user;
                logs.push_back({username, getCurrentTimestamp(), true});
                saveAccessLogs(logs);
                attempts = 0; // Reiniciar intentos
                return true;
            }
        }
    }

    logs.push_back({username, getCurrentTimestamp(), false});
    saveAccessLogs(logs);
    attempts++;
    cout << "Nombre de usuario o contrasena incorrectos. Intentos restantes: " << (3 - attempts) << "\n";
    return false;
}

// Funcion para mostrar el perfil del usuario
void showProfile(const User& user) {
    cout << "\n--- Perfil de Usuario ---\n";
    cout << "Nombre de usuario: " << user.username << "\n";
    cout << "Nivel de acceso: ";
    switch (user.level) {
        case AccessLevel::ADMIN: cout << "Administrador\n"; break;
        case AccessLevel::USER: cout << "Usuario\n"; break;
        case AccessLevel::GUEST: cout << "Invitado\n"; break;
    }
}

// Funcion para mostrar todos los usuarios (solo para admin)
void showAllUsers(const vector<User>& users) {
    cout << "\n--- Lista de Usuarios ---\n";
    for (const auto& user : users) {
        cout << "Usuario: " << user.username << ", Nivel: ";
        switch (user.level) {
            case AccessLevel::ADMIN: cout << "Administrador\n"; break;
            case AccessLevel::USER: cout << "Usuario\n"; break;
            case AccessLevel::GUEST: cout << "Invitado\n"; break;
        }
    }
}

// Funcion para mostrar el registro de accesos (solo para admin)
void showAccessLogs(const vector<AccessLog>& logs) {
    cout << "\n--- Registro de Accesos ---\n";
    for (const auto& log : logs) {
        cout << "Usuario: " << log.username << ", Fecha/Hora: " << log.timestamp 
             << ", Exito: " << (log.success ? "Si" : "No") << "\n";
    }
}

// Funcion para editar el nivel de acceso de un usuario (solo admin)
void editUserAccessLevel(vector<User>& users) {
    string username;
    cout << "\n--- Editar Nivel de Acceso ---\n";
    cout << "Ingrese el nombre de usuario a modificar: ";
    cin >> username;

    for (auto& user : users) {
        if (user.username == username) {
            cout << "Nivel actual: ";
            switch (user.level) {
                case AccessLevel::ADMIN: cout << "Administrador\n"; break;
                case AccessLevel::USER: cout << "Usuario\n"; break;
                case AccessLevel::GUEST: cout << "Invitado\n"; break;
            }
            cout << "Seleccione nuevo nivel (1: Administrador, 2: Usuario, 3: Invitado): ";
            int newLevel;
            cin >> newLevel;

            // Solo permitir cambios válidos
            if (user.level == AccessLevel::USER && newLevel == 1) {
                user.level = AccessLevel::ADMIN;
                cout << "Nivel cambiado a Administrador.\n";
            } else if (user.level == AccessLevel::GUEST && newLevel == 2) {
                user.level = AccessLevel::USER;
                cout << "Nivel cambiado a Usuario.\n";
            } else {
                cout << "Cambio no permitido. Solo puede cambiar de Usuario a Administrador o de Invitado a Usuario.\n";
            }
            saveUsers(users);
            return;
        }
    }
    cout << "Usuario no encontrado.\n";
}

// Funcion para mostrar el menu segun el nivel de acceso
void showMenu(const User& user, vector<User>& users, const vector<AccessLog>& logs) {
    if (user.level == AccessLevel::GUEST) {
        cout << "\nBienvenido, invitado! Gracias por visitar nuestro sistema.\n";
        return;
    }

    while (true) {
        cout << "\n--- Menu ---\n";
        cout << "1. Ver perfil\n";
        if (user.level == AccessLevel::ADMIN) {
            cout << "2. Ver todos los usuarios\n";
            cout << "3. Ver registro de accesos\n";
            cout << "4. Editar nivel de acceso de un usuario\n";
            cout << "5. Salir\n";
        } else {
            cout << "2. Salir\n";
        }

        int choice;
        cout << "Seleccione una opcion: ";
        cin >> choice;

        if (user.level == AccessLevel::ADMIN) {
            if (choice == 1) showProfile(user);
            else if (choice == 2) showAllUsers(users);
            else if (choice == 3) showAccessLogs(logs);
            else if (choice == 4) editUserAccessLevel(users);
            else if (choice == 5) break;
            else cout << "Opcion invalida.\n";
        } else {
            if (choice == 1) showProfile(user);
            else if (choice == 2) break;
            else cout << "Opcion invalida.\n";
        }
    }
}

// Funcion principal
int main() {
    system("chcp 65001"); // Cambia la consola a UTF-8
    setlocale(LC_ALL, ""); // Usa el locale del sistema

    vector<User> users;
    vector<AccessLog> logs;
    int attempts = 0;
    const int maxAttempts = 3;

    // Cargar datos al iniciar el programa
    loadUsers(users);
    loadAccessLogs(logs);

    while (true) {
        cout << "\n--- Sistema de Gestion de Usuarios ---\n";
        cout << "1. Registrarse\n";
        cout << "2. Iniciar sesion\n";
        cout << "3. Salir\n";
        cout << "Seleccione una opcion: ";

        int choice;
        cin >> choice;

        if (choice == 1) {
            registerUser(users, logs);
        } else if (choice == 2) {
            if (attempts >= maxAttempts) {
                cout << "Demasiados intentos fallidos. Sistema bloqueado.\n";
                break;
            }
            User currentUser;
            if (login(users, logs, currentUser, attempts)) {
                showMenu(currentUser, users, logs);
            }
        } else if (choice == 3) {
            cout << "Saliendo del sistema.\n";
            break;
        } else {
            cout << "Opcion invalida.\n";
        }
    }

    return 0;
}
