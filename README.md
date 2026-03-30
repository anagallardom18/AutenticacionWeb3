# AutenticacionWeb

Aplicación de inicio de sesión multifactor  

Permite:
- Iniciar sesión con contraseña.  
- Recuperar contraseña olvidada.  
- Iniciar sesión con TOTP (códigos de un solo uso).  
- Iniciar sesión mediante un dispositivo USB (FIDO2).
- Iniciar sesión mediante Passkeys.
- Iniciar sesión mediante biometría.
- Registrar nuevos usuarios y nuevos dispositivos/credenciales.  
- Aplicar un segundo factor de autenticación mediante un código OTP enviado por correo electrónico (Se puede desactivar si se usa el login1fa)
- Restringir el acceso según la ubicación del usuario, permitiendo que las contraseñas puedan ser sencillas gracias a otros factores de seguridad.

---

## Tecnologías y librerías utilizadas

- **Java**  
- **Eclipse** (IDE)  
- **Maven** (gestor de dependencias y compilación)  
- **Servlets**  
- **MySQL** (base de datos)  
- **Gson** (para JSON)  
- **ZXing** (códigos QR)  
- **Jakarta Mail** (envío de correos)   
- **FIDO2 / Passkeys**  

## Base de datos

La aplicación utiliza una base de datos MySQL llamada:

autenticacion_db

El esquema de la base de datos se encuentra en:

src/database/schema.sql

Este archivo permite crear automáticamente las tablas necesarias para ejecutar la aplicación.

## Ejecución del proyecto

Clonar el repositorio

Importar el proyecto en Eclipse como proyecto Maven

Configurar un servidor Apache Tomcat

Ejecutar el proyecto en el servidor

La aplicación estará disponible normalmente en:

http://localhost:8080/AutenticacionWeb2/

## Estructura del proyecto:

src/main/java/autenticacion
Código fuente de la aplicación

src/main/webapp
Archivos web (JSP,CSS)

src/database
Esquema de la base de datos

pom.xml
Gestión de dependencias mediante Maven



