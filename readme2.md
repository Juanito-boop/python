CREATE TABLE tutoria (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(20) NOT NULL UNIQUE,  -- Código único para la tutoría
    espacio_academico VARCHAR(100) NOT NULL,
    docente_id INT,
    FOREIGN KEY (docente_id) REFERENCES user(id)  -- Relación con la tabla user
);



pip install Flask
pip install Flask-Bcrypt
pip install Flask-SQLAlchemy
pip install Flask-Session

# contexto de los paquetes:

Flask: Este es el framework para construir la aplicación web.
Flask-Bcrypt: Esta extensión proporciona hashing de contraseñas utilizando Bcrypt.
Flask-SQLAlchemy: Este es un ORM (Object Relational Mapper) que facilita la interacción con bases de datos SQL.
Flask-Session: Esta extensión permite gestionar sesiones en la aplicación Flask.

# relación de endpoints:

/: Redirige al usuario a la página de inicio de sesión o al panel de control según su rol si ya está autenticado.

/login: Maneja el inicio de sesión de usuarios. Si se envían credenciales válidas, redirige al panel de control; si no, muestra un mensaje de error.

/register: Permite a nuevos usuarios registrarse. Verifica la unicidad del nombre de usuario y la identificación antes de crear un nuevo usuario.

/dashboard: Muestra el panel de control del usuario. Requiere que el usuario esté autenticado.

/logout: Cierra la sesión del usuario y redirige a la página de inicio de sesión.

/admin/users: Permite a los administradores gestionar usuarios (ver, eliminar). Solo accesible para usuarios con rol de administrador.

/admin/users/edit/<int:user_id>: Permite a los administradores editar la información de un usuario específico.

/admin/tutorias: Permite a los administradores gestionar tutorías (crear, listar). Solo accesible para usuarios con rol de administrador.

/admin/tutorias/delete/<int:tutoria_id>: Elimina una tutoría específica. Solo accesible para usuarios con rol de administrador.

/admin/tutorias/edit/<int:tutoria_id>: Permite a los administradores editar los detalles de una tutoría específica.

/profile/edit: Permite a los usuarios editar su perfil (nombre de usuario, identificación, contraseña). Requiere autenticación.