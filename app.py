from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_bcrypt import Bcrypt
from config import Config
from models import db, User,Tutoria  # Importa db y User, Tutoria

app = Flask(__name__)
app.config.from_object(Config)  # Carga la configuración desde el objeto Config
db.init_app(app)  # Inicializa la base de datos con la app
bcrypt = Bcrypt(app)  # Inicializa Flask-Bcrypt para manejar el hash de contraseñas

# Define la función para verificar si el código de tutoría existe
def codigo_tutoria_existe(codigo, tutoria_id=None):
    query = Tutoria.query.filter_by(codigo=codigo)
    if tutoria_id:
        query = query.filter(Tutoria.id != tutoria_id)  # Excluye la tutoría que se está editando
    return query.first() is not None

@app.route('/')
def home():
    # Si el usuario ya ha iniciado sesión, redirigir al dashboard según el rol
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('dashboard'))
        elif role == 'teacher':
            return redirect(url_for('dashboard'))
        elif role == 'student':
            return redirect(url_for('dashboard'))
    # Si no ha iniciado sesión, redirigir a la página de login
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya ha iniciado sesión, redirige al dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    # Manejo de la lógica de inicio de sesión
    if request.method == 'POST':
        username = request.form['username'].strip()  # Eliminamos espacios innecesarios
        password = request.form['password']
        user = User.query.filter(User.username.ilike(username)).first()  # Utiliza ilike para la búsqueda

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login exitoso', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales incorrectas', 'danger')

    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    # Manejo del registro de nuevos usuarios
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Obtiene el rol del formulario
        identificacion = request.form['identificacion']  # Obtiene la identificación
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash de la contraseña
        
        # Verifica si el nombre de usuario o la identificación ya existen
        existing_user = User.query.filter(
            (User.username.ilike(username)) | (User.identificacion == identificacion)
        ).first()

        if existing_user:
            # Comprobar si el nombre de usuario ya existe (esto se hace en la consulta)
            if existing_user.username.lower() == username.lower():  # Comparación sin distinción de mayúsculas
                flash('El nombre de usuario ya está en uso. Elige otro.', 'danger')
            # Comprobar si la identificación ya existe
            if existing_user.identificacion == identificacion:
                flash('La identificación ya está registrada. Elige otra.', 'danger')
            return redirect(url_for('register'))  # Redirige si ya existe el usuario

        # Si el nombre de usuario y la identificación son únicos, crea el nuevo usuario
        new_user = User(username=username, password=hashed_password, role=role, identificacion=identificacion)
        db.session.add(new_user)  # Agrega el nuevo usuario a la sesión
        db.session.commit()  # Guarda los cambios en la base de datos
        flash('Registro exitoso', 'success')  # Mensaje de éxito
        return redirect(url_for('login'))  # Redirige a la página de inicio de sesión

    return render_template('register.html')  # Renderiza la plantilla de registro


@app.route('/dashboard')
def dashboard():
    # endpoint Muestra el panel de control del usuario
    if 'username' in session:
        user = db.session.get(User, session['user_id'])
  # Obtiene el usuario de la base de datos
        return render_template('dashboard.html', username=session['username'], role=session['role'], user=user)  # Pasa el usuario a la plantilla
    flash('Debes iniciar sesión primero', 'danger')  # Mensaje de error si no hay sesión
    return redirect(url_for('login'))  # Redirige a la página de inicio de sesión

@app.route('/logout')
def logout():
    # endpoint Maneja el cierre de sesión
    session.clear()  # Limpia la sesión
    flash('Has cerrado sesión', 'success')  # Mensaje de éxito
    return redirect(url_for('login'))  # Redirige a la página de inicio de sesión

@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session['role'] != 'admin':
        flash('Acceso denegado. Solo los administradores pueden acceder a esta sección.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()  # Obtiene todos los usuarios

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'delete':
            if int(user_id) == session['user_id']:
                flash('No puedes eliminar tu propio usuario.', 'danger')
            else:
                user_to_delete = User.query.get(user_id)
                # Verificar si el usuario tiene tutorías asociadas
                if user_to_delete and user_to_delete.tutorias:  # verifica relación del usuario existente con tutorías asociadas
                    flash('No se puede eliminar el usuario porque tiene tutorías asociadas.', 'danger')
                elif user_to_delete:
                    db.session.delete(user_to_delete)
                    db.session.commit()
                    flash('Usuario eliminado exitosamente.', 'success')
                else:
                    flash('Usuario no encontrado.', 'danger')

            # Añadimos redirección para que la página se recargue tras eliminar o editar un usuario
            return redirect(url_for('manage_users'))

    return render_template('manage_users.html', users=users)



@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('manage_users'))

    current_user_id = session['user_id']

    if request.method == 'POST':
        username = request.form['username']
        identificacion = request.form['identificacion']
        role = request.form['role']
        new_password = request.form['password']  # Nueva contraseña desde el formulario

        if user_id == current_user_id:
            if role != user.role:
                flash('No puedes cambiar tu propio rol.', 'warning')
                return redirect(url_for('edit_user', user_id=user_id))

        existing_user = User.query.filter(
            ((User.username == username) | (User.identificacion == identificacion)) &
            (User.id != user_id)
        ).first()

        if existing_user:
            if existing_user.username == username:
                flash('El nombre de usuario ya está en uso. Elige otro.', 'danger')
            if existing_user.identificacion == identificacion:
                flash('La identificación ya está registrada. Elige otra.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        user.username = username
        user.identificacion = identificacion
        if user_id != current_user_id:
            user.role = role

        # Actualiza la contraseña solo si se proporciona una nueva
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password

        db.session.commit()
        flash('Usuario actualizado exitosamente.', 'success')
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/admin/tutorias', methods=['GET', 'POST'])
def manage_tutorias():
    if 'username' not in session or session['role'] != 'admin':
        flash('Acceso denegado. Solo los administradores pueden acceder a esta sección.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        codigo = request.form['codigo']
        espacio_academico = request.form['espacio_academico']
        docente_id = request.form['docente']

        if codigo_tutoria_existe(codigo):
            flash('El código de la tutoría ya existe. Por favor, usa uno diferente.', 'danger')
            return redirect(url_for('manage_tutorias'))

        new_tutoria = Tutoria(codigo=codigo, espacio_academico=espacio_academico, docente_id=docente_id)
        db.session.add(new_tutoria)
        db.session.commit()
        flash('Tutoría creada exitosamente.', 'success')
        return redirect(url_for('manage_tutorias'))

    docentes = User.query.filter_by(role='teacher').all()
    tutorias = Tutoria.query.all()
    return render_template('manage_tutorias.html', tutorias=tutorias, docentes=docentes)


@app.route('/admin/tutorias/delete/<int:tutoria_id>', methods=['POST'])
def delete_tutoria(tutoria_id):
    if 'username' not in session or session['role'] != 'admin':
        flash('Acceso denegado. Solo los administradores pueden acceder a esta sección.', 'danger')
        return redirect(url_for('dashboard'))

    tutoria_to_delete = Tutoria.query.get(tutoria_id)
    if tutoria_to_delete:
        db.session.delete(tutoria_to_delete)
        db.session.commit()
        flash('Tutoría eliminada exitosamente.', 'success')
    else:
        flash('Tutoría no encontrada.', 'danger')
    
    return redirect(url_for('manage_tutorias'))

@app.route('/admin/tutorias/edit/<int:tutoria_id>', methods=['GET', 'POST'])
def edit_tutoria(tutoria_id):
    if 'username' not in session or session['role'] != 'admin':
        flash('Acceso denegado. Solo los administradores pueden acceder a esta sección.', 'danger')
        return redirect(url_for('dashboard'))

    tutoria_to_edit = Tutoria.query.get(tutoria_id)
    if not tutoria_to_edit:
        flash('Tutoría no encontrada.', 'danger')
        return redirect(url_for('manage_tutorias'))

    if request.method == 'POST':
        codigo = request.form['codigo']
        espacio_academico = request.form['espacio_academico']
        docente_id = request.form['docente']

        if codigo_tutoria_existe(codigo, tutoria_id):
            flash('El código de la tutoría ya existe. Por favor, usa uno diferente.', 'danger')
            return redirect(url_for('edit_tutoria', tutoria_id=tutoria_id))

        tutoria_to_edit.codigo = codigo
        tutoria_to_edit.espacio_academico = espacio_academico
        tutoria_to_edit.docente_id = docente_id
        db.session.commit()
        flash('Tutoría editada exitosamente.', 'success')
        return redirect(url_for('manage_tutorias'))

    docentes = User.query.filter_by(role='teacher').all()
    return render_template('edit_tutoria.html', tutoria=tutoria_to_edit, docentes=docentes)


@app.route('/profile/edit', methods=['GET', 'POST']) 
def edit_profile():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero', 'danger')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        flash('Usuario no encontrado.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username'].strip()  # Eliminamos espacios innecesarios
        identificacion = request.form['identificacion'].strip()  # Eliminamos espacios innecesarios
        new_password = request.form['password']

        # Verifica si el nuevo username o identificacion ya existen en otros usuarios
        existing_user = User.query.filter(
            ((User.username.ilike(username)) | (User.identificacion == identificacion)) &  # Usamos ilike para comparación insensible a mayúsculas
            (User.id != user.id)
        ).first()

        if existing_user:
            if existing_user.username.lower() == username.lower():  # Comparar en minúsculas
                flash('El nombre de usuario ya está en uso. Elige otro.', 'danger')
            if existing_user.identificacion == identificacion:
                flash('La identificación ya está registrada. Elige otra.', 'danger')
            return redirect(url_for('edit_profile'))  # Evita guardar si hay conflicto

        # Actualiza el perfil del usuario con los datos proporcionados
        user.username = username
        user.identificacion = identificacion

        # Actualiza la contraseña solo si se proporciona una nueva
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password

        db.session.commit()
        flash('Perfil actualizado exitosamente.', 'success')
        return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)  # Inicia la aplicación en modo debug
