from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json
import random
from sqlalchemy import or_
from dotenv import load_dotenv
import os

# 1. Configuración de la App
load_dotenv()

app = Flask(__name__)

# Configuración segura desde variables de entorno
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_host = os.getenv('DB_HOST')
db_port = os.getenv('DB_PORT')
db_name = os.getenv('DB_NAME')

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Cargar el cerebro conversacional del chatbot
try:
    with open('chatbot_data.json', 'r', encoding='utf-8') as file:
        chatbot_data = json.load(file)
except FileNotFoundError:
    chatbot_data = {"intents": []}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))

# 2. Modelos de Base de Datos (Adaptados a tu schema)
class Usuario(UserMixin, db.Model):
    __tablename__ = 'usuarios'
    
    id = db.Column('id_usuario', db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.utcnow)
    conversaciones = db.relationship('Conversacion', backref='usuario', lazy=True)

    def __init__(self, nombre: str, email: str, password: str):
        self.nombre = nombre
        self.email = email
        self.set_password(password)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Autor(db.Model):
    __tablename__ = 'autores'
    id = db.Column('id_autor', db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    nacionalidad = db.Column(db.String(50))
    libros = db.relationship('Libro', backref='autor', lazy=True)

class Libro(db.Model):
    __tablename__ = 'libros'
    id = db.Column('id_libro', db.Integer, primary_key=True)
    titulo = db.Column(db.String(200))
    descripcion = db.Column(db.Text)
    id_autor = db.Column(db.Integer, db.ForeignKey('autores.id_autor'))
    tema = db.Column(db.String(100))
    disponible = db.Column(db.Boolean, default=True)
    # Campos añadidos desde el wireframe
    isbn = db.Column(db.String(20), unique=True, nullable=True)
    paginas = db.Column(db.Integer, nullable=True)
    editorial = db.Column(db.String(100), nullable=True)

class RelacionLibro(db.Model):
    __tablename__ = 'relaciones_libros'
    id = db.Column('id_relacion', db.Integer, primary_key=True)
    id_libro_origen = db.Column(db.Integer, db.ForeignKey('libros.id_libro'))
    id_libro_rel = db.Column(db.Integer, db.ForeignKey('libros.id_libro'))
    tipo_relacion = db.Column(db.String(50))

class Conversacion(db.Model):
    __tablename__ = 'conversaciones'
    id = db.Column('id_conversacion', db.Integer, primary_key=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'))
    titulo = db.Column(db.String(100), nullable=False)
    fecha_hora = db.Column(db.DateTime, default=datetime.utcnow)
    mensajes = db.relationship('Mensaje', backref='conversacion', lazy=True)

class Mensaje(db.Model):
    __tablename__ = 'mensajes'
    id = db.Column('id_mensaje', db.Integer, primary_key=True)
    id_conversacion = db.Column(db.Integer, db.ForeignKey('conversaciones.id_conversacion'))
    remitente = db.Column(db.String(20)) # 'usuario' o 'ia'
    contenido = db.Column(db.Text)
    fecha_hora = db.Column(db.DateTime, default=datetime.utcnow)

# 3. Rutas de la Aplicación (Basadas en Wireframes)

# Ruta principal (Chat)
@app.route('/')
@login_required
def index():
    return render_template('chat.html')

# Rutas de Autenticación
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Usuario.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Credenciales incorrectas. Inténtalo de nuevo.')
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        nombre_usuario = request.form['usuario']
        email_usuario = request.form['email']
        password_usuario = request.form['password']
        
        user_exists = Usuario.query.filter_by(email=email_usuario).first()
        if user_exists:
            flash('El correo electrónico ya está registrado.')
            return redirect(url_for('registro'))
            
        new_user = Usuario(nombre=nombre_usuario, email=email_usuario, password=password_usuario)
        new_user.set_password(password_usuario)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Registro exitoso! Por favor, inicia sesión.')
        return redirect(url_for('login'))
        
    return render_template('registro.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Ruta para ver una conversación específica del historial
@app.route('/conversacion/<int:conv_id>')
@login_required
def ver_conversacion(conv_id):
    conv = Conversacion.query.get_or_404(conv_id)
    # Medida de seguridad: solo el dueño puede ver su conversación
    if conv.id_usuario != current_user.id:
        abort(403) # Forbidden
    
    mensajes = Mensaje.query.filter_by(id_conversacion=conv_id).order_by(Mensaje.fecha_hora.asc()).all()
    
    # Reutilizamos la plantilla de chat para mostrar la conversación
    return render_template('chat.html', conversacion=conv, mensajes=mensajes)

# Rutas de Contenido
@app.route('/historial')
@login_required
def historial():
    # Obtenemos el término de búsqueda de los argumentos de la URL (ej: /historial?q=hola)
    query = request.args.get('q')
    
    # La consulta base siempre filtra por el usuario actual
    base_query = Conversacion.query.filter_by(id_usuario=current_user.id)
    
    if query:
        # Si hay un término de búsqueda, filtramos por título o por el contenido
        # de cualquiera de los mensajes asociados a la conversación.
        # Usar .any() es más robusto y eficiente que un join manual.
        search_term = f'%{query}%'
        base_query = base_query.filter(
            or_(
                Conversacion.titulo.ilike(search_term),
                Conversacion.mensajes.any(Mensaje.contenido.ilike(search_term))
            )
        )
    
    # Ordenamos las conversaciones resultantes por fecha y las obtenemos todas
    conversaciones = base_query.order_by(Conversacion.fecha_hora.desc()).all()
    
    return render_template('historial.html', conversaciones=conversaciones, search_query=query)

@app.route('/libros')
@login_required
def libros():
    lista_libros = Libro.query.all()
    return render_template('libros.html', libros=lista_libros)

# Rutas para recuperación de contraseña (a implementar)
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    return render_template('recuperar.html')

@app.route('/nueva-contrasena/<token>', methods=['GET', 'POST'])
def nueva_contrasena(token):
    return render_template('nueva_contrasena.html')
    
# 4. API para el Chat
@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    user_message_content = data.get('message')
    conv_id = data.get('conversation_id') # Recibimos el ID desde el frontend

    if not user_message_content:
        return jsonify({'error': 'No se recibió ningún mensaje.'}), 400

    conversacion = None
    if conv_id:
        # Si se proporciona un ID, buscamos la conversación existente
        conversacion = Conversacion.query.get(conv_id)
        if not conversacion or conversacion.id_usuario != current_user.id:
            return jsonify({'error': 'Conversación no encontrada o no autorizada.'}), 404
    
    if not conversacion:
        # Si no hay ID o no se encontró, creamos una nueva
        titulo_conversacion = (user_message_content[:50] + '...') if len(user_message_content) > 50 else user_message_content
        conversacion = Conversacion(id_usuario=current_user.id, titulo=titulo_conversacion)
        db.session.add(conversacion)
        db.session.flush()

    # Guardamos el mensaje en la conversación correcta
    user_message = Mensaje(id_conversacion=conversacion.id, remitente='usuario', contenido=user_message_content)
    db.session.add(user_message)
    
    # --- Lógica de la "IA" (Versión 1.3 - Híbrida) RESTAURADA ---
    ai_response_content = ""
    search_term = user_message_content.lower().strip()

    try:
        # 1. Buscar en el cerebro conversacional (JSON)
        for intent in chatbot_data['intents']:
            for pattern in intent['patterns']:
                if pattern in search_term:
                    ai_response_content = random.choice(intent['responses'])
                    break
            if ai_response_content:
                break
        
        # 2. Si no es charla casual, buscar en la base de datos
        if not ai_response_content:
            keywords = {
                'autor': ['autor', 'autores', 'escribió'],
                'paginas': ['páginas', 'cuántas páginas'],
                'isbn': ['isbn'],
                'descripcion': ['describe', 'descripción', 'trata'],
                'tema': ['tema', 'sobre', 'acerca de', 'recomienda']
            }
            detected_intent = None
            detected_entity = search_term
            for intent, kws in keywords.items():
                for kw in kws:
                    if kw in search_term:
                        detected_intent = intent
                        cleaned_search = search_term
                        for other_kw in kws:
                            cleaned_search = cleaned_search.replace(other_kw, '')
                        detected_entity = cleaned_search.strip()
                        break
                if detected_intent:
                    break
            
            if detected_intent:
                if detected_intent in ['autor', 'paginas', 'isbn', 'descripcion']:
                    libro = Libro.query.filter(Libro.titulo.ilike(f"%{detected_entity}%")).first()
                    if libro:
                        if detected_intent == 'autor':
                            ai_response_content = f"El autor de '{libro.titulo}' es {libro.autor.nombre}."
                        elif detected_intent == 'paginas':
                            ai_response_content = f"'{libro.titulo}' tiene {libro.paginas} páginas."
                        elif detected_intent == 'isbn':
                            ai_response_content = f"El ISBN de '{libro.titulo}' es {libro.isbn}."
                        elif detected_intent == 'descripcion':
                            ai_response_content = f"'{libro.titulo}' trata sobre: {libro.descripcion}"
                    else:
                        ai_response_content = f"No pude encontrar el libro '{detected_entity}' para darte esa información."
                elif detected_intent == 'tema':
                    libros = Libro.query.filter(Libro.tema.ilike(f"%{detected_entity}%")).all()
                    if libros:
                        lista_libros = ", ".join([f"'{l.titulo}'" for l in libros])
                        ai_response_content = f"Sobre el tema '{detected_entity}', he encontrado: {lista_libros}."
                    else:
                        ai_response_content = f"No encontré libros sobre el tema '{detected_entity}'."
            else:
                libro = Libro.query.filter(Libro.titulo.ilike(f"%{search_term}%")).first()
                if libro:
                    ai_response_content = f"Encontré '{libro.titulo}' de {libro.autor.nombre}. Puedes preguntarme por su descripción, autor, páginas o ISBN."
                else:
                    ai_response_content = "No te he entendido bien. Prueba a preguntarme 'qué puedes hacer' para ver mis funciones."
    except Exception as e:
        ai_response_content = "Oh, parece que hubo un problema interno al procesar tu solicitud. Ya estamos trabajando en ello."
        print(f"Error en la lógica del chat: {e}")

    # Guardamos la respuesta de la IA
    ai_message = Mensaje(id_conversacion=conversacion.id, remitente='ia', contenido=ai_response_content)
    db.session.add(ai_message)
    
    db.session.commit()

    # Devolvemos la respuesta y el ID de la conversación (importante para chats nuevos)
    return jsonify({
        'response': ai_response_content,
        'conversation_id': conversacion.id
    })
    
# Creación de la base de datos y tablas
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)