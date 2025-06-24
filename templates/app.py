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
import re
from flask import session
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

# 2. Modelos de Base de Datos
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

# 3. Rutas de la Aplicación 

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
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Correo y contraseña son obligatorios.')
            return redirect(url_for('login'))

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
        nombre_usuario = request.form.get('usuario')
        email_usuario = request.form.get('email')
        password_usuario = request.form.get('password')
        
        # Validación 
        if not nombre_usuario or not email_usuario or not password_usuario:
            flash('Todos los campos son obligatorios.')
            return redirect(url_for('registro'))
            
        user_exists = Usuario.query.filter_by(email=email_usuario).first()
        if user_exists:
            flash('El correo electrónico ya está registrado.')
            return redirect(url_for('registro'))
            
        new_user = Usuario(nombre=nombre_usuario, email=email_usuario, password=password_usuario)
        
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
    conv_id = data.get('conversation_id')

    if not user_message_content:
        return jsonify({'error': 'No se recibió ningún mensaje.'}), 400

    conversacion = None
    if conv_id:
        conversacion = Conversacion.query.get(conv_id)
        if not conversacion or conversacion.id_usuario != current_user.id:
            return jsonify({'error': 'Conversación no encontrada o no autorizada.'}), 404
    
    if not conversacion:
        titulo_conversacion = (user_message_content[:50] + '...') if len(user_message_content) > 50 else user_message_content
        conversacion = Conversacion(id_usuario=current_user.id, titulo=titulo_conversacion)
        db.session.add(conversacion)
        db.session.flush()

    user_message = Mensaje(id_conversacion=conversacion.id, remitente='usuario', contenido=user_message_content)
    db.session.add(user_message)
    
  
    ai_response_content = ""
    search_term = user_message_content.lower().strip()

    try:
        # 1. VERIFICAR SI HAY PREGUNTAS PENDIENTES
        if 'pending_question' in session and session['pending_question']:
            pending_intent = session.pop('pending_question', None)
            book_title_from_user = re.sub(r'\b(del libro|libro)\b', '', search_term).strip()
            libro = Libro.query.filter(Libro.titulo.ilike(f"%{book_title_from_user}%")).first()
            if libro:
                session['last_book_title'] = libro.titulo
                if pending_intent == 'autor': ai_response_content = f"El autor de '{libro.titulo}' es {libro.autor.nombre}."
                elif pending_intent == 'paginas': ai_response_content = f"'{libro.titulo}' tiene {libro.paginas} páginas."
                else: ai_response_content = f"Encontré '{libro.titulo}'. Puedes preguntarme más sobre él."
            else:
                ai_response_content = f"Lo siento, no pude encontrar el libro '{book_title_from_user}'."

        # 2. SI NO HAY PREGUNTAS PENDIENTES PROCESAR NORMALMENTE 
        if not ai_response_content:
            # Búsqueda por coincidencia exacta en JSON 
            for intent in chatbot_data['intents']:
                if any(p.lower() == search_term for p in intent['patterns']):
                    ai_response_content = random.choice(intent['responses'])
                    break
            
            
            if not ai_response_content:
                all_keywords = {
                    'autor': ['autor de', 'autor del libro', 'quien es el autor de', 'autor', 'autores', 'escribio', 'quien escribio'],
                    'paginas': ['paginas de', 'páginas de', 'páginas', 'cuantas paginas tiene', 'cuantas paginas', 'cuántas páginas', 'numero de paginas'],
                }
                cleaned_search = search_term.replace("?", "").replace("!", "")
                detected_intent = None
                trigger_keyword = None

                for intent, kws in all_keywords.items():
                    for kw in sorted(kws, key=len, reverse=True):
                        if cleaned_search.startswith(kw) or cleaned_search.endswith(kw):
                            detected_intent = intent
                            trigger_keyword = kw
                            break
                    if detected_intent: break

                if detected_intent:
                    detected_entity = cleaned_search.replace(trigger_keyword, "").strip()
                    if not detected_entity:
                        if 'last_book_title' in session:
                            detected_entity = session['last_book_title']
                        else:
                            session['pending_question'] = detected_intent
                            ai_response_content = f"Claro, te puedo dar información sobre '{detected_intent}'. ¿De qué libro quieres saber?"
                    
                    if detected_entity and not ai_response_content:
                        libro = Libro.query.filter(Libro.titulo.ilike(f"%{detected_entity}%")).first()
                        if libro:
                            session['last_book_title'] = libro.titulo
                            if detected_intent == 'autor': ai_response_content = f"El autor de '{libro.titulo}' es {libro.autor.nombre}."
                            elif detected_intent == 'paginas': ai_response_content = f"'{libro.titulo}' tiene {libro.paginas} páginas."
                        else:
                            ai_response_content = f"No pude encontrar un libro que coincida con '{detected_entity}'."

            # 3. Si no hay respuesta búsqueda general por título o tema
            if not ai_response_content:
                session.pop('pending_question', None)
                libro = Libro.query.filter(Libro.titulo.ilike(f"%{search_term}%")).first()
                if libro:
                    session['last_book_title'] = libro.titulo
                    ai_response_content = f"Encontré '{libro.titulo}' de {libro.autor.nombre}. Puedes preguntarme más sobre él, por ejemplo, cuántas páginas tiene."
                else:
                    libros_tema = Libro.query.filter(Libro.tema.ilike(f"%{search_term}%")).all()
                    if libros_tema:
                        session.pop('last_book_title', None)
                        lista_libros = ", ".join([f"'{l.titulo}'" for l in libros_tema])
                        ai_response_content = f"Sobre el tema '{search_term}', he encontrado: {lista_libros}."
                    else:
                        ai_response_content = "No te he entendido bien. Prueba a preguntarme, por ejemplo, 'quién es el autor de Clean Code'."

    except Exception as e:
        ai_response_content = "Oh, parece que hubo un problema interno. Ya estamos trabajando en ello."
        print(f"Error en la lógica del chat: {e}")

    ai_message = Mensaje(id_conversacion=conversacion.id, remitente='ia', contenido=ai_response_content)
    db.session.add(ai_message)
    db.session.commit()

    return jsonify({'response': ai_response_content, 'conversation_id': conversacion.id})

# 5. Configuración de Ejecución
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)