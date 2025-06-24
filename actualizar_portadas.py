import os
from app import app, db, Libro

# Ruta absoluta a la carpeta de portadas
CARPETA_PORTADAS = os.path.join(os.path.dirname(__file__), 'static', 'Libros')

# Extensiones permitidas
EXTENSIONES = ['.png', '.jpg', '.jpeg']

with app.app_context():
    libros = Libro.query.all()
    actualizados = 0
    no_encontrados = []

    for libro in libros:
        # Verifica si el campo portada está vacío o es None
        if not libro.portada:
            no_encontrados.append(libro.titulo)
            continue

        # Obtener solo el nombre base (sin ruta ni extensión)
        nombre_base = os.path.splitext(os.path.basename(libro.portada))[0]
        encontrado = False
        for ext in EXTENSIONES:
            nombre_archivo = nombre_base + ext
            ruta_completa = os.path.join(CARPETA_PORTADAS, nombre_archivo)
            if os.path.isfile(ruta_completa):
                # Actualizar la ruta en la base de datos
                libro.portada = f'Libros/{nombre_archivo}'
                db.session.add(libro)
                actualizados += 1
                encontrado = True
                break
        if not encontrado:
            no_encontrados.append(libro.titulo)

    db.session.commit()

    print(f"Portadas actualizadas: {actualizados}")
    if no_encontrados:
        print("No se encontró imagen para los siguientes libros:")
        for titulo in no_encontrados:
            print(f"- {titulo}")
    else:
        print("¡Todas las portadas fueron actualizadas correctamente!")