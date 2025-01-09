# Imagen base de Python
FROM python:3.9-slim

# Instalar dependencias del sistema para PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*

# Crear el directorio de trabajo
WORKDIR /app

# Copiar archivos del proyecto al contenedor
COPY ./streamlit /app

# Copiar el archivo de dependencias
COPY requirements.txt /app/requirements.txt

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r /app/requirements.txt

# Comando por defecto para Streamlit
CMD ["streamlit", "run", "/app/app.py"]
