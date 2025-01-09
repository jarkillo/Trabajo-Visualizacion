# Dashboard de Visualización de Datos con Streamlit

Este proyecto consiste en un tablero interactivo de visualización de datos desarrollado con **Streamlit** y **Python**. Utiliza un conjunto de datos sobre phishing para explorar diferentes características relacionadas con URLs, contenido y factores externos.

## 🚀 Cómo usar este proyecto

### Requisitos previos
- Tener instalado Docker y Docker Compose en tu máquina.

### Instrucciones

```bash
git clone https://github.com/tu_usuario/phishing-visualizacion.git
cd tu_repositorio
docker-compose up --build
```

Abre tu navegador y accede al tablero en: [http://localhost:8501](http://localhost:8501).

## 🛠️ Tecnologías usadas
- **Streamlit**: Para crear el tablero interactivo.
- **PostgreSQL**: Base de datos para almacenar los datos.
- **SQLAlchemy**: Conexión entre Python y PostgreSQL.
- **Docker**: Para orquestar los servicios.

## 📊 Características
- **Conjunto de datos**: Analiza un dataset sobre phishing con 87 variables.
- **Interactividad**: Filtra y explora datos dinámicamente.
- **Visualizaciones**: Gráficos de barras, líneas y estadísticas descriptivas.

## 📁 Estructura del proyecto

phishing-visualizacion/
├── data/
│   ├── phishing_data.csv    # Conjunto de datos CSV
├── scripts/
│   ├── load_data.py         # Script para cargar el CSV en la base de datos
├── streamlit/
│   ├── app.py               # Código del tablero de Streamlit
├── requirements.txt         # Dependencias necesarias para Python
├── Dockerfile               # Configuración del contenedor
├── docker-compose.yml       # Orquestación de servicios (DB, Streamlit)
└── README.md                # Documentación del proyecto


## ⚙️ Configuración adicional

- **Dependencias**: Están listadas en `requirements.txt`.

## 📝 Notas
- Si experimentas problemas con Docker, verifica que los servicios estén funcionando correctamente:

```bash
docker ps
```

- Para reconstruir los contenedores:
```bash
docker-compose build --no-cache
```


