import os
from sqlalchemy import create_engine
import pandas as pd
import streamlit as st

# Leer la URL de la base de datos desde las variables de entorno
db_url = os.getenv("DATABASE_URL")

# Crear conexión con la base de datos
engine = create_engine(db_url)

# Cargar datos de la base de datos
@st.cache_data
def load_data():
    query = "SELECT * FROM phishing_data"
    return pd.read_sql(query, engine)

try:
    # Intentar cargar los datos
    data = load_data()
    st.title("Dashboard de Phishing")
    st.write("Exploración de datos")
    st.dataframe(data)

except Exception as e:
    st.error(f"Error al cargar los datos: {e}")
