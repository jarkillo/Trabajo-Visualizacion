import os
from sqlalchemy import create_engine
import pandas as pd
import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt

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

    # Crear las pestañas principales
    main_tab = st.tabs(["Sintaxis", "Contenido", "Consultas externas"])

    # Pestaña Sintaxis
    with main_tab[0]:
        st.header("Exploración de Sintaxis")

        syntax_tab = st.tabs(["Gráfico 1", "Gráfico 2", "Gráfico 3", "Gráfico 4"])

        # Subpestaña Gráfico 1
        with syntax_tab[0]:
            st.subheader("Mapa de Calor de Correlaciones")
            st.write("Mapa de calor que muestra las correlaciones entre las variables seleccionadas y la variable objetivo (status).")

            # Seleccionar variables de interés
            selected_columns = [
                'nb_www', 'length_url', 'nb_slash', 'nb_dots', 'nb_hyphens',
                'nb_qm', 'ratio_digits_url', 'shortest_word_host', 'longest_words_raw',
                'longest_word_host', 'shortest_words_raw', 'length_hostname',
                'shortest_word_path', 'phish_hints', 'char_repeat', 'status'
            ]

            # Filtrar datos
            correlation_data = data[selected_columns].corr()

            # Crear el mapa de calor
            fig, ax = plt.subplots(figsize=(10, 8))
            sns.heatmap(correlation_data, annot=True, fmt=".2f", cmap="coolwarm", ax=ax)
            st.pyplot(fig)

        # Subpestaña Gráfico 2
        with syntax_tab[1]:
            st.subheader("Gráfico 2")
            st.write("Aquí irá el segundo gráfico de sintaxis")

        # Subpestaña Gráfico 3
        with syntax_tab[2]:
            st.subheader("Gráfico 3")
            st.write("Aquí irá el tercer gráfico de sintaxis")

        # Subpestaña Gráfico 4
        with syntax_tab[2]:
            st.subheader("Gráfico 4")
            st.write("Aquí irá el tercer gráfico de sintaxis")


    # Pestaña Contenido
    with main_tab[1]:
        st.header("Exploración de Contenido")

        content_tab = st.tabs(["Gráfico 1", "Gráfico 2", "Gráfico 3"])

        # Subpestaña Gráfico 1
        with content_tab[0]:
            st.subheader("Gráfico 1")
            st.write("Aquí irá el primer gráfico de contenido")

        # Subpestaña Gráfico 2
        with content_tab[1]:
            st.subheader("Gráfico 2")
            st.write("Aquí irá el segundo gráfico de contenido")

        # Subpestaña Gráfico 3
        with content_tab[2]:
            st.subheader("Gráfico 3")
            st.write("Aquí irá el tercer gráfico de contenido")

    # Pestaña Consultas externas
    with main_tab[2]:
        st.header("Exploración de Consultas Externas")

        external_tab = st.tabs(["Gráfico 1", "Gráfico 2", "Gráfico 3"])

        # Subpestaña Gráfico 1
        with external_tab[0]:
            st.subheader("Gráfico 1")
            st.write("Aquí irá el primer gráfico de consultas externas")

        # Subpestaña Gráfico 2
        with external_tab[1]:
            st.subheader("Gráfico 2")
            st.write("Aquí irá el segundo gráfico de consultas externas")

        # Subpestaña Gráfico 3
        with external_tab[2]:
            st.subheader("Gráfico 3")
            st.write("Aquí irá el tercer gráfico de consultas externas")

except Exception as e:
    st.error(f"Error al cargar los datos: {e}")

