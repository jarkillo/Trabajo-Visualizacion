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
            st.subheader("Mapa de Calor Interactivo de Correlaciones")
            st.write("Selecciona las variables para generar un mapa de calor dinámico que muestra las correlaciones con la variable objetivo (status).")

            # Selección de variables
            variables = [
                'nb_www', 'length_url', 'nb_slash', 'nb_dots', 'nb_hyphens',
                'nb_qm', 'ratio_digits_url', 'shortest_word_host', 'longest_words_raw',
                'longest_word_host', 'shortest_words_raw', 'length_hostname',
                'shortest_word_path', 'phish_hints', 'char_repeat'
            ]
            selected_vars = st.multiselect("Selecciona variables:", variables, default=variables)

            if selected_vars:
                # Añadir la variable objetivo
                selected_columns = selected_vars + ['status']

                # Calcular correlaciones
                correlation_data = data[selected_columns].corr()

                # Crear el mapa de calor
                fig, ax = plt.subplots(figsize=(10, 8))
                sns.heatmap(correlation_data, annot=True, fmt=".2f", cmap="coolwarm", ax=ax)
                st.pyplot(fig)
            else:
                st.warning("Por favor, selecciona al menos una variable para visualizar el mapa de calor.")

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
            def google_index_visualization(data):
                st.subheader("Visualización de Google Index con Status")
                st.write("""
        
                **Función:** Intenta comprobar si un dominio o URL está indexado por Google.

                **Valores:**
                - **-1:** Tráfico inusual detectado (bloqueado por Google).
                - **0:** URL indexada por Google.
                - **1:** URL no indexada por Google.
                """)

                # Seleccionar las variables necesarias
                etiquetas_gi = data["google_index"].value_counts().index
                recuento_gi = data["google_index"].value_counts()

                figura, axis = plt.subplots(1, 2, figsize=(15, 7))
                figura.suptitle("Proporción de Status por Google Index", fontsize=16)

                # Gráfico 1: Proporción de status para cada valor de google index
                colores_genero = ['#f0f508', '#1498b7', '#ffcc00']
                axis[0].pie(recuento_gi, labels=etiquetas_gi, autopct="%.2f%%", startangle=90, colors=colores_genero, wedgeprops={'edgecolor': 'black'})
                axis[0].set_title("Proporción de Google Index de las URLs")

                # Gráfico 2: Diagrama de barras del recuento de las urls por google index según status
                grafico_google_index_status = sns.countplot(data=data, x="google_index", hue="status", ax=axis[1], palette='pastel')

                # Añadir los números en las barras
                for p in grafico_google_index_status.patches:
                    grafico_google_index_status.annotate(f'{p.get_height()}', (p.get_x() + p.get_width() / 2., p.get_height()), 
                                                ha='center', va='center', fontsize=12, color='black', xytext=(0, 5), textcoords='offset points')

                axis[1].set(title="Google Index de las URLs y Status", ylabel="Cantidad de URLs", xlabel="Google Index")

                figura.tight_layout(rect=[0, 0.03, 1, 0.95])
                st.pyplot(figura)

                # Análisis de status por Google Index
                figura, axis = plt.subplots(1, 3, figsize=(15, 6))
                figura.suptitle("Proporción de Status por Google Index", fontsize=16)

                # Gráfico 1: Proporción de status para URLs indexadas por Google (0)
                url_indexed_google = data[data["google_index"] == 0]
                recuento_indexed = url_indexed_google["status"].value_counts()
                etiquetas_indexed = ["Legítima", "Phishing"]
                axis[0].pie(recuento_indexed, labels=etiquetas_indexed, autopct="%.2f%%", startangle=90, colors=['#38eb29', '#ff3131'], wedgeprops={'edgecolor': 'black'})
                axis[0].set_title("URL indexada por Google (0)")

                # Gráfico 2: Proporción de status para URLs no indexadas por Google (1)
                url_non_indexed_google = data[data["google_index"] == 1]
                recuento_non_indexed = url_non_indexed_google["status"].value_counts()
                etiquetas_non_indexed = ["Phishing", "Legítima"]
                axis[1].pie(recuento_non_indexed, labels=etiquetas_non_indexed, autopct="%.2f%%", startangle=90, colors=['#ff3131', '#38eb29'], wedgeprops={'edgecolor': 'black'})
                axis[1].set_title("URL no indexada por Google (1)")  

                # Cálculo de la tasa de status (phishing o no) por google index
                tasa_phishing_indexed = (url_indexed_google["status"].sum() / len(url_indexed_google)) * 100 if len(url_indexed_google) > 0 else 0
                tasa_phishing_non_indexed = (url_non_indexed_google["status"].sum() / len(url_non_indexed_google)) * 100 if len(url_non_indexed_google) > 0 else 0

                # Gráfico 3: Tasa de status por Google Index
                axis[2].bar(['URL indexada por Google', 'URL no indexada por Google'], [tasa_phishing_indexed, tasa_phishing_non_indexed], color=['#1498b7', '#f0f508'])
                axis[2].set_ylabel('Tasa de Status (Phishing o Legítima) (%)')
                axis[2].set_title('Tasa de Status (Phishing o Legítima) por Google Index')

                for i, v in enumerate([tasa_phishing_indexed, tasa_phishing_non_indexed]):
                    axis[2].text(i, v + 0.5, f'{v:.2f}%', ha='center', va='bottom', fontsize=12)

                figura.tight_layout(rect=[0, 0.03, 1, 0.95])
                st.pyplot(figura)

            # Llamar a la función dentro del tablero de Streamlit
            google_index_visualization(data)

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

