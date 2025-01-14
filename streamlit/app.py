import os
from sqlalchemy import create_engine
import pandas as pd
import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px

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


                # --- Gráficos principales ---
                fig_pie = px.pie(data, names="google_index", title="Proporción de Google Index de las URLs",
                                color="google_index", color_discrete_map={-1: '#f0f508', 0: '#1498b7', 1: '#ffcc00'})
                st.plotly_chart(fig_pie)
    
                fig_bar = px.histogram(data, x="google_index", color="status", barmode="group",
                                        title="Google Index de las URLs y Status",
                                        labels={"google_index": "Google Index", "status": "Status", "count":"Cantidad de URLs"},
                                        color_discrete_map={0: '#38eb29', 1: '#ff3131'}) # Mapa de colores para status
                st.plotly_chart(fig_bar)
    
                # --- Análisis de status por Google Index ---
                fig = go.Figure()
    
                for index_value in data['google_index'].unique():
                    subset = data[data['google_index'] == index_value]
                    status_counts = subset['status'].value_counts(normalize=True) * 100
                    
                    for status_value, percentage in status_counts.items():
                        fig.add_trace(go.Bar(
                            x=[f'Google Index: {index_value}'],
                            y=[percentage],
                            name=f'Status: {status_value}',
                            marker_color = '#38eb29' if status_value == 0 else '#ff3131',
                            customdata=[[index_value, status_value]],
                            hovertemplate=
                                "<b>Google Index:</b> %{customdata[0]}<br>" +
                                "<b>Status:</b> %{customdata[1]}<br>" +
                                "<b>Porcentaje:</b> %{y:.2f}%<extra></extra>"
                        ))
    
                fig.update_layout(
                    title="Porcentaje de Status por cada valor de Google Index",
                    xaxis_title="Google Index",
                    yaxis_title="Porcentaje",
                    barmode='group',
                    legend_title="Status"
                )
    
                st.plotly_chart(fig)


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

