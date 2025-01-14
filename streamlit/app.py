import os
from sqlalchemy import create_engine
import pandas as pd
import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np

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

        syntax_tab = st.tabs(["Mapa de Calor", "Análisis Dinámico", "Variable phishing_score"])

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
            st.subheader("Análisis Dinámico de Variables")
            st.write("Selecciona una variable para analizar su relación con la variable objetivo (status).")

            # Selección interactiva de la variable
            sintax_url_columns = [
                'nb_at', 'nb_dots', 'nb_hyphens', 'nb_qm', 'nb_and', 'nb_or',
                'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash',
                'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar',
                'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path',
                'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode',
                'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
                'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service',
                'path_extension', 'nb_redirection', 'nb_external_redirection',
                'length_words_raw', 'char_repeat', 'shortest_words_raw',
                'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
                'longest_word_host', 'longest_word_path', 'avg_words_raw',
                'avg_word_host', 'avg_word_path', 'phish_hints',
                'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
                'suspecious_tld', 'statistical_report'
            ]

            selected_variable = st.selectbox("Selecciona una variable:", sintax_url_columns)

            if selected_variable:
                # Gráfico de barras inicial
                st.write(f"### Gráfico de Barras: {selected_variable} vs status")
                fig1, ax1 = plt.subplots(figsize=(10, 6))
                sns.countplot(x=selected_variable, hue='status', data=data, ax=ax1, palette="viridis")
                ax1.set_title(f"Distribución de {selected_variable} por Status")
                ax1.set_xlabel(selected_variable)
                ax1.set_ylabel("Cantidad de Datos")
                st.pyplot(fig1)

                if data[selected_variable].dtype in ['float64', 'int64']:
                    # Elección entre umbral personalizado o intervalos iguales
                    binarization_method = st.radio(
                        f"¿Cómo deseas binarizar {selected_variable}?",
                        ("Intervalos iguales", "Umbral personalizado")
                    )

                    if binarization_method == "Intervalos iguales":
                        num_bins = st.slider(f"Selecciona el número de grupos para binarizar {selected_variable}",
                                             min_value=2, max_value=10, value=2)
                        bins = np.linspace(data[selected_variable].min(), data[selected_variable].max(), num_bins + 1)
                        bin_labels = [f"Grupo {i}" for i in range(1, num_bins + 1)]
                        data[f"{selected_variable}_binarized"] = pd.cut(data[selected_variable], bins=bins, labels=bin_labels, include_lowest=True)
                    else:
                        threshold = st.number_input(f"Selecciona un umbral para binarizar {selected_variable}",
                                                    min_value=float(data[selected_variable].min()),
                                                    max_value=float(data[selected_variable].max()),
                                                    value=float(data[selected_variable].mean()))
                        data[f"{selected_variable}_binarized"] = (data[selected_variable] >= threshold).astype(int)

                    # Gráfico de barras binarizado
                    st.write(f"### Gráfico de Barras: {selected_variable} binarizado vs status")
                    fig2, ax2 = plt.subplots(figsize=(10, 6))
                    sns.countplot(x=f"{selected_variable}_binarized", hue='status', data=data, ax=ax2, palette="viridis")
                    ax2.set_title(f"{selected_variable} Binarizado por Status")
                    ax2.set_xlabel(f"{selected_variable} Binarizado")
                    ax2.set_ylabel("Cantidad de Datos")
                    st.pyplot(fig2)

            else:
                st.warning("Por favor, selecciona una variable para visualizar los gráficos.")

        # Subpestaña Gráfico 3
        # Subpestaña Gráfico 3
        with syntax_tab[2]:
            st.subheader("Phishing Score y Comparaciones")
            st.write("Generar un puntaje basado en variables seleccionadas y sus umbrales, y analizar su relación con la variable objetivo.")

            # Definir las variables y umbrales por defecto
            default_thresholds = {
                'nb_at': 1.0, 'nb_dots': 4.0, 'nb_qm': 1.0, 'nb_and': 1.0, 'nb_eq': 1.0,
                'nb_tilde': 1.0, 'nb_slash': 6.0, 'nb_colon': 2.0, 'nb_semicolumn': 1.0,
                'nb_www': 0.0, 'nb_com': 1.0, 'nb_dslash': 1.0, 'http_in_path': 1.0,
                'ratio_digits_url': 0.1, 'ratio_digits_host': 0.1, 'tld_in_subdomain': 0.0,
                'abnormal_subdomain': 0.0, 'prefix_suffix': 0.0, 'nb_external_redirection': 1.0,
                'char_repeat': 8.0, 'longest_words_raw': 24.0, 'longest_word_host': 22.0,
                'longest_word_path': 16.0, 'avg_words_raw': 13.0, 'avg_word_host': 15.0,
                'avg_word_path': 11.0, 'phish_hints': 1.0, 'brand_in_subdomain': 1.0,
                'brand_in_path': 1.0, 'suspecious_tld': 1.0, 'statistical_report': 1.0
            }

            selected_variables = st.multiselect("Selecciona las variables:", default_thresholds.keys(), default=list(default_thresholds.keys()))
            thresholds = {var: st.number_input(f"Threshold para {var}", min_value=0.0, value=float(default_thresholds[var])) for var in selected_variables}

            if selected_variables:
                # Crear phishing_score
                data['phishing_score'] = 0
                for var, threshold in thresholds.items():
                    if var == 'nb_www':
                        data['phishing_score'] += (data[var] != threshold).astype(int)
                    else:
                        data['phishing_score'] += (data[var] >= threshold).astype(int)

                # Gráfico 1: Comparación phishing_score con status
                st.write("### Comparación entre phishing_score y status")
                fig3, ax3 = plt.subplots(figsize=(10, 6))
                phishing_counts = data.groupby(['phishing_score', 'status']).size().reset_index(name='counts')
                sns.barplot(x='phishing_score', y='counts', hue='status', data=phishing_counts, ax=ax3, palette="viridis")
                ax3.set_title("Distribución de Phishing Score por Status")
                ax3.set_xlabel("Phishing Score")
                ax3.set_ylabel("Cantidad de Registros")
                st.pyplot(fig3)

                # Gráfico 2: Mapa de calor de phishing_score con status
                st.write("### Mapa de Calor: Phishing Score vs Status")
                fig4, ax4 = plt.subplots(figsize=(8, 6))
                heatmap_data = data[['phishing_score', 'status']].corr()
                sns.heatmap(heatmap_data, annot=True, cmap="coolwarm", ax=ax4)
                st.pyplot(fig4)
            else:
                st.warning("Por favor, selecciona al menos una variable para generar el phishing_score.")


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

