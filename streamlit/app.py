import os
from sqlalchemy import create_engine
import pandas as pd
import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
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
    main_tab = st.tabs(["Portada", "Sintaxis", "Contenido", "Consultas externas", "Resultados de Modelos"])

    # Portada del Dashboard
    with main_tab[0]:
        # Título principal
        st.markdown(
            """
            <h1 style='text-align: center; color: #FFD700;'>📊 Dashboard de Predicción de Phishing 📊</h1>
            """, unsafe_allow_html=True
        )

        # Subtítulo descriptivo
        st.markdown(
            """
            <h3 style='text-align: center; color: #32CD32;'>Una herramienta para analizar el dataset y comparar modelos predictivos en la detección de phishing</h3>
            """, unsafe_allow_html=True
        )

        # Breve descripción
        st.markdown(
            """
            Este dashboard proporciona una visión detallada sobre:
            - Exploración de variables sintácticas, contenido de URLs y consultas externas.
            - Análisis de correlaciones y distribuciones de variables.
            - Generación de puntajes de phishing y comparaciones con la variable objetivo.
            - Comparación de métricas de validación y test para distintos modelos.
            - Evaluación de diferencias entre métricas clave.
            - Exploración interactiva y personalizable de los resultados.
            
            Desarrollado por: **[Mercedes Iglesias, Macarena Herrera y Manuel López]** 🧑‍💻
            """, unsafe_allow_html=True
        )

    # Pestaña Sintaxis
    with main_tab[1]:
        st.header("Exploración de Sintaxis")

        # Todas las variables disponibles
        variables_sintaxis = [
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
            'suspecious_tld', 'statistical_report', 'length_url', 'length_hostname'
        ]

        # Crear subpestañas
        syntax_tab = st.tabs(["Análisis Inicial", "Mapa de Calor", "Análisis Dinámico", "Variable phishing_score"])

        # Subpestaña Gráfico 0: Análisis Inicial
        with syntax_tab[0]:
            st.subheader("Análisis inicial")

            # Resumen Estadístico Interactivo

            st.subheader("Resumen Estadístico de Variables Seleccionadas")

            # Selección de variables
            selected_vars_summary = st.multiselect(
                "Selecciona variables para el resumen estadístico:",
                variables_sintaxis
            )

            if selected_vars_summary:
                summary = data[selected_vars_summary + ['status']].groupby('status').describe().transpose()
                st.write(summary)
            else:
                st.warning("Por favor, selecciona al menos una variable para ver el resumen estadístico.")

       # Subpestaña Gráfico 1

        with syntax_tab[1]:
            st.subheader("Mapa de Calor Interactivo de Correlaciones")
            st.write("Selecciona las variables para generar un mapa de calor dinámico que muestra las correlaciones con la variable objetivo (status).")



            # Variables seleccionadas por defecto
            default_selected = [
                'nb_www', 'length_url', 'nb_slash', 'nb_dots', 'nb_hyphens',
                'nb_qm', 'ratio_digits_url', 'shortest_word_host', 'longest_words_raw',
                'longest_word_host', 'shortest_words_raw', 'length_hostname',
                'shortest_word_path', 'phish_hints', 'char_repeat'
            ]

            # Widget de selección múltiple
            selected_vars = st.multiselect("Selecciona variables:", variables_sintaxis, default=default_selected, key="heatmap")

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
        with syntax_tab[2]:
            st.subheader("Análisis Dinámico de Variables")
            st.write("Selecciona una variable para analizar su relación con la variable objetivo (status).")

            selected_variable = st.selectbox("Selecciona una variable:", variables_sintaxis, key="dynamic_analysis_var")

            if selected_variable:
                # Gráfico 1: Gráfico de barras inicial (variable seleccionada vs status)
                fig_bar1 = px.histogram(
                    data_frame=data,
                    x=selected_variable,  # La variable seleccionada
                    color="status",  # Diferenciación por status
                    barmode="group",
                    title=f"Distribución de {selected_variable} por Status",
                    labels={"status": "Status", selected_variable: selected_variable, "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Verde y rojo
                )
                st.plotly_chart(fig_bar1)


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

                    # Gráfico 2: Gráfico de barras binarizado (variable seleccionada binarizada vs status)
                    fig_bar2 = px.histogram(
                        data_frame=data,
                        x=f"{selected_variable}_binarized",  # Variable binarizada
                        color="status",  # Diferenciación por status
                        barmode="group",
                        title=f"{selected_variable} Binarizado por Status",
                        labels={"status": "Status", f"{selected_variable}_binarized": f"{selected_variable} Binarizado", "count": "Cantidad de URLs"},
                        color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Verde y rojo
                    )
                    st.plotly_chart(fig_bar2)

            else:
                st.warning("Por favor, selecciona una variable para visualizar los gráficos.")

        # Subpestaña Gráfico 3
        with syntax_tab[3]:
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
            with st.expander("Configuración de Phishing Score"):
                st.write("Configura las variables y umbrales para el cálculo del phishing_score.")
                selected_variables = st.multiselect("Selecciona las variables:", default_thresholds.keys(), default=list(default_thresholds.keys()), key="phishing_score_vars")
                thresholds = {var: st.number_input(f"Threshold para {var}", min_value=0.0, value=float(default_thresholds[var])) for var in selected_variables}

            if selected_variables:
                # Crear phishing_score
                data['phishing_score'] = 0
                for var, threshold in thresholds.items():
                    if var == 'nb_www':
                        data['phishing_score'] += (data[var] != threshold).astype(int)
                    else:
                        data['phishing_score'] += (data[var] >= threshold).astype(int)

                # Asegurar que 'status' sea categórica
                data['status'] = data['status'].astype('category')


                # Gráfico de phishing_score vs status
                st.write("### Comparación entre phishing_score y status")
                phishing_counts = data.groupby(['phishing_score', 'status']).size().reset_index(name='counts')

                fig_bar3 = px.bar(
                    phishing_counts,
                    x="phishing_score",
                    y="counts",
                    color="status",
                    barmode="relative", # Barras apiladas
                    title="Distribución de Phishing Score por Status",
                    labels={"phishing_score": "Phishing Score", "counts": "Cantidad de Registros", "status": "Status"},
                    category_orders={"status": [0, 1]},  
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Verde y rojo
                )

                st.plotly_chart(fig_bar3)

                # Mapa de calor: Correlación de phishing_score con status usando rojo y azul vivos con valores más visibles
                st.write("### Mapa de Calor: Phishing Score vs Status")

                # Calcular la correlación
                heatmap_data = data[['phishing_score', 'status']].corr()

                # Crear el mapa de calor con colores vivos
                fig_heatmap = px.imshow(
                    heatmap_data,
                    color_continuous_scale=["#ff6961", "#ffffff", "#61b6ff"],  # Rojo vivo, blanco, azul vivo
                    title="Mapa de Calor: Phishing Score vs Status",
                    labels={"color": "Correlación"},
                    x=heatmap_data.columns, 
                    y=heatmap_data.columns,
                    text_auto=".2f"  # Mostrar valores con 2 decimales en las celdas
                )

                # Cambiar el color de texto para que sea visible sobre el fondo
                fig_heatmap.update_traces(
                    textfont=dict(color="white"),  # Color blanco para los valores
                    zmin=-1,  # Correlación negativa máxima
                    zmax=1    # Correlación positiva máxima
                )

                # Mostrar el gráfico
                st.plotly_chart(fig_heatmap)
            else:
                st.warning("Por favor, selecciona al menos una variable para generar el phishing_score.")


    # Pestaña Contenido
    with main_tab[2]:
        st.header("Exploración de Contenido")

        content_tab = st.tabs(["Análisis Inicial", "Análisis de Distribución y Comparación", "Análisis de Relación Bivariada"])

        # Subpestaña Gráfico 1
        with content_tab[0]:
            st.subheader("Análisis inicial")
            st.write("Resumen Estadístico y Mapa de Calor de Correlaciones")

            # Resumen Estadístico Interactivo
            with st.expander("Resumen Estadístico Interactivo"):
                st.subheader("Resumen Estadístico de Variables Seleccionadas")
                # Selección de variables
                selected_vars_summary = st.multiselect(
                    "Selecciona variables para el resumen estadístico:",
                    ['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor']
                )
                
                if selected_vars_summary:
                    summary = data[selected_vars_summary + ['status']].groupby('status').describe().transpose()
                    st.write(summary)
                else:
                    st.warning("Por favor, selecciona al menos una variable para ver el resumen estadístico.")

            # Mapa de Calor de Correlaciones
            with st.expander("Mapa de Calor de Correlaciones Interactivo"):
                st.subheader("Mapa de Calor de Correlaciones entre Variables Seleccionadas")
                
                # Selección de variables para el mapa de calor
                selected_vars_heatmap = st.multiselect(
                    "Selecciona variables para el mapa de calor:",
                    ['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor','status'],
                    default=['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor','status']
                )
                
                if len(selected_vars_heatmap) > 1:
                    # Calcular correlación
                    corr_matrix = data[selected_vars_heatmap].corr()
                    
                    # Generar mapa de calor
                    heatmap_fig, ax = plt.subplots(figsize=(10, 8))
                    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f", ax=ax)
                    ax.set_title("Mapa de Calor de Correlaciones")
                    st.pyplot(heatmap_fig)
                else:
                    st.warning("Por favor, selecciona al menos dos variables para generar el mapa de calor.")

        # Subpestaña Gráfico 2
        with content_tab[1]:
            st.subheader("Análisis de Distribución y Comparación")
            st.write("Análisis de Distribución y Comparación de Variables")

            # Filtro por status
            status_filter = st.multiselect(
                "Selecciona los estados (status) para filtrar:",
                data['status'].unique(),
                default=data['status'].unique(),
                key="status_filter_distribution"
            )

            # Selección de variables para la distribución
            selected_vars_distribution = st.multiselect(
                "Selecciona variables para analizar la distribución:",
                ['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor'],
                key="distribution_vars"
            )

            # Parámetros del histograma
            plot_type = st.radio(
                "Selecciona el tipo de gráfico:",
                ['Histograma', 'Gráfico de Cajas']
            )
            
            if selected_vars_distribution and status_filter:
                filtered_data = data[data['status'].isin(status_filter)]

                for var in selected_vars_distribution:
                    st.write(f"Distribución de {var} por Status")
                    if plot_type == 'Histograma':
                        # Crear un histograma ajustado
                        bins = st.slider(f"Selecciona el número de bins para {var}:", min_value=5, max_value=50, value=20)
                        hist_fig = plt.figure(figsize=(10, 6))
                        sns.histplot(filtered_data, x=var, hue='status', multiple="stack", bins=bins, kde=True, palette="viridis")
                        plt.title(f"Distribución de {var} por Status")
                        plt.xlabel(var)
                        plt.ylabel("Frecuencia")
                        st.pyplot(hist_fig)
                    elif plot_type == 'Gráfico de Cajas':
                        # Crear un gráfico de cajas
                        box_fig = plt.figure(figsize=(10, 6))
                        sns.boxplot(data=filtered_data, x='status', y=var, palette="viridis")
                        plt.title(f"Distribución de {var} por Status (Gráfico de Cajas)")
                        plt.xlabel("Status")
                        plt.ylabel(var)
                        st.pyplot(box_fig)
            else:
                st.warning("Por favor, selecciona al menos una variable y un estado para analizar la distribución.")

        # Subpestaña Gráfico 3
        with content_tab[2]:
            st.subheader("Análisis de Relación Bivariada")
            st.write("Aquí podemos explorar relaciones bivariadas entre las variables y status.")
            
            # Filtro por status
            status_filter = st.multiselect(
                "Selecciona los estados (status) para filtrar:",
                data['status'].unique(),
                default=data['status'].unique(),
                key="status_filter_bivariate"
            )

            # Selección de variables para el análisis bivariado
            selected_x_var = st.selectbox(
                "Selecciona una variable para el eje X:",
                ['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor']
            )

            selected_y_var = st.selectbox(
                "Selecciona una variable para el eje Y:",
                ['domain_in_title', 'ratio_digits_host', 'nb_hyperlinks', 'safe_anchor']
            )

            plot_type = st.radio(
                "Selecciona el tipo de gráfico:",
                ['Gráfico de Dispersión', 'Gráfico de Líneas']
            )

            # Opción para añadir una línea de regresión
            add_regression = st.checkbox("Añadir línea de regresión")

            if selected_x_var and selected_y_var and status_filter:
                filtered_data = data[data['status'].isin(status_filter)]
                st.write(f"Relación entre {selected_x_var} y {selected_y_var} por Status")

                plot_fig = plt.figure(figsize=(10, 6))
                if plot_type == 'Gráfico de Dispersión':
                    sns.scatterplot(data=filtered_data, x=selected_x_var, y=selected_y_var, hue='status', palette="coolwarm", alpha=0.7)
                    if add_regression:
                        sns.regplot(data=filtered_data, x=selected_x_var, y=selected_y_var, scatter=False, color='red')
                elif plot_type == 'Gráfico de Líneas':
                    sns.lineplot(data=filtered_data, x=selected_x_var, y=selected_y_var, hue='status', palette="coolwarm")

                plt.title(f"Relación entre {selected_x_var} y {selected_y_var} por Status")
                plt.xlabel(selected_x_var)
                plt.ylabel(selected_y_var)
                st.pyplot(plot_fig)
            else:
                st.warning("Por favor, selecciona variables y estados para ambos ejes X e Y.")

    # Pestaña Consultas externas
    with main_tab[3]:
        st.header("Exploración de Consultas Externas")

        external_tab = st.tabs(["Análisis Inicial", "Google Index", "Page Rank", "Web Traffic", "Domain Age", "Ip", "Domain Registration Length"])

        # Subpestaña Análisis Inicial
        with external_tab[0]:
            st.subheader("Análisis inicial")
            st.write("Resumen Estadístico y Mapa de Calor de Correlaciones")

            # Resumen Estadístico Interactivo
            with st.expander("Resumen Estadístico Interactivo"):
                st.subheader("Resumen Estadístico de Variables Seleccionadas")
                # Selección de variables
                selected_vars_summary = st.multiselect(
                    "Selecciona variables para el resumen estadístico:",
                    ['google_index', 'page_rank', 'web_traffic', 'domain_age', 'domain_registration_length', 'ip'],
                    key="external_summary_vars"
                )
                
                if selected_vars_summary:
                    summary = data[selected_vars_summary + ['status']].groupby('status').describe().transpose()
                    st.write(summary)
                else:
                    st.warning("Por favor, selecciona al menos una variable para ver el resumen estadístico.")

            # Mapa de Calor de Correlaciones
            with st.expander("Mapa de Calor de Correlaciones Interactivo"):
                st.subheader("Mapa de Calor de Correlaciones entre Variables Seleccionadas")
                
                # Selección de variables para el mapa de calor
                selected_vars_heatmap = st.multiselect(
                    "Selecciona variables para el mapa de calor:",
                    ['google_index', 'page_rank', 'web_traffic', 'domain_age', 'domain_registration_length', 'ip','status'],
                    default=['google_index', 'page_rank', 'web_traffic', 'domain_age', 'domain_registration_length', 'ip','status'],
                    key="external_heatmap_vars"
                )
                
                if len(selected_vars_heatmap) > 1:
                    # Calcular correlación
                    corr_matrix = data[selected_vars_heatmap].corr()
                    
                    # Generar mapa de calor
                    heatmap_fig, ax = plt.subplots(figsize=(10, 8))
                    sns.heatmap(corr_matrix, annot=True, cmap='coolwarm', fmt=".2f", ax=ax)
                    ax.set_title("Mapa de Calor de Correlaciones")
                    st.pyplot(heatmap_fig)
                else:
                    st.warning("Por favor, selecciona al menos dos variables para generar el mapa de calor.")
        
        # Subpestaña Gráfico 1: google_index
        with external_tab[1]:
            
            # Función para visualización interactiva de Google Index y Status
            def google_index_visualization(data):
                st.subheader("Visualización de Google Index con Status)")
                st.write("""
                
                **Función:** Intenta comprobar si un dominio o URL está indexado por Google.

                **Valores:**
                - **-1:** Tráfico inusual detectado (bloqueado por Google).
                - **0:** URL indexada por Google.
                - **1:** URL no indexada por Google.
                """)

                # --- Gráficos principales ---
                fig_pie = px.pie(data, names="google_index", title="Proporción de Google Index en las URLs",
                                color="google_index", color_discrete_map={-1: '#f0f508', 0: '#1498b7', 1: '#ffcc00'})
                fig_pie.for_each_trace(lambda t: t.update(name = {-1: 'Tráfico Inusual', 0: 'Indexada', 1: 'No Indexada'}[t.name]))
                st.plotly_chart(fig_pie)

                fig_bar = px.histogram(data, x="google_index", color="status", barmode="group",
                                        title="Distribución de Google Index en función de Status",
                                        labels={"google_index": "Google Index", "status": "Status", "count":"Cantidad de URLs"},
                                        color_discrete_map={0: '#38eb29', 1: '#ff3131'}) # Mapa de colores para status
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de Google Index
                selected_google_index = st.selectbox("Selecciona el valor de Google Index:", [0, 1], key="google_index_selection")

                # Filtrar datos según la selección
                subset = data[data['google_index'] == selected_google_index]
                status_counts = subset['status'].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig_pie = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig_pie.update_layout(
                    title=f"Proporción de Status para Google Index {selected_google_index}"
                )

                st.plotly_chart(fig_pie)

            # Llamar a la función dentro del tablero de Streamlit
            google_index_visualization(data)

        # Subpestaña Gráfico 2: page_rank
        with external_tab[2]:
            
            # Función para visualización interactiva de Page Rank y Status
            def page_rank_visualization(data):
                st.subheader("Visualización de Page Rank con Status")
                st.write("""
        
                **Función:** Indica la puntuación PageRank de un dominio determinado a partir de la API Open PageRank.

                **Valores:**
                - **0**: No hay puntuación de PageRank (el dominio no está clasificado o no hay puntuación válida).
                - **Positive Integer**: Puntuación de PageRank (una medida de la importancia o relevancia del dominio).
                - **-1**: Se ha producido un error (e.g., dominio no válido o problema de solicitud).
                """)

                 # --- Gráfico de sectores: Proporción de Page Rank en las URLs---
                fig_pie = px.pie(
                    data_frame=data,
                    names="page_rank",
                    title="Proporción de Page Rank en las URLs",
                    color="page_rank",
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                st.plotly_chart(fig_pie)

                # --- Gráfico de barras agrupadas: Distribución de Page Rank en función de Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="page_rank",
                    color="status",
                    barmode="group",
                    title="Distribución de Page Rank en función de Status",
                    labels={"page_rank": "Page Rank", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de Page Rank
                selected_page_rank = st.selectbox("Selecciona el rango de Page Rank:", ["Bajo (0-2)", "Alto (3+)", "Error (-1)"], key="page_rank_selection")

                # Filtrar datos según la selección
                if selected_page_rank == "Bajo (0-2)":
                    subset = data[data["page_rank"] <= 2]
                elif selected_page_rank == "Alto (3+)":
                    subset = data[data["page_rank"] > 2]
                else:
                    subset = data[data["page_rank"] == -1]

                status_counts = subset["status"].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig.update_layout(
                    title=f"Proporción de Status para Page Rank {selected_page_rank}"
                )

                st.plotly_chart(fig)

            # Llamar a la función con los datos cargados en el tablero Streamlit
            page_rank_visualization(data)

        # Subpestaña Gráfico 3: web_traffic
        with external_tab[3]:

            def categorize_web_traffic(value, threshold):
                if value == 0:
                    return 'Error'
                elif value <= threshold:
                    return 'Rango bajo'
                else:
                    return 'Rango alto'

            # Calcular el percentil 50 para definir el umbral entre rango bajo y alto
            threshold = np.percentile(data['web_traffic'][data['web_traffic'] > 0], 50)

            # Crear la columna 'web_traffic_category'
            data['web_traffic_category'] = data['web_traffic'].apply(lambda x: categorize_web_traffic(x, threshold))

            # Función para visualización interactiva de Web Traffic y Status
            def web_traffic_visualization(data):
                st.subheader("Visualización de Web Traffic con Status")
                st.write("""
                
                **Función:** Obtiene el rango «REACH» de la API de Alexa utilizando una URL corta, que proporciona el rango de tráfico del sitio web.

                **Valores:**
                - **Rango alto:** Indica un tráfico web alto.
                - **Rango bajo:** Indica un tráfico web bajo.
                - **0:** Indica un error o la imposibilidad de obtener los datos.
                """)

                # --- Gráficos principales ---
                fig_pie = px.pie(data, names="web_traffic_category", title="Proporción de Web Traffic en las URLs",
                                color="web_traffic_category", color_discrete_map={'Error': '#d3d3d3', 'Rango bajo': '#1498b7', 'Rango alto': '#ffcc00'})
                st.plotly_chart(fig_pie)

                fig_bar = px.histogram(data, x="web_traffic_category", color="status", barmode="group",
                                        title="Distribución de Web Traffic en función de Status",
                                        labels={"web_traffic_category": "Web Traffic", "status": "Status", "count":"Cantidad de URLs"},
                                        color_discrete_map={0: '#38eb29', 1: '#ff3131'}) # Mapa de colores para status
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de Web Traffic
                selected_web_traffic = st.selectbox("Selecciona el rango de Web Traffic:", ["Error (0)", "Rango bajo", "Rango alto"], key="web_traffic_selection")

                # Filtrar datos según la selección
                subset = data[data['web_traffic_category'] == selected_web_traffic]
                status_counts = subset['status'].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig_pie = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig_pie.update_layout(
                    title=f"Proporción de Status para Web Traffic {selected_web_traffic}"
                )

                st.plotly_chart(fig_pie)

            # Llamar a la función dentro del tablero de Streamlit
            web_traffic_visualization(data)

        # Subpestaña Gráfico 4: domain_age
        with external_tab[4]:
        
            def categorize_domain_age(value, threshold):
                if value == -2:
                    return 'Error (-2)'
                elif value == -1:
                    return 'Error (-1)'
                elif value <= threshold:
                    return 'Rango bajo'
                else:
                    return 'Rango alto'

            # Calcular el percentil 50 para definir el umbral entre rango bajo y alto
            threshold = np.percentile(data['domain_age'][data['domain_age'] > 0], 50)

            # Crear la columna 'domain_age_category'
            data['domain_age_category'] = data['domain_age'].apply(categorize_domain_age, args=(threshold,))

            # Función para visualización interactiva de Domain Age y Status
            def domain_age_visualization(data):
                st.subheader("Visualización de Domain Age con Status")

                st.write("""
                **Función:** Extrae el nombre de dominio de la URL y envía una petición a una API externa para obtener la edad del dominio.

                **Valores:**
                - **-2:** Cuando la edad del dominio no está disponible.
                - **-1:** Cuando falla la petición a la API.
                - **Integer:** La edad real del dominio en años, si se ha recuperado correctamente.
                """)

                # --- Gráfico de barras agrupadas: Distribución de Domain Age en función de Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="domain_age_category",
                    color="status",
                    barmode="group",
                    title="Distribución de Comain Age en función de Status",
                    labels={"domain_age_category": "Domain Age", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de Domain Age
                selected_domain_age = st.selectbox("Selecciona la categoría de Domain Age:", data['domain_age_category'].unique(), key="domain_age_selection")

                # Filtrar datos según la selección
                subset = data[data['domain_age_category'] == selected_domain_age]
                status_counts = subset['status'].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig.update_layout(
                    title=f"Proporción de Status para Domain Age {selected_domain_age}"
                )

                st.plotly_chart(fig)

            # Llamar a la función con los datos cargados en el tablero
            domain_age_visualization(data)

        # Subpestaña Gráfico 5: ip
        with external_tab[5]:

            # Función para visualización interactiva de IP y Status
            def ip_visualization(data):
                st.subheader("Visualización de IP con Status")

                st.write("""
                **Función:** Indica si aparece una dirección IP en el hostname.

                **Valores:**
                - **0:** Indica que la URL no utiliza una dirección IP como dominio.
                - **1:** Indica que la URL utiliza una dirección IP como dominio.
                """)

                # --- Gráfico de sectores: Proporción de IP en las URLs ---
                fig_pie = px.pie(data, names="ip", title="Proporción de IP en las URLs",
                                color="ip", color_discrete_map={0: '#1498b7', 1: '#ffcc00'})
                fig_pie.for_each_trace(lambda t: t.update(name = {0: 'No IP', 1: 'IP como dominio'}[t.name]))
                st.plotly_chart(fig_pie)

                # --- Gráfico de barras agrupadas: IP y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="ip",
                    color="status",
                    barmode="group",
                    title="Distribución de IP en función de Status",
                    labels={"ip": "IP", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de IP
                selected_ip = st.selectbox("Selecciona el valor de IP:", [0, 1], key="ip_selection")

                # Filtrar datos según la selección
                subset = data[data['ip'] == selected_ip]
                status_counts = subset['status'].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig_pie = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig_pie.update_layout(
                    title=f"Proporción de Status para IP {selected_ip}"
                )

                st.plotly_chart(fig_pie)

            # Llamar a la función con los datos cargados en el tablero
            ip_visualization(data)

        # Subpestaña Gráfico 6: domain_registration_length
        with external_tab[6]:

            def categorize_domain_registration_length(value, threshold):
                if value == -1:
                    return 'Error (-1)'
                elif value == 0:
                    return 'No disponible (0)'
                elif value <= threshold:
                    return 'Rango bajo'
                else:
                    return 'Rango alto'

            # Calcular el percentil 50 para definir el umbral entre rango bajo y alto
            threshold = np.percentile(data['domain_registration_length'][data['domain_registration_length'] > 0], 50)

            # Crear la columna 'domain_registration_length_category'
            data['domain_registration_length_category'] = data['domain_registration_length'].apply(categorize_domain_registration_length, args=(threshold,))

            # Función para visualización interactiva de Domain Registration Length y Status
            def domain_registration_length_visualization(data):
                st.subheader("Visualización de Domain Registration Length con Status")

                st.write("""
                **Función:** Indica la diferencia en días entre la fecha de expiración del dominio y la fecha actual, indicando cuánto tiempo lleva registrado el dominio.

                **Valores:**
                - **0:** El dominio no tiene fecha de expiración o la información no está disponible.
                - **-1:** Hubo un error durante la búsqueda en Whois.
                - **Integer positivo:** Si el dominio tiene fecha de expiración, la función calcula el número de días desde la fecha actual.
                """)

                # --- Gráfico de sectores: Proporción de Domain Registration Length en las URLs ---
                fig_pie = px.pie(data, names="domain_registration_length_category", title="Proporción de Domain Registration Length en las URLs",
                                color="domain_registration_length_category", color_discrete_map={'Error (-1)': '#d3d3d3', 'No disponible (0)': '#1498b7', 'Rango bajo': '#ffcc00', 'Rango alto': '#ff3131'})

                st.plotly_chart(fig_pie)

                # --- Gráfico de barras agrupadas: Domain Registration Length y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="domain_registration_length_category",
                    color="status",
                    barmode="group",
                    title="Distribución de Domain Registration Length en función de Status",
                    labels={"domain_registration_length_category": "Domain Registration Length", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                fig_bar.for_each_trace(lambda t: t.update(name = {'0': 'Legítima', '1': 'Phishing'}[str(t.name)]))
                st.plotly_chart(fig_bar)

                # Selección interactiva de Domain Registration Length
                selected_domain_registration_length = st.selectbox("Selecciona la categoría de Domain Registration Length:", data['domain_registration_length_category'].unique(), key="domain_registration_length_selection")

                # Filtrar datos según la selección
                subset = data[data['domain_registration_length_category'] == selected_domain_registration_length]
                status_counts = subset['status'].value_counts(normalize=True) * 100

                # Crear gráfico de sectores
                fig = go.Figure(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig.update_layout(
                    title=f"Proporción de Status para Domain Registration Length {selected_domain_registration_length}"
                )

                st.plotly_chart(fig)

            # Llamar a la función con los datos cargados en el tablero
            domain_registration_length_visualization(data)

    # Pestaña de Resultados de Modelos
    with main_tab[4]:
        st.header("Resultados de Modelos")
        st.write("Visualiza los resultados de la selección de características y evaluación de modelos.")

        # Datos de la tabla
        import pandas as pd

        # Crea el DataFrame con los datos proporcionados
        data_modelos = pd.DataFrame({
            "Método Selección": ["manual", "manual", "importancia", "L1", "importancia", "manual", "L1", "importancia", "L1"],
            "Modelo": ["XGBoost", "Gradient Boosting", "XGBoost", "XGBoost", "Gradient Boosting", "Random Forest", "Gradient Boosting", "Random Forest", "Random Forest"],
            "Modo": ["GridSearch"] * 9,
            "Accuracy Validation": [0.966390, 0.967311, 0.956722, 0.966851, 0.961326, 0.964088, 0.970534, 0.954420, 0.959945],
            "Accuracy Test": [0.971455, 0.961455, 0.967311, 0.966390, 0.966390, 0.965009, 0.963168, 0.962247, 0.960866],
            "Accuracy-difference": [0.005065, 0.004144, 0.010589, -0.000461, 0.005064, 0.000921, -0.007366, 0.007827, 0.000921]
        })

        # Mostrar la tabla interactiva
        with st.expander("Resumen Estadístico de las Métricas"):
            st.subheader("Tabla de Resultados de Modelos")
            st.dataframe(data_modelos, use_container_width=True)

            # Opcional: Descargar la tabla como archivo CSV
            @st.cache_data
            def convertir_csv(df):
                return df.to_csv(index=False).encode('utf-8')

            csv = convertir_csv(data_modelos)

            st.download_button(
                label="Descargar Tabla en CSV",
                data=csv,
                file_name="resultados_modelos.csv",
                mime="text/csv"
            )

        # Resumen estadístico
        with st.expander("Resumen Estadístico de las Métricas"):
            st.subheader("Resumen Estadístico de las Métricas")
            st.write(data_modelos[["Accuracy Validation", "Accuracy Test", "Accuracy-difference"]].describe())

            # Gráfico comparativo de métricas por modelo
            melted_data = data_modelos.melt(
                id_vars=["Modelo", "Método Selección"],
                value_vars=["Accuracy Validation", "Accuracy Test"],
                var_name="Métrica",
                value_name="Valor"
            )

        with st.expander("Comparación de Métricas por Modelo"):
            selected_method = st.selectbox(
                "Selecciona el Método de Selección:",
                options=data_modelos["Método Selección"].unique(),
                index=0
            )

            filtered_data = melted_data[melted_data["Método Selección"] == selected_method]

            # Definir una paleta de colores vivos
            colors_vivos = {
                "F1-Macro Validation": "#FF6347",  # Rojo tomate
                "Accuracy Validation": "#FFD700",  # Amarillo
                "F1-Macro Test": "#1E90FF",       # Azul brillante
                "Accuracy Test": "#32CD32"        # Verde lima
            }

            fig_line_metrics_improved = px.scatter(
                filtered_data,
                x="Modelo",
                y="Valor",
                color="Métrica",
                size="Valor",
                size_max=15,
                title=f"Comparación de Métricas por Modelo (Método: {selected_method})",
                labels={"Valor": "Puntuación", "Métrica": "Métrica", "Modelo": "Modelo"},
                color_discrete_map=colors_vivos  # Aplicar los colores vivos
            )

            for metric in filtered_data["Métrica"].unique():
                metric_data = filtered_data[filtered_data["Métrica"] == metric]
                fig_line_metrics_improved.add_scatter(
                    x=metric_data["Modelo"],
                    y=metric_data["Valor"],
                    mode="lines",
                    line=dict(width=2, color=colors_vivos[metric]),  # Usar los mismos colores para las líneas
                    name=f"Línea: {metric}",
                    showlegend=False
                )

            st.plotly_chart(fig_line_metrics_improved)


        with st.expander("Diferencia en Accuracy entre Validación y Test"):
            fig_line_accuracy_diff = px.line(
                data_modelos,
                x="Modelo",
                y="Accuracy-difference",
                color="Método Selección",
                markers=True,
                title="Diferencia en Accuracy entre Validación y Test por Modelo",
                labels={"Accuracy-difference": "Diferencia en Accuracy", "Modelo": "Modelo"},
                color_discrete_sequence=["#FF4500", "#00FA9A", "#1E90FF"]  # Colores vivos para cada método
            )

            fig_line_accuracy_diff.update_traces(
                marker=dict(size=12),
                line=dict(width=3)  # Líneas más gruesas para mejor visibilidad
            )

            st.plotly_chart(fig_line_accuracy_diff)



        with st.expander("Mejor Modelo según Accuracy Test"):
    # Seleccionar el mejor modelo según Accuracy Test
            best_model = data_modelos.loc[data_modelos["Accuracy Test"].idxmax()]

            # Mostrar los detalles del mejor modelo
            st.write(f"**Modelo:** {best_model['Modelo']}")
            st.write(f"**Método de Selección:** {best_model['Método Selección']}")
            st.write(f"**Accuracy Test:** {best_model['Accuracy Test']:.3f}")
except Exception as e:
    st.error(f"Error al cargar los datos: {e}")

