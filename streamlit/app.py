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

        external_tab = st.tabs(["Google Index", "Page Rank", "Web Traffic", "Domain Age", "Ip", "Domain Registration Length"])

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

                # Colores para cada status
                status_colors = {0: '#38eb29', 1: '#ff3131'}

                # Variable para rastrear si se debe mostrar la leyenda para un valor de status
                legend_shown = {0: False, 1: False}

                # --- Gráficos de sectores para Google Index 0 y 1 ---
                for index_value in [0, 1]:
                    subset = data[data['google_index'] == index_value]
                    status_counts = subset['status'].value_counts(normalize=True) * 100

                    fig_pie = go.Figure(go.Pie(
                        labels=["Legítima", "Phishing"],
                        values=[status_counts.get(0, 0), status_counts.get(1, 0)],
                        marker=dict(colors=['#38eb29', '#ff3131']),
                        hole=0.4
                    ))

                    fig_pie.update_layout(
                        title=f"Proporción de Status para Google Index {index_value}"
                    )

                    st.plotly_chart(fig_pie)

            # Llamar a la función dentro del tablero de Streamlit
            google_index_visualization(data)

        # Subpestaña Gráfico 2
        with external_tab[1]:
            
            def page_rank_visualization(data):
                st.subheader("Visualización de Page Rank con Status")
                st.write("""
        
                **Función:** Indica la puntuación PageRank de un dominio determinado a partir de la API Open PageRank.

                **Valores:**
                - 0: No hay puntuación de PageRank (el dominio no está clasificado o no hay puntuación válida).
                - *Positive Integer*: Puntuación de PageRank (una medida de la importancia o relevancia del dominio).
                - -1: Se ha producido un error (e.g., dominio no válido o problema de solicitud).
                """)

                 # --- Gráfico de sectores: Proporción de Page Rank ---
                fig_pie = px.pie(
                    data_frame=data,
                    names="page_rank",
                    title="Proporción de Page Rank de las URLs",
                    color="page_rank",
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                st.plotly_chart(fig_pie)

                # --- Gráfico de barras agrupadas: Page Rank y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="page_rank",
                    color="status",
                    barmode="group",
                    title="Page Rank de las URLs y Status",
                    labels={"page_rank": "Page Rank", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                st.plotly_chart(fig_bar)

                # --- Análisis de Status por Page Rank ---
                fig = go.Figure()

                # Proporción de status para Page Rank Bajo (0-2)
                low_page_rank = data[data["page_rank"] <= 2]
                recuento_low = low_page_rank["status"].value_counts()
                fig.add_trace(go.Pie(
                    labels=["Phishing", "Legítima"],
                    values=recuento_low,
                    name="Page Rank Bajo (0-2)",
                    marker=dict(colors=['#ff3131', '#38eb29']),
                    hole=0.4
                ))

                # Proporción de status para Page Rank Alto (3+)
                high_page_rank = data[data["page_rank"] > 2]
                recuento_high = high_page_rank["status"].value_counts()
                fig.add_trace(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=recuento_high,
                    name="Page Rank Alto (3+)",
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                # Configuración del layout
                fig.update_layout(
                    title="Proporción de Status por Page Rank",
                    annotations=[
                        dict(text="Bajo (0-2)", x=0.18, y=0.5, font_size=12, showarrow=False),
                        dict(text="Alto (3+)", x=0.82, y=0.5, font_size=12, showarrow=False)
                    ]
                )
                st.plotly_chart(fig)

                # --- Tasa de Status (Phishing o no) por Page Rank ---
                tasa_phishing_low = (low_page_rank["status"].sum() / len(low_page_rank)) * 100 if len(low_page_rank) > 0 else 0
                tasa_phishing_high = (high_page_rank["status"].sum() / len(high_page_rank)) * 100 if len(high_page_rank) > 0 else 0

                fig_tasa = go.Figure(go.Bar(
                    x=['Page Rank Bajo (0-2)', 'Page Rank Alto (3+)'],
                    y=[tasa_phishing_low, tasa_phishing_high],
                    marker_color=['#f0f508', '#1498b7']
                ))

                fig_tasa.update_layout(
                    title="Tasa de Status (Phishing o Legítima) por Page Rank",
                    xaxis_title="Page Rank",
                    yaxis_title="Tasa (%)",
                    template="plotly_white"
                )

                st.plotly_chart(fig_tasa)

            # Llamar a la función con los datos cargados en el tablero
            page_rank_visualization(data)

        # Subpestaña Gráfico 3
        with external_tab[2]:

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
            data['web_traffic_category'] = data['web_traffic'].apply(categorize_web_traffic, args=(threshold,))


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
                fig_pie = px.pie(data, names="web_traffic_category", title="Proporción de Web Traffic de las URLs",
                                color="web_traffic_category", color_discrete_map={'Error': '#d3d3d3', 'Rango bajo': '#1498b7', 'Rango alto': '#ffcc00'})
                st.plotly_chart(fig_pie)

                fig_bar = px.histogram(data, x="web_traffic_category", color="status", barmode="group",
                                        title="Web Traffic de las URLs y Status",
                                        labels={"web_traffic_category": "Web Traffic", "status": "Status", "count":"Cantidad de URLs"},
                                        color_discrete_map={0: '#38eb29', 1: '#ff3131'}) # Mapa de colores para status
                st.plotly_chart(fig_bar)

                # --- Análisis de status por Web Traffic ---
                fig = go.Figure()

                # Colores para cada status
                status_colors = {0: '#38eb29', 1: '#ff3131'}

                # Variable para rastrear si se debe mostrar la leyenda para un valor de status
                legend_shown = {0: False, 1: False}

                for traffic_value in data['web_traffic_category'].unique():
                    subset = data[data['web_traffic_category'] == traffic_value]
                    status_counts = subset['status'].value_counts(normalize=True) * 100

                    for status_value, percentage in status_counts.items():
                        fig.add_trace(go.Bar(
                            x=[f'Web Traffic: {traffic_value}'],
                            y=[percentage],
                            name=f'Status: {status_value}',
                            marker_color=status_colors[status_value],
                            customdata=[[traffic_value, status_value]],
                            hovertemplate=(
                                "<b>Web Traffic:</b> %{customdata[0]}<br>"
                                "<b>Status:</b> %{customdata[1]}<br>"
                                "<b>Porcentaje:</b> %{y:.2f}%<extra></extra>"
                            ),
                            # Configuración de la leyenda
                            showlegend=(not legend_shown[status_value])  # Mostrar la leyenda solo una vez por categoría
                        ))
                        legend_shown[status_value] = True  # Marcar la leyenda como mostrada para este status

                fig.update_layout(
                    title="Porcentaje de Status por cada valor de Web Traffic",
                    xaxis_title="Web Traffic",
                    yaxis_title="Porcentaje",
                    barmode='group',
                    legend_title="Status"
                )

                st.plotly_chart(fig) 

            # Llamar a la función dentro del tablero de Streamlit
            web_traffic_visualization(data)

        # Subpestaña Gráfico 4
        with external_tab[3]:
            # Función para visualización interactiva de Domain Age y Status
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

            def domain_age_visualization(data):
                st.subheader("Visualización Interactiva de Domain Age y Status")

                st.write("""
                **Función:** Analizar la relación entre la edad del dominio (`domain_age`) y el status de las URLs.

                **Valores:**
                - **-2:** Cuando la edad del dominio no está disponible.
                - **-1:** Cuando falla la petición a la API.
                - **Integer:** La edad real del dominio en años, si se ha recuperado correctamente.
                """)

                # --- Gráfico de barras agrupadas: Domain Age y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="domain_age_category",
                    color="status",
                    barmode="group",
                    title="Domain Age de las URLs y Status",
                    labels={"domain_age_category": "Domain Age", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                st.plotly_chart(fig_bar)

                # --- Análisis de Status por Domain Age ---
                fig = go.Figure()

                # Proporción de status para cada categoría de Domain Age
                for category in data['domain_age_category'].unique():
                    subset = data[data['domain_age_category'] == category]
                    recuento = subset['status'].value_counts()
                    fig.add_trace(go.Pie(
                        labels=["Legítima", "Phishing"],
                        values=recuento,
                        name=f"Domain Age {category}",
                        marker=dict(colors=['#38eb29', '#ff3131']),
                        hole=0.4,
                        domain=dict(x=[0, 0.5] if category in ['Error (-2)', 'Rango bajo'] else [0.5, 1])
                    ))

                # Configuración del layout
                fig.update_layout(
                    title="Proporción de Status por Domain Age",
                    grid=dict(rows=1, columns=2),
                    annotations=[
                        dict(text="Error (-2)", x=0.12, y=0.5, font_size=12, showarrow=False),
                        dict(text="Error (-1)", x=0.37, y=0.5, font_size=12, showarrow=False),
                        dict(text="Bajo", x=0.62, y=0.5, font_size=12, showarrow=False),
                        dict(text="Alto", x=0.87, y=0.5, font_size=12, showarrow=False)
                    ]
                )
                st.plotly_chart(fig)

                # --- Tasa de Status (Phishing o no) por Domain Age ---
                tasa_phishing_error_2 = (data[data['domain_age_category'] == 'Error (-2)']['status'].sum() / len(data[data['domain_age_category'] == 'Error (-2)'])) * 100 if len(data[data['domain_age_category'] == 'Error (-2)']) > 0 else 0
                tasa_phishing_error_1 = (data[data['domain_age_category'] == 'Error (-1)']['status'].sum() / len(data[data['domain_age_category'] == 'Error (-1)'])) * 100 if len(data[data['domain_age_category'] == 'Error (-1)']) > 0 else 0
                tasa_phishing_bajo = (data[data['domain_age_category'] == 'Rango bajo']['status'].sum() / len(data[data['domain_age_category'] == 'Rango bajo'])) * 100 if len(data[data['domain_age_category'] == 'Rango bajo']) > 0 else 0
                tasa_phishing_alto = (data[data['domain_age_category'] == 'Rango alto']['status'].sum() / len(data[data['domain_age_category'] == 'Rango alto'])) * 100 if len(data[data['domain_age_category'] == 'Rango alto']) > 0 else 0

                fig_tasa = go.Figure(go.Bar(
                    x=['Error (-2)', 'Error (-1)', 'Domain Age Bajo', 'Domain Age Alto'],
                    y=[tasa_phishing_error_2, tasa_phishing_error_1, tasa_phishing_bajo, tasa_phishing_alto],
                    marker_color=['#d3d3d3', '#d3d3d3', '#1498b7', '#ff5733']
                ))

                fig_tasa.update_layout(
                    title="Tasa de Status (Phishing o Legítima) por Domain Age",
                    xaxis_title="Domain Age",
                    yaxis_title="Tasa (%)",
                    template="plotly_white"
                )

                st.plotly_chart(fig_tasa)

            # Llamar a la función con los datos cargados en el tablero
            domain_age_visualization(data)


        # Subpestaña Gráfico 5
        with external_tab[4]:

            # Función para visualización interactiva de IP y Status
            def ip_visualization(data):
                st.subheader("Visualización Interactiva de IP y Status")

                st.write("""
                **Función:** Analizar la relación entre la presencia de una dirección IP (`ip`) y el status de las URLs.

                **Valores:**
                - **0:** Indica que la URL no utiliza una dirección IP como dominio.
                - **1:** Indica que la URL utiliza una dirección IP como dominio.
                """)

                # --- Gráfico de barras agrupadas: IP y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="ip",
                    color="status",
                    barmode="group",
                    title="Distribución de IP de las URLs y Status",
                    labels={"ip": "IP", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                st.plotly_chart(fig_bar)

                # --- Proporción de Status por IP ---
                ip_0 = data[data["ip"] == 0]
                ip_1 = data[data["ip"] == 1]

                recuento_ip_0 = ip_0["status"].value_counts()
                recuento_ip_1 = ip_1["status"].value_counts()

                fig = go.Figure()
                fig.add_trace(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=recuento_ip_0,
                    name="IP = 0",
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                fig.add_trace(go.Pie(
                    labels=["Phishing", "Legítima"],
                    values=recuento_ip_1,
                    name="IP = 1",
                    marker=dict(colors=['#ff3131', '#38eb29']),
                    hole=0.4
                ))

                # Configuración del layout
                fig.update_layout(
                    title="Proporción de Status por IP",
                    annotations=[
                        dict(text="IP = 0", x=0.18, y=0.5, font_size=12, showarrow=False),
                        dict(text="IP = 1", x=0.82, y=0.5, font_size=12, showarrow=False)
                    ]
                )
                st.plotly_chart(fig)

                # --- Tasa de Status por IP ---
                tasa_phishing_ip_0 = (ip_0["status"].sum() / len(ip_0)) * 100 if len(ip_0) > 0 else 0
                tasa_phishing_ip_1 = (ip_1["status"].sum() / len(ip_1)) * 100 if len(ip_1) > 0 else 0

                fig_tasa = go.Figure(go.Bar(
                    x=['IP = 0', 'IP = 1'],
                    y=[tasa_phishing_ip_0, tasa_phishing_ip_1],
                    marker_color=['#1498b7', '#f0f508']
                ))

                fig_tasa.update_layout(
                    title="Tasa de Status (Phishing o Legítima) por IP",
                    xaxis_title="IP",
                    yaxis_title="Tasa (%)",
                    template="plotly_white"
                )

                st.plotly_chart(fig_tasa)

            # Llamar a la función con los datos cargados en el tablero
            ip_visualization(data)

        # Subpestaña Gráfico 6
        with external_tab[5]:
            # Función para visualización interactiva de Domain Registration Length y Status
            def domain_registration_length_visualization(data):
                st.subheader("Visualización Interactiva de Domain Registration Length y Status")

                st.write("""
                **Función:** Analizar la relación entre el tiempo de registro del dominio (`domain_registration_length`) y el status de las URLs.

                **Valores:**
                - **0:** El dominio no tiene fecha de expiración o la información no está disponible.
                - **-1:** Hubo un error durante la búsqueda en Whois.
                - **Integer positivo:** Días restantes antes de la expiración del dominio.
                """)

                # --- Gráfico de barras agrupadas: Domain Registration Length y Status ---
                fig_bar = px.histogram(
                    data_frame=data,
                    x="domain_registration_length",
                    color="status",
                    barmode="group",
                    title="Domain Registration Length de las URLs y Status",
                    labels={"domain_registration_length": "Días hasta la Expiración", "status": "Status", "count": "Cantidad de URLs"},
                    color_discrete_map={0: '#38eb29', 1: '#ff3131'}  # Colores para status
                )
                st.plotly_chart(fig_bar)

                # --- Proporción de Status por Domain Registration Length ---
                valid_length = data[data["domain_registration_length"] > 0]
                short_length = valid_length[valid_length["domain_registration_length"] <= valid_length["domain_registration_length"].median()]
                long_length = valid_length[valid_length["domain_registration_length"] > valid_length["domain_registration_length"].median()]

                recuento_short = short_length["status"].value_counts()
                recuento_long = long_length["status"].value_counts()

                fig = go.Figure()
                fig.add_trace(go.Pie(
                    labels=["Phishing", "Legítima"],
                    values=recuento_short,
                    name="Tiempo Corto",
                    marker=dict(colors=['#ff3131', '#38eb29']),
                    hole=0.4
                ))

                fig.add_trace(go.Pie(
                    labels=["Legítima", "Phishing"],
                    values=recuento_long,
                    name="Tiempo Largo",
                    marker=dict(colors=['#38eb29', '#ff3131']),
                    hole=0.4
                ))

                # Configuración del layout
                fig.update_layout(
                    title="Proporción de Status por Domain Registration Length",
                    annotations=[
                        dict(text="Corto", x=0.18, y=0.5, font_size=12, showarrow=False),
                        dict(text="Largo", x=0.82, y=0.5, font_size=12, showarrow=False)
                    ]
                )
                st.plotly_chart(fig)

                # --- Tasa de Status por Domain Registration Length ---
                tasa_phishing_short = (short_length["status"].sum() / len(short_length)) * 100 if len(short_length) > 0 else 0
                tasa_phishing_long = (long_length["status"].sum() / len(long_length)) * 100 if len(long_length) > 0 else 0

                fig_tasa = go.Figure(go.Bar(
                    x=['Tiempo Corto', 'Tiempo Largo'],
                    y=[tasa_phishing_short, tasa_phishing_long],
                    marker_color=['#f0f508', '#1498b7']
                ))

                fig_tasa.update_layout(
                    title="Tasa de Status (Phishing o Legítima) por Domain Registration Length",
                    xaxis_title="Tiempo de Registro",
                    yaxis_title="Tasa (%)",
                    template="plotly_white"
                )

                st.plotly_chart(fig_tasa)

            # Llamar a la función con los datos cargados en el tablero
            domain_registration_length_visualization(data)



except Exception as e:
    st.error(f"Error al cargar los datos: {e}")

