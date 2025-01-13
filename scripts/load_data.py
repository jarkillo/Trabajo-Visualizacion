legitimate = 0
phishing = 1

import pandas as pd
from sqlalchemy import create_engine
import time

# Esperar a que la base de datos esté lista
time.sleep(10)

# Conectar a la base de datos
engine = create_engine("postgresql://user:password@db:5432/phishing_db")

# Leer el CSV
df = pd.read_csv("/data/phishing_data.csv")

# Codificar la variable 'status'
if 'status' in df.columns:
    df['status'] = df['status'].map({'legitimate': legitimate, 'phishing': phishing})
    if df['status'].isnull().any():
        raise ValueError("La columna 'status' contiene valores desconocidos que no se pueden codificar.")

# Crear la tabla si no existe y cargar los datos
df.to_sql("phishing_data", engine, if_exists="replace", index=False)

print("Datos cargados correctamente.")
