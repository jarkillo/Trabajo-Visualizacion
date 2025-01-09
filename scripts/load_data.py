import pandas as pd
from sqlalchemy import create_engine
import time

# Esperar a que la base de datos esté lista
time.sleep(10)

# Conectar a la base de datos
engine = create_engine("postgresql://user:password@db:5432/phishing_db")

# Leer el CSV
df = pd.read_csv("/data/phishing_data.csv")

# Crear la tabla si no existe y cargar los datos
df.to_sql("phishing_data", engine, if_exists="replace", index=False)

print("Datos cargados correctamente.")
