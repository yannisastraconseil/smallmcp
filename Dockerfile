# On utilise la version 3.11 en version "slim" (légère)
FROM python:3.11-slim

# On définit le dossier de travail dans le conteneur
WORKDIR /app

# On copie la liste des dépendances
COPY requirements.txt .

# On installe les librairies (pip est déjà à jour sur la 3.11)
RUN pip install --no-cache-dir -r requirements.txt

# On copie le reste du code (server.py)
COPY . .

# On expose le port standard de FastMCP
EXPOSE 8000

# On lance le serveur
CMD ["python", "server.py"]