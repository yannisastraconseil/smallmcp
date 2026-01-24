import os
import logging
import requests
from mcp.server.fastmcp import FastMCP

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialisation du serveur
mcp = FastMCP("ServiceNow Agent", host="0.0.0.0", port=8000)

# Récupération des variables (on les définira dans le terminal juste après)
SN_INSTANCE = os.getenv("SN_INSTANCE")
SN_USER = os.getenv("SN_USER")
SN_PASSWORD = os.getenv("SN_PASSWORD")

# Configuration
REQUEST_TIMEOUT = 30  # secondes

# Session HTTP réutilisable pour le connection pooling
session = requests.Session()
if SN_USER and SN_PASSWORD:
    session.auth = (SN_USER, SN_PASSWORD)
session.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json"
})

@mcp.tool()
def create_incident(short_description: str, urgency: int, category: str = "Hardware") -> str:
    """Crée un incident dans ServiceNow."""

    # Validation des variables d'environnement
    if not SN_INSTANCE or not SN_USER or not SN_PASSWORD:
        logger.error("Variables d'environnement manquantes")
        return "Erreur : Variables d'environnement SN_INSTANCE, SN_USER et SN_PASSWORD doivent être définies."

    # URL ServiceNow
    url = f"https://{SN_INSTANCE}.service-now.com/api/now/table/incident"

    # Logique simple d'affectation - normalisation une seule fois
    category_lower = category.lower()
    assignment_group = "Service Desk"
    if category_lower == "hardware":
        assignment_group = "Hardware Support"
    elif category_lower == "software":
        assignment_group = "Software Support"

    # Données à envoyer
    payload = {
        "short_description": short_description,
        "urgency": str(urgency),
        "category": category,
        "assignment_group": assignment_group,
        "caller_id": "Abel Tuter"
    }

    logger.info(f"Création d'incident: {short_description[:50]}... (urgency={urgency}, category={category})")

    # Envoi avec session réutilisable et timeout
    try:
        response = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        # Validation de la réponse
        result_data = response.json()
        if 'result' not in result_data or 'number' not in result_data['result']:
            logger.error(f"Format de réponse inattendu: {result_data}")
            return "Erreur : Format de réponse ServiceNow inattendu"

        ticket_number = result_data['result']['number']
        logger.info(f"Ticket créé avec succès: {ticket_number}")
        return f"Succès ! Ticket créé : {ticket_number}"

    except requests.exceptions.Timeout:
        logger.error(f"Timeout lors de la création d'incident après {REQUEST_TIMEOUT}s")
        return f"Erreur : Le serveur ServiceNow n'a pas répondu dans les {REQUEST_TIMEOUT} secondes"
    except requests.exceptions.HTTPError as e:
        logger.error(f"Erreur HTTP: {e.response.status_code} - {e.response.text}")
        return f"Erreur HTTP {e.response.status_code} : {e.response.text[:100]}"
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Erreur de connexion: {str(e)}")
        return f"Erreur de connexion : Impossible de joindre ServiceNow"
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur de requête: {str(e)}")
        return f"Erreur de requête : {str(e)}"
    except (KeyError, ValueError) as e:
        logger.error(f"Erreur de parsing: {str(e)}")
        return f"Erreur : Impossible de parser la réponse ServiceNow"

# Lancement
if __name__ == "__main__":
    mcp.run(transport='sse')