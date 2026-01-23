import os
import requests
from mcp.server.fastmcp import FastMCP

# Initialisation du serveur
mcp = FastMCP("ServiceNow Agent")

# Récupération des variables (on les définira dans le terminal juste après)
SN_INSTANCE = os.getenv("SN_INSTANCE")
SN_USER = os.getenv("SN_USER")
SN_PASSWORD = os.getenv("SN_PASSWORD")

@mcp.tool()
def create_incident(short_description: str, urgency: int, category: str = "Hardware") -> str:
    """Crée un incident dans ServiceNow."""
    
    if not SN_INSTANCE or not SN_USER:
        return "Erreur : Variables d'environnement manquantes."

    # URL ServiceNow
    url = f"https://{SN_INSTANCE}.service-now.com/api/now/table/incident"
    
    # Logique simple d'affectation
    assignment_group = "Service Desk"
    if category.lower() == "hardware":
        assignment_group = "Hardware Support"
    elif category.lower() == "software":
        assignment_group = "Software Support"

    # Données à envoyer
    payload = {
        "short_description": short_description,
        "urgency": str(urgency),
        "category": category,
        "assignment_group": assignment_group,
        "caller_id": "Abel Tuter"
    }
    
    # Envoi
    try:
        response = requests.post(
            url, 
            auth=(SN_USER, SN_PASSWORD), 
            headers={"Content-Type": "application/json"}, 
            json=payload
        )
        response.raise_for_status()
        return f"Succès ! Ticket créé : {response.json()['result']['number']}"
    except Exception as e:
        return f"Erreur : {str(e)}"

# Lancement
if __name__ == "__main__":
    mcp.run(transport='sse', host='0.0.0.0', port=8000)