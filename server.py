import os
import logging
import json
import re
import requests
from functools import lru_cache
from typing import Optional
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ========== SERVICENOW CONSTANTS ==========

class IncidentState:
    """ServiceNow incident state values."""
    NEW = "1"
    IN_PROGRESS = "2"
    ON_HOLD = "3"
    RESOLVED = "6"
    CLOSED = "7"
    CANCELLED = "8"

    @classmethod
    def all_values(cls):
        return ["1", "2", "3", "6", "7", "8"]

    @classmethod
    def all_names(cls):
        return ["New", "In Progress", "On Hold", "Resolved", "Closed", "Cancelled"]


class Priority:
    """ServiceNow priority values."""
    CRITICAL = "1"
    HIGH = "2"
    MODERATE = "3"
    LOW = "4"
    PLANNING = "5"

    @classmethod
    def all_values(cls):
        return ["1", "2", "3", "4", "5"]


class Urgency:
    """ServiceNow urgency values."""
    HIGH = "1"
    MEDIUM = "2"
    LOW = "3"

    @classmethod
    def all_values(cls):
        return ["1", "2", "3"]


class Impact:
    """ServiceNow impact values."""
    HIGH = "1"
    MEDIUM = "2"
    LOW = "3"

    @classmethod
    def all_values(cls):
        return ["1", "2", "3"]


class ChangeType:
    """ServiceNow change request types."""
    STANDARD = "standard"
    NORMAL = "normal"
    EMERGENCY = "emergency"

    @classmethod
    def all_values(cls):
        return ["standard", "normal", "emergency"]


class ChangeState:
    """ServiceNow change request state values."""
    NEW = "-5"
    ASSESS = "-4"
    AUTHORIZE = "-3"
    SCHEDULED = "-2"
    IMPLEMENT = "-1"
    REVIEW = "0"
    CLOSED = "3"
    CANCELLED = "4"

    @classmethod
    def all_values(cls):
        return ["-5", "-4", "-3", "-2", "-1", "0", "3", "4"]


class WorkflowState:
    """ServiceNow knowledge article workflow states."""
    DRAFT = "draft"
    PUBLISHED = "published"
    RETIRED = "retired"

    @classmethod
    def all_values(cls):
        return ["draft", "published", "retired"]


# Initialisation du serveur
mcp = FastMCP("ServiceNow Agent", host="0.0.0.0", port=8000)

# Récupération des variables d'environnement
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


# ========== FIELD DEFINITIONS FOR OPTIMIZED QUERIES ==========
# Only request the fields we actually need to reduce payload size by ~90%

INCIDENT_LIST_FIELDS = "number,sys_id,short_description,state,priority,assigned_to,category,sys_created_on,sys_updated_on"
INCIDENT_DETAIL_FIELDS = "number,sys_id,short_description,description,state,priority,urgency,impact,assigned_to,category,subcategory,sys_created_on,sys_updated_on"
INCIDENT_RESOLVER_FIELDS = "sys_id"

CHANGE_LIST_FIELDS = "number,sys_id,short_description,type,state,risk,impact,start_date,end_date,sys_created_on,sys_updated_on"
CHANGE_DETAIL_FIELDS = "number,sys_id,short_description,description,type,state,risk,impact,priority,start_date,end_date,assigned_to,assignment_group,sys_created_on,sys_updated_on"
CHANGE_TASK_FIELDS = "number,short_description,state,assigned_to"
CHANGE_RESOLVER_FIELDS = "sys_id"

ARTICLE_LIST_FIELDS = "number,sys_id,short_description,kb_knowledge_base,kb_category,workflow_state,author,sys_created_on,sys_updated_on"
ARTICLE_DETAIL_FIELDS = "number,sys_id,short_description,text,kb_knowledge_base,kb_category,workflow_state,author,keywords,article_type,view_count,sys_created_on,sys_updated_on"

CATALOG_LIST_FIELDS = "sys_id,name,short_description,category,price,active,order"
# Minimal fields for catalog item details (optimized for ordering workflow)
CATALOG_DETAIL_FIELDS = "sys_id,name,short_description,price"
# Variable fields required for submit_catalog_request - provides the schema for ordering
CATALOG_VARIABLE_FIELDS = "name,question_text,type,mandatory,help_text"


# ========== VALIDATION FUNCTIONS ==========

def validate_incident_state(state: str) -> tuple[bool, str]:
    """Validate incident state value.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not state:
        return True, ""

    valid_states = IncidentState.all_values() + IncidentState.all_names()
    if state not in valid_states:
        return False, f"Invalid state: {state}. Valid states: New (1), In Progress (2), On Hold (3), Resolved (6), Closed (7), Cancelled (8)"

    return True, ""


def validate_priority(priority: str) -> tuple[bool, str]:
    """Validate priority value.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not priority:
        return True, ""

    if priority not in Priority.all_values():
        return False, f"Invalid priority: {priority}. Valid values: 1 (Critical), 2 (High), 3 (Moderate), 4 (Low), 5 (Planning)"

    return True, ""


def validate_urgency(urgency: int) -> tuple[bool, str]:
    """Validate urgency value.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if urgency is None:
        return True, ""

    if str(urgency) not in Urgency.all_values():
        return False, f"Invalid urgency: {urgency}. Valid values: 1 (High), 2 (Medium), 3 (Low)"

    return True, ""


def validate_impact(impact: str) -> tuple[bool, str]:
    """Validate impact value.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not impact:
        return True, ""

    if impact not in Impact.all_values():
        return False, f"Invalid impact: {impact}. Valid values: 1 (High), 2 (Medium), 3 (Low)"

    return True, ""


def validate_change_type(change_type: str) -> tuple[bool, str]:
    """Validate change request type.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not change_type:
        return True, ""

    if change_type not in ChangeType.all_values():
        return False, f"Invalid change type: {change_type}. Valid types: standard, normal, emergency"

    return True, ""


def validate_change_state(state: str) -> tuple[bool, str]:
    """Validate change request state.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not state:
        return True, ""

    if state not in ChangeState.all_values():
        return False, f"Invalid change state: {state}. Valid states: New (-5), Assess (-4), Authorize (-3), Scheduled (-2), Implement (-1), Review (0), Closed (3), Cancelled (4)"

    return True, ""


def validate_workflow_state(state: str) -> tuple[bool, str]:
    """Validate knowledge article workflow state.

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not state:
        return True, ""

    if state not in WorkflowState.all_values():
        return False, f"Invalid workflow state: {state}. Valid states: draft, published, retired"

    return True, ""


def validate_sys_id(sys_id: str) -> tuple[bool, str]:
    """Validate ServiceNow sys_id format (32-character hexadecimal).

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not sys_id:
        return False, "sys_id is required"

    if len(sys_id) != 32:
        return False, f"Invalid sys_id format: must be 32 characters, got {len(sys_id)}"

    if not all(c in "0123456789abcdef" for c in sys_id.lower()):
        return False, "Invalid sys_id format: must contain only hexadecimal characters (0-9, a-f)"

    return True, ""


def clean_json_from_markdown(json_str: str) -> str:
    """Clean JSON string by removing markdown code block wrappers.

    LLMs often wrap JSON in markdown code blocks like ```json ... ```.
    This function strips those wrappers to get clean JSON.

    Args:
        json_str: Potentially markdown-wrapped JSON string

    Returns:
        Clean JSON string without markdown formatting
    """
    if not json_str:
        return json_str

    # Remove leading/trailing whitespace
    cleaned = json_str.strip()

    # Pattern to match ```json or ``` at start and ``` at end
    # Handles: ```json\n{...}\n``` or ```\n{...}\n```
    markdown_pattern = re.compile(
        r'^```(?:json)?\s*\n?(.*?)\n?```$',
        re.DOTALL | re.IGNORECASE
    )

    match = markdown_pattern.match(cleaned)
    if match:
        cleaned = match.group(1).strip()
        logger.debug("Removed markdown code block wrapper from JSON input")

    return cleaned


# ========== HELPER FUNCTIONS ==========

def make_request(method: str, endpoint: str, data: dict = None, params: dict = None) -> dict:
    """Helper to make ServiceNow API requests."""
    if not SN_INSTANCE or not SN_USER or not SN_PASSWORD:
        return {
            "success": False,
            "message": "Environment variables SN_INSTANCE, SN_USER, and SN_PASSWORD must be set"
        }

    url = f"https://{SN_INSTANCE}.service-now.com/api/now/{endpoint}"

    try:
        response = session.request(method, url, json=data, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.error(f"Request timeout after {REQUEST_TIMEOUT}s")
        return {"error": f"Request timeout after {REQUEST_TIMEOUT} seconds"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
        return {"error": f"HTTP {e.response.status_code}: {e.response.text[:200]}"}
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return {"error": str(e)}


@lru_cache(maxsize=128)
def resolve_incident_id(incident_id: str) -> Optional[str]:
    """Helper to resolve incident number to sys_id.

    Cached with LRU cache for performance optimization.
    Uses minimal field selection to reduce API payload.
    """
    # Check if it's already a sys_id (32 hex chars)
    if len(incident_id) == 32 and all(c in "0123456789abcdef" for c in incident_id):
        return incident_id

    # Otherwise, query by incident number with minimal fields
    params = {
        "sysparm_query": f"number={incident_id}",
        "sysparm_limit": 1,
        "sysparm_fields": INCIDENT_RESOLVER_FIELDS
    }

    result = make_request("GET", "table/incident", params=params)
    if "error" in result:
        return None

    incidents = result.get("result", [])
    if not incidents:
        return None

    return incidents[0].get("sys_id")


@lru_cache(maxsize=128)
def resolve_change_id(change_id: str) -> Optional[str]:
    """Helper to resolve change request number to sys_id.

    Cached with LRU cache for performance optimization.
    Uses minimal field selection to reduce API payload.
    """
    # Check if it's already a sys_id (32 hex chars)
    if len(change_id) == 32 and all(c in "0123456789abcdef" for c in change_id):
        return change_id

    # Otherwise, query by change number with minimal fields
    params = {
        "sysparm_query": f"number={change_id}",
        "sysparm_limit": 1,
        "sysparm_fields": CHANGE_RESOLVER_FIELDS
    }

    result = make_request("GET", "table/change_request", params=params)
    if "error" in result:
        return None

    changes = result.get("result", [])
    if not changes:
        return None

    return changes[0].get("sys_id")


# ========== INCIDENT MANAGEMENT (6 tools) ==========

@mcp.tool()
def create_incident(
    short_description: str,
    urgency: int,
    category: str = "Hardware",
    description: str = None,
    priority: str = None
) -> str:
    """Create a new incident in ServiceNow.

    Args:
        short_description: Brief description of the incident
        urgency: Urgency level (1=High, 2=Medium, 3=Low)
        category: Category (Hardware, Software, Network, etc.)
        description: Detailed description (optional)
        priority: Priority level (1-5, optional)

    Returns:
        JSON string with incident details including incident number
    """
    logger.info(f"Creating incident: {short_description[:50]}...")

    # Validate inputs
    valid, error = validate_urgency(urgency)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    valid, error = validate_priority(priority)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    payload = {
        "short_description": short_description,
        "urgency": str(urgency),
        "category": category,
    }

    if description:
        payload["description"] = description
    if priority:
        payload["priority"] = priority

    result = make_request("POST", "table/incident", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to create incident: {result['error']}",
            "data": None
        })

    incident_data = result.get("result", {})
    logger.info(f"Incident created: {incident_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Incident created successfully: {incident_data.get('number')}",
        "data": {
            "incident_number": incident_data.get("number"),
            "sys_id": incident_data.get("sys_id"),
            "state": incident_data.get("state"),
            "priority": incident_data.get("priority"),
            "urgency": incident_data.get("urgency")
        }
    })


@mcp.tool()
def update_incident(
    incident_id: str,
    state: str = None,
    assigned_to: str = None,
    priority: str = None,
    work_notes: str = None
) -> str:
    """Update an existing incident in ServiceNow.

    Args:
        incident_id: Incident number (e.g., INC0010001) or sys_id
        state: New state (1=New, 2=In Progress, 3=On Hold, 6=Resolved, 7=Closed, 8=Cancelled)
        assigned_to: User to assign the incident to
        priority: New priority level (1-5)
        work_notes: Work notes to add

    Returns:
        JSON string with updated incident details
    """
    logger.info(f"Updating incident: {incident_id}")

    # Validate inputs
    valid, error = validate_incident_state(state)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    valid, error = validate_priority(priority)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    # Resolve incident_id to sys_id
    sys_id = resolve_incident_id(incident_id)
    if not sys_id:
        return json.dumps({
            "success": False,
            "message": f"Incident not found: {incident_id}",
            "data": None
        })

    payload = {}
    if state:
        payload["state"] = state
    if assigned_to:
        payload["assigned_to"] = assigned_to
    if priority:
        payload["priority"] = priority
    if work_notes:
        payload["work_notes"] = work_notes

    result = make_request("PUT", f"table/incident/{sys_id}", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to update incident: {result['error']}",
            "data": None
        })

    incident_data = result.get("result", {})
    logger.info(f"Incident updated: {incident_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Incident updated successfully: {incident_data.get('number')}",
        "data": {
            "incident_number": incident_data.get("number"),
            "sys_id": incident_data.get("sys_id"),
            "state": incident_data.get("state"),
            "assigned_to": incident_data.get("assigned_to"),
            "priority": incident_data.get("priority")
        }
    })


@mcp.tool()
def add_comment(incident_id: str, comment: str, is_work_note: bool = False) -> str:
    """Add a comment or work note to an incident.

    Args:
        incident_id: Incident number or sys_id
        comment: Comment text
        is_work_note: If True, adds as work note (internal), otherwise as comment (customer visible)

    Returns:
        Success message
    """
    logger.info(f"Adding comment to incident: {incident_id}")

    # Resolve incident_id to sys_id
    sys_id = resolve_incident_id(incident_id)
    if not sys_id:
        return json.dumps({
            "success": False,
            "message": f"Incident not found: {incident_id}",
            "data": None
        })

    payload = {}
    if is_work_note:
        payload["work_notes"] = comment
    else:
        payload["comments"] = comment

    result = make_request("PUT", f"table/incident/{sys_id}", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to add comment: {result['error']}",
            "data": None
        })

    incident_data = result.get("result", {})
    comment_type = "work note" if is_work_note else "comment"
    logger.info(f"Comment added to incident: {incident_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"{comment_type.capitalize()} added successfully to {incident_data.get('number')}",
        "data": {
            "incident_number": incident_data.get("number"),
            "sys_id": incident_data.get("sys_id")
        }
    })


@mcp.tool()
def resolve_incident(incident_id: str, resolution_code: str, resolution_notes: str) -> str:
    """Resolve an incident in ServiceNow.

    Args:
        incident_id: Incident number or sys_id
        resolution_code: Resolution code (e.g., "Solved (Permanently)", "Solved (Workaround)")
        resolution_notes: Notes explaining the resolution

    Returns:
        JSON string with resolved incident details
    """
    logger.info(f"Resolving incident: {incident_id}")

    # Resolve incident_id to sys_id
    sys_id = resolve_incident_id(incident_id)
    if not sys_id:
        return json.dumps({
            "success": False,
            "message": f"Incident not found: {incident_id}",
            "data": None
        })

    payload = {
        "state": "6",  # Resolved state
        "close_code": resolution_code,
        "close_notes": resolution_notes
    }

    result = make_request("PUT", f"table/incident/{sys_id}", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to resolve incident: {result['error']}",
            "data": None
        })

    incident_data = result.get("result", {})
    logger.info(f"Incident resolved: {incident_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Incident resolved successfully: {incident_data.get('number')}",
        "data": {
            "incident_number": incident_data.get("number"),
            "sys_id": incident_data.get("sys_id"),
            "state": incident_data.get("state"),
            "close_code": incident_data.get("close_code")
        }
    })


@mcp.tool()
def list_incidents(
    limit: int = 10,
    state: str = None,
    assigned_to: str = None,
    priority: str = None,
    category: str = None
) -> str:
    """List incidents from ServiceNow with optional filters.

    Args:
        limit: Maximum number of incidents to return (default: 10)
        state: Filter by state
        assigned_to: Filter by assigned user
        priority: Filter by priority
        category: Filter by category

    Returns:
        JSON string with list of incidents
    """
    logger.info(f"Listing incidents (limit={limit})")

    # Build query filters
    filters = []
    if state:
        filters.append(f"state={state}")
    if assigned_to:
        filters.append(f"assigned_to={assigned_to}")
    if priority:
        filters.append(f"priority={priority}")
    if category:
        filters.append(f"category={category}")

    params = {
        "sysparm_limit": limit,
        "sysparm_fields": INCIDENT_LIST_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    if filters:
        params["sysparm_query"] = "^".join(filters)

    result = make_request("GET", "table/incident", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to list incidents: {result['error']}",
            "data": []
        })

    incidents = []
    for inc in result.get("result", []):
        incidents.append({
            "number": inc.get("number"),
            "sys_id": inc.get("sys_id"),
            "short_description": inc.get("short_description"),
            "state": inc.get("state"),
            "priority": inc.get("priority"),
            "assigned_to": inc.get("assigned_to"),
            "category": inc.get("category"),
            "created_on": inc.get("sys_created_on"),
            "updated_on": inc.get("sys_updated_on")
        })

    logger.info(f"Found {len(incidents)} incidents")

    return json.dumps({
        "success": True,
        "message": f"Found {len(incidents)} incidents",
        "data": incidents
    })


@mcp.tool()
def get_incident_by_number(incident_number: str) -> str:
    """Get a specific incident by its number.

    Args:
        incident_number: Incident number (e.g., INC0010001)

    Returns:
        JSON string with incident details
    """
    logger.info(f"Getting incident: {incident_number}")

    params = {
        "sysparm_query": f"number={incident_number}",
        "sysparm_limit": 1,
        "sysparm_fields": INCIDENT_DETAIL_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    result = make_request("GET", "table/incident", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to get incident: {result['error']}",
            "data": None
        })

    incidents = result.get("result", [])
    if not incidents:
        return json.dumps({
            "success": False,
            "message": f"Incident not found: {incident_number}",
            "data": None
        })

    inc = incidents[0]
    incident_data = {
        "number": inc.get("number"),
        "sys_id": inc.get("sys_id"),
        "short_description": inc.get("short_description"),
        "description": inc.get("description"),
        "state": inc.get("state"),
        "priority": inc.get("priority"),
        "urgency": inc.get("urgency"),
        "impact": inc.get("impact"),
        "assigned_to": inc.get("assigned_to"),
        "category": inc.get("category"),
        "subcategory": inc.get("subcategory"),
        "created_on": inc.get("sys_created_on"),
        "updated_on": inc.get("sys_updated_on")
    }

    logger.info(f"Incident found: {incident_number}")

    return json.dumps({
        "success": True,
        "message": f"Incident {incident_number} found",
        "data": incident_data
    })


# ========== CHANGE MANAGEMENT (4 tools) ==========

@mcp.tool()
def create_change_request(
    short_description: str,
    type: str = "normal",
    description: str = None,
    risk: str = None,
    impact: str = None,
    start_date: str = None,
    end_date: str = None
) -> str:
    """Create a new change request in ServiceNow.

    Args:
        short_description: Brief description of the change
        type: Change type (standard, normal, emergency)
        description: Detailed description
        risk: Risk level (1=High, 2=Medium, 3=Low)
        impact: Impact level (1=High, 2=Medium, 3=Low)
        start_date: Planned start date (YYYY-MM-DD HH:MM:SS)
        end_date: Planned end date (YYYY-MM-DD HH:MM:SS)

    Returns:
        JSON string with change request details including change number
    """
    logger.info(f"Creating change request: {short_description[:50]}...")

    # Validate inputs
    valid, error = validate_change_type(type)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    valid, error = validate_impact(impact)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    payload = {
        "short_description": short_description,
        "type": type
    }

    if description:
        payload["description"] = description
    if risk:
        payload["risk"] = risk
    if impact:
        payload["impact"] = impact
    if start_date:
        payload["start_date"] = start_date
    if end_date:
        payload["end_date"] = end_date

    result = make_request("POST", "table/change_request", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to create change request: {result['error']}",
            "data": None
        })

    change_data = result.get("result", {})
    logger.info(f"Change request created: {change_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Change request created successfully: {change_data.get('number')}",
        "data": {
            "change_number": change_data.get("number"),
            "sys_id": change_data.get("sys_id"),
            "type": change_data.get("type"),
            "state": change_data.get("state"),
            "risk": change_data.get("risk"),
            "impact": change_data.get("impact")
        }
    })


@mcp.tool()
def update_change_request(
    change_id: str,
    state: str = None,
    risk: str = None,
    impact: str = None,
    work_notes: str = None
) -> str:
    """Update an existing change request.

    Args:
        change_id: Change request number (e.g., CHG0000001) or sys_id
        state: New state (-5=New, -4=Assess, -3=Authorize, -2=Scheduled, -1=Implement, 0=Review, 3=Closed, 4=Cancelled)
        risk: New risk level (1=High, 2=Medium, 3=Low)
        impact: New impact level (1=High, 2=Medium, 3=Low)
        work_notes: Work notes to add

    Returns:
        JSON string with updated change request details
    """
    logger.info(f"Updating change request: {change_id}")

    # Validate inputs
    valid, error = validate_change_state(state)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    valid, error = validate_impact(impact)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    # Resolve change_id to sys_id
    sys_id = resolve_change_id(change_id)
    if not sys_id:
        return json.dumps({
            "success": False,
            "message": f"Change request not found: {change_id}",
            "data": None
        })

    payload = {}
    if state:
        payload["state"] = state
    if risk:
        payload["risk"] = risk
    if impact:
        payload["impact"] = impact
    if work_notes:
        payload["work_notes"] = work_notes

    result = make_request("PUT", f"table/change_request/{sys_id}", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to update change request: {result['error']}",
            "data": None
        })

    change_data = result.get("result", {})
    logger.info(f"Change request updated: {change_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Change request updated successfully: {change_data.get('number')}",
        "data": {
            "change_number": change_data.get("number"),
            "sys_id": change_data.get("sys_id"),
            "state": change_data.get("state"),
            "risk": change_data.get("risk"),
            "impact": change_data.get("impact")
        }
    })


@mcp.tool()
def list_change_requests(
    limit: int = 10,
    state: str = None,
    type: str = None,
    timeframe: str = None
) -> str:
    """List change requests from ServiceNow.

    Args:
        limit: Maximum number of change requests to return (default: 10)
        state: Filter by state (-5 to 4)
        type: Filter by type (standard, normal, emergency)
        timeframe: Filter by timeframe (upcoming, in-progress, completed)

    Returns:
        JSON string with list of change requests
    """
    logger.info(f"Listing change requests (limit={limit})")

    # Validate inputs
    valid, error = validate_change_state(state)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": []
        })

    valid, error = validate_change_type(type)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": []
        })

    # Build query filters
    filters = []
    if state:
        filters.append(f"state={state}")
    if type:
        filters.append(f"type={type}")

    # Add timeframe filtering logic
    if timeframe:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if timeframe == "upcoming":
            # Changes that haven't started yet
            filters.append(f"start_date>{now}")
        elif timeframe == "in-progress":
            # Changes that have started but not ended
            filters.append(f"start_date<{now}^end_date>{now}")
        elif timeframe == "completed":
            # Changes that have ended and are closed
            filters.append(f"end_date<{now}^state=3")
        else:
            return json.dumps({
                "success": False,
                "message": f"Invalid timeframe: {timeframe}. Valid values: upcoming, in-progress, completed",
                "data": []
            })

    params = {
        "sysparm_limit": limit,
        "sysparm_fields": CHANGE_LIST_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    if filters:
        params["sysparm_query"] = "^".join(filters)

    result = make_request("GET", "table/change_request", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to list change requests: {result['error']}",
            "data": []
        })

    changes = []
    for chg in result.get("result", []):
        changes.append({
            "number": chg.get("number"),
            "sys_id": chg.get("sys_id"),
            "short_description": chg.get("short_description"),
            "type": chg.get("type"),
            "state": chg.get("state"),
            "risk": chg.get("risk"),
            "impact": chg.get("impact"),
            "start_date": chg.get("start_date"),
            "end_date": chg.get("end_date"),
            "created_on": chg.get("sys_created_on"),
            "updated_on": chg.get("sys_updated_on")
        })

    logger.info(f"Found {len(changes)} change requests")

    return json.dumps({
        "success": True,
        "message": f"Found {len(changes)} change requests",
        "data": changes
    })


@mcp.tool()
def get_change_request_details(change_id: str) -> str:
    """Get detailed information about a specific change request.

    Args:
        change_id: Change request number (e.g., CHG0000001) or sys_id

    Returns:
        JSON string with change request details and associated tasks
    """
    logger.info(f"Getting change request details: {change_id}")

    # Resolve change_id to sys_id
    sys_id = resolve_change_id(change_id)
    if not sys_id:
        return json.dumps({
            "success": False,
            "message": f"Change request not found: {change_id}",
            "data": None
        })

    # Get the change request with optimized field selection
    params = {
        "sysparm_fields": CHANGE_DETAIL_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    result = make_request("GET", f"table/change_request/{sys_id}", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to get change request: {result['error']}",
            "data": None
        })

    chg = result.get("result", {})

    # Get associated tasks with optimized field selection
    task_params = {
        "sysparm_query": f"change_request={change_id}",
        "sysparm_fields": CHANGE_TASK_FIELDS,
        "sysparm_display_value": "true"
    }

    tasks_result = make_request("GET", "table/change_task", params=task_params)
    tasks = tasks_result.get("result", []) if "error" not in tasks_result else []

    change_data = {
        "number": chg.get("number"),
        "sys_id": chg.get("sys_id"),
        "short_description": chg.get("short_description"),
        "description": chg.get("description"),
        "type": chg.get("type"),
        "state": chg.get("state"),
        "risk": chg.get("risk"),
        "impact": chg.get("impact"),
        "priority": chg.get("priority"),
        "start_date": chg.get("start_date"),
        "end_date": chg.get("end_date"),
        "assigned_to": chg.get("assigned_to"),
        "assignment_group": chg.get("assignment_group"),
        "created_on": chg.get("sys_created_on"),
        "updated_on": chg.get("sys_updated_on"),
        "tasks": [
            {
                "number": task.get("number"),
                "short_description": task.get("short_description"),
                "state": task.get("state"),
                "assigned_to": task.get("assigned_to")
            }
            for task in tasks
        ]
    }

    logger.info(f"Change request found: {chg.get('number')} with {len(tasks)} tasks")

    return json.dumps({
        "success": True,
        "message": f"Change request {chg.get('number')} found with {len(tasks)} tasks",
        "data": change_data
    })


# ========== KNOWLEDGE BASE (4 tools) ==========

@mcp.tool()
def create_article(
    title: str,
    text: str,
    short_description: str,
    knowledge_base: str,
    category: str,
    keywords: str = None
) -> str:
    """Create a new knowledge article.

    Args:
        title: Article title
        text: Article body content (supports HTML)
        short_description: Brief description
        knowledge_base: Knowledge base sys_id
        category: Category sys_id
        keywords: Search keywords (optional)

    Returns:
        JSON string with article details including article ID
    """
    logger.info(f"Creating knowledge article: {title[:50]}...")

    payload = {
        "short_description": title,
        "text": text,
        "kb_knowledge_base": knowledge_base,
        "kb_category": category
    }

    if keywords:
        payload["keywords"] = keywords

    result = make_request("POST", "table/kb_knowledge", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to create article: {result['error']}",
            "data": None
        })

    article_data = result.get("result", {})
    logger.info(f"Article created: {article_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Article created successfully: {article_data.get('number')}",
        "data": {
            "article_number": article_data.get("number"),
            "sys_id": article_data.get("sys_id"),
            "short_description": article_data.get("short_description"),
            "workflow_state": article_data.get("workflow_state")
        }
    })


@mcp.tool()
def update_article(
    article_id: str,
    title: str = None,
    text: str = None,
    short_description: str = None,
    keywords: str = None
) -> str:
    """Update an existing knowledge article.

    Args:
        article_id: Article sys_id
        title: New title (optional)
        text: New body content (optional)
        short_description: New short description (optional)
        keywords: New keywords (optional)

    Returns:
        JSON string with updated article details
    """
    logger.info(f"Updating article: {article_id}")

    payload = {}
    if title:
        payload["short_description"] = title
    if text:
        payload["text"] = text
    if short_description:
        payload["short_description"] = short_description
    if keywords:
        payload["keywords"] = keywords

    result = make_request("PATCH", f"table/kb_knowledge/{article_id}", data=payload)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to update article: {result['error']}",
            "data": None
        })

    article_data = result.get("result", {})
    logger.info(f"Article updated: {article_data.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Article updated successfully: {article_data.get('number')}",
        "data": {
            "article_number": article_data.get("number"),
            "sys_id": article_data.get("sys_id"),
            "short_description": article_data.get("short_description"),
            "workflow_state": article_data.get("workflow_state")
        }
    })


@mcp.tool()
def list_articles(
    limit: int = 10,
    knowledge_base: str = None,
    category: str = None,
    query: str = None,
    workflow_state: str = None
) -> str:
    """List knowledge articles with optional filters.

    Uses ServiceNow's Zing full-text search engine for query searches,
    providing stemming, relevance scoring, and better search results.

    Args:
        limit: Maximum number of articles to return (default: 10)
        knowledge_base: Filter by knowledge base sys_id
        category: Filter by category sys_id
        query: Full-text search query (uses Zing search engine for relevance)
        workflow_state: Filter by workflow state (draft, published, retired)

    Returns:
        JSON string with list of articles
    """
    logger.info(f"Listing articles (limit={limit})")

    # Validate inputs
    valid, error = validate_workflow_state(workflow_state)
    if not valid:
        return json.dumps({
            "success": False,
            "message": error,
            "data": []
        })

    # Build query filters
    filters = []
    if knowledge_base:
        filters.append(f"kb_knowledge_base={knowledge_base}")
    if category:
        filters.append(f"kb_category={category}")
    if workflow_state:
        filters.append(f"workflow_state={workflow_state}")

    # Use Zing full-text search instead of LIKE for better relevance and performance
    if query:
        filters.append(f"123TEXTQUERY321={query}")

    params = {
        "sysparm_limit": limit,
        "sysparm_fields": ARTICLE_LIST_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    if filters:
        params["sysparm_query"] = "^".join(filters)

    result = make_request("GET", "table/kb_knowledge", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to list articles: {result['error']}",
            "data": []
        })

    articles = []
    for art in result.get("result", []):
        articles.append({
            "number": art.get("number"),
            "sys_id": art.get("sys_id"),
            "short_description": art.get("short_description"),
            "kb_knowledge_base": art.get("kb_knowledge_base"),
            "kb_category": art.get("kb_category"),
            "workflow_state": art.get("workflow_state"),
            "author": art.get("author"),
            "created_on": art.get("sys_created_on"),
            "updated_on": art.get("sys_updated_on")
        })

    logger.info(f"Found {len(articles)} articles")

    return json.dumps({
        "success": True,
        "message": f"Found {len(articles)} articles",
        "data": articles
    })


@mcp.tool()
def get_article(article_id: str) -> str:
    """Get a specific knowledge article by ID.

    Args:
        article_id: Article sys_id

    Returns:
        JSON string with full article details including content
    """
    logger.info(f"Getting article: {article_id}")

    params = {
        "sysparm_fields": ARTICLE_DETAIL_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    result = make_request("GET", f"table/kb_knowledge/{article_id}", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to get article: {result['error']}",
            "data": None
        })

    art = result.get("result", {})

    article_data = {
        "number": art.get("number"),
        "sys_id": art.get("sys_id"),
        "short_description": art.get("short_description"),
        "text": art.get("text"),
        "kb_knowledge_base": art.get("kb_knowledge_base"),
        "kb_category": art.get("kb_category"),
        "workflow_state": art.get("workflow_state"),
        "author": art.get("author"),
        "keywords": art.get("keywords"),
        "article_type": art.get("article_type"),
        "view_count": art.get("view_count"),
        "created_on": art.get("sys_created_on"),
        "updated_on": art.get("sys_updated_on")
    }

    logger.info(f"Article found: {art.get('number')}")

    return json.dumps({
        "success": True,
        "message": f"Article {art.get('number')} found",
        "data": article_data
    })


# ========== SERVICE CATALOG (3 tools) ==========

@mcp.tool()
def list_catalog_items(
    limit: int = 10,
    category: str = None,
    query: str = None,
    active: bool = True
) -> str:
    """List service catalog items.

    Args:
        limit: Maximum number of items to return (default: 10)
        category: Filter by category sys_id
        query: Search query for item names/descriptions
        active: Only return active items (default: True)

    Returns:
        JSON string with list of catalog items
    """
    logger.info(f"Listing catalog items (limit={limit})")

    # Build query filters
    filters = []
    if active:
        filters.append("active=true")
    if category:
        filters.append(f"category={category}")
    if query:
        filters.append(f"short_descriptionLIKE{query}^ORnameLIKE{query}")

    params = {
        "sysparm_limit": limit,
        "sysparm_fields": CATALOG_LIST_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    if filters:
        params["sysparm_query"] = "^".join(filters)

    result = make_request("GET", "table/sc_cat_item", params=params)

    if "error" in result:
        return json.dumps({
            "success": False,
            "message": f"Failed to list catalog items: {result['error']}",
            "data": []
        })

    items = []
    for item in result.get("result", []):
        items.append({
            "sys_id": item.get("sys_id"),
            "name": item.get("name"),
            "short_description": item.get("short_description"),
            "category": item.get("category"),
            "price": item.get("price"),
            "active": item.get("active"),
            "order": item.get("order")
        })

    logger.info(f"Found {len(items)} catalog items")

    return json.dumps({
        "success": True,
        "message": f"Found {len(items)} catalog items",
        "data": items
    })


@mcp.tool()
def get_catalog_item(item_id: str) -> str:
    """Get details of a specific catalog item including the variable schema for ordering.

    This tool provides the information needed to call submit_catalog_request.
    The 'variables_schema' in the response shows which keys to use in the
    'variables' JSON parameter when ordering.

    Args:
        item_id: Catalog item sys_id (32-character hexadecimal)

    Returns:
        JSON string with catalog item details and variable schema for ordering.
        The 'variables_schema' array shows:
        - name: The technical key to use in submit_catalog_request variables
        - label: Human-readable description of the field
        - type: Data type (string, integer, reference, etc.)
        - mandatory: Whether the field is required (true/false)
        - help_text: Additional guidance for the field
    """
    logger.info(f"Getting catalog item: {item_id}")

    # Validate item_id format
    valid, error = validate_sys_id(item_id)
    if not valid:
        logger.warning(f"Invalid item_id format: {error}")
        return json.dumps({
            "success": False,
            "message": error,
            "data": None
        })

    # Get item details with minimal fields
    params = {
        "sysparm_fields": CATALOG_DETAIL_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    result = make_request("GET", f"table/sc_cat_item/{item_id}", params=params)

    if "error" in result:
        logger.error(f"Failed to get catalog item {item_id}: {result['error']}")
        return json.dumps({
            "success": False,
            "message": f"Failed to get catalog item: {result['error']}",
            "data": None
        })

    item = result.get("result", {})

    if not item:
        logger.warning(f"Catalog item not found: {item_id}")
        return json.dumps({
            "success": False,
            "message": f"Catalog item not found: {item_id}",
            "data": None
        })

    # Query item_option_new table for variable schema
    var_params = {
        "sysparm_query": f"cat_item={item_id}",
        "sysparm_fields": CATALOG_VARIABLE_FIELDS,
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true"
    }

    logger.debug(f"Fetching variables for catalog item: {item_id}")
    var_result = make_request("GET", "table/item_option_new", params=var_params)
    variables = var_result.get("result", []) if "error" not in var_result else []

    # Build variable schema with clear naming for LLM consumption
    variables_schema = []
    mandatory_fields = []

    for var in variables:
        var_name = var.get("name", "")
        is_mandatory = var.get("mandatory") in ["true", True, "1"]

        variable_info = {
            "name": var_name,  # Use this as the key in submit_catalog_request
            "label": var.get("question_text", ""),
            "type": var.get("type", "string"),
            "mandatory": is_mandatory,
            "help_text": var.get("help_text", "")
        }
        variables_schema.append(variable_info)

        if is_mandatory and var_name:
            mandatory_fields.append(var_name)

    item_data = {
        "sys_id": item.get("sys_id"),
        "name": item.get("name"),
        "short_description": item.get("short_description"),
        "price": item.get("price"),
        # Schema for submit_catalog_request - use 'name' field as keys
        "variables_schema": variables_schema,
        # Quick reference for required fields
        "mandatory_variables": mandatory_fields,
        # Usage hint for the LLM
        "ordering_hint": f"To order this item, call submit_catalog_request with item_id='{item_id}' and variables containing: {', '.join(mandatory_fields) if mandatory_fields else 'no mandatory fields'}"
    }

    logger.info(f"Catalog item found: {item.get('name')} with {len(variables)} variables ({len(mandatory_fields)} mandatory)")

    return json.dumps({
        "success": True,
        "message": f"Catalog item '{item.get('name')}' found with {len(variables)} variables. Use the 'name' field from variables_schema as keys when calling submit_catalog_request.",
        "data": item_data
    })


@mcp.tool()
def submit_catalog_request(
    item_id: str,
    variables: str = None,
    quantity: int = 1
) -> str:
    """Submit an order for a service catalog item.

    Uses the ServiceNow Service Catalog API (sn_sc namespace) to order items.
    Call get_catalog_item first to see which variables are required.

    Args:
        item_id: Catalog item sys_id (32-character hexadecimal string)
        variables: JSON string of catalog item variables. Use the 'name' fields
                   from get_catalog_item's variables_schema as keys.
                   Example: '{"requested_for": "user_sys_id", "justification": "Business need"}'
                   Note: Markdown code blocks (```json...```) are automatically stripped.
        quantity: Number of items to order (default: 1)

    Returns:
        JSON string with request details including request number
    """
    logger.info(f"Submitting catalog request for item: {item_id}")

    # Validate environment variables
    if not SN_INSTANCE or not SN_USER or not SN_PASSWORD:
        logger.error("ServiceNow credentials not configured")
        return json.dumps({
            "success": False,
            "message": "Environment variables SN_INSTANCE, SN_USER, and SN_PASSWORD must be set",
            "data": None
        })

    # Validate item_id format locally (32-char hex)
    valid, error = validate_sys_id(item_id)
    if not valid:
        logger.warning(f"Invalid item_id: {error}")
        return json.dumps({
            "success": False,
            "message": f"Invalid item_id: {error}",
            "data": None
        })

    # Validate quantity
    if quantity < 1:
        logger.warning(f"Invalid quantity: {quantity}")
        return json.dumps({
            "success": False,
            "message": "Quantity must be at least 1",
            "data": None
        })

    # Parse and clean variables JSON
    parsed_variables = {}
    if variables:
        # Clean markdown code block wrappers if present
        cleaned_variables = clean_json_from_markdown(variables)

        try:
            parsed_variables = json.loads(cleaned_variables)
            if not isinstance(parsed_variables, dict):
                logger.warning("Variables is not a JSON object")
                return json.dumps({
                    "success": False,
                    "message": "Variables must be a JSON object (dictionary), not an array or primitive",
                    "data": None
                })
            logger.debug(f"Parsed {len(parsed_variables)} variables for catalog request")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse variables JSON: {e}")
            return json.dumps({
                "success": False,
                "message": f"Invalid JSON in variables parameter: {str(e)}. Ensure proper JSON format without trailing commas.",
                "data": None
            })

    # Build the order payload for sn_sc API
    payload = {
        "sysparm_quantity": str(quantity),
        "variables": parsed_variables
    }

    # Direct API call to Service Catalog namespace (sn_sc)
    # Note: This uses a different API path than the standard Table API
    url = f"https://{SN_INSTANCE}.service-now.com/api/sn_sc/servicecatalog/items/{item_id}/order_now"

    logger.info(f"Calling Service Catalog API: POST {url}")

    try:
        response = session.post(
            url,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        result = response.json()
    except requests.exceptions.Timeout:
        logger.error(f"Request timeout after {REQUEST_TIMEOUT}s")
        return json.dumps({
            "success": False,
            "message": f"Request timeout after {REQUEST_TIMEOUT} seconds",
            "data": None
        })
    except requests.exceptions.HTTPError as e:
        error_detail = e.response.text[:500] if e.response else str(e)
        logger.error(f"HTTP error submitting catalog request: {e.response.status_code} - {error_detail}")
        return json.dumps({
            "success": False,
            "message": f"Failed to submit catalog request: HTTP {e.response.status_code}. Check that item_id is valid and all mandatory variables are provided.",
            "data": {"error_detail": error_detail}
        })
    except requests.RequestException as e:
        logger.error(f"Request failed: {e}")
        return json.dumps({
            "success": False,
            "message": f"Request failed: {str(e)}",
            "data": None
        })

    request_data = result.get("result", {})

    # Extract relevant information from the response
    request_number = request_data.get("request_number") or request_data.get("number")
    request_id = request_data.get("request_id") or request_data.get("sys_id")

    logger.info(f"Catalog request submitted successfully: {request_number}")

    return json.dumps({
        "success": True,
        "message": f"Catalog request submitted successfully: {request_number}",
        "data": {
            "request_number": request_number,
            "request_id": request_id,
            "item_id": item_id,
            "quantity": quantity,
            "table": request_data.get("table", "sc_request"),
            "redirect_url": request_data.get("redirect_url")
        }
    })


# Lancement
if __name__ == "__main__":
    mcp.run(transport='sse')
