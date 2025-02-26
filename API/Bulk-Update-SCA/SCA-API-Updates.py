import requests
import json


def load_config(config_file="config.json"):
    """Loads configuration values from a JSON file."""
    with open(config_file, "r") as file:
        return json.load(file)

def generate_oauth_token(config):
    """
    Generates an OAuth token using the provided API key.

    Parameters:
        config (dict): Configuration dictionary with IAM URL, API key, and tenant name.

    Returns:
        str: The OAuth token if successful, or an error message if not.
    """
    url = f"{config['iam_url']}{config['tenant_name']}/protocol/openid-connect/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": config["api_key"]
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json().get("access_token", "Error: Access token not found.")
    return f"Error: Failed to generate token. Status: {response.status_code}, Response: {response.text}"

def get_latest_scan_id(config, headers, project_ids=[], app_ids=[], branch=None, engine=None, limit=20, offset=0, scan_status=None):
    """
    Fetch the latest scan information from Checkmarx API.

    :param config: Dictionary containing API configuration, including 'api_url'.
    :param headers: Dictionary containing authorization headers.
    :param project_ids: List of project IDs to filter by.
    :param app_ids: List of application IDs to filter by.
    :param branch: (Optional) Branch name to filter results.
    :param engine: (Optional) Scanner type (sast, sca, kics, apisec).
    :param limit: (Optional) Maximum number of results to return (default: 20).
    :param offset: (Optional) Number of results to skip (default: 0).
    :param scan_status: (Optional) Execution status filter (Queued, Running, Completed, Failed, Partial, Canceled).

    :return: JSON response with the latest scan details or None if an error occurs.
    """
    
    endpoint = f"{config['api_url']}/projects/last-scan"
    
    # Construct query parameters
    params = {
        "limit": limit,
        "offset": offset
    }
    
    if project_ids:
        params["project-ids"] = ",".join(project_ids)
    
    if app_ids:
        params["application-id"] = ",".join(app_ids)
    
    if branch:
        params["branch"] = branch
    
    if engine:
        params["engine"] = engine
    
    if scan_status:
        params["scan-status"] = scan_status

    try:
        response = requests.get(endpoint, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching latest scan data: {e}")
        return None
    

def update_sca_vulnerability_status(config, headers):
    """
    Updates the status of a vulnerability in Checkmarx SCA.

    Parameters:
        config (dict): Configuration dictionary with all necessary values.
        token (str): Bearer token for authentication.

    Returns:
        Response: The HTTP response object from the API request.
    """
    endpoint = f"{config['api_url']}/sca/management-of-risk/package-vulnerabilities"
    payload = {
        "Actions": [
            {
                "Value": "NotExploitable",
                "Comment": config["comment"],
                "ActionType": "ChangeState"
            }
        ],
        "ProjectIds": [config["project_id"]],
        "PackageName": config["package_name"],
        "PackageManager": config["package_manager"],
        "PackageVersion": config["package_version"],
        "VulnerabilityId": config["vulnerability_id"]
    }
    return requests.post(endpoint, json=payload, headers=headers)

def get_specific_scan_results(conifg,headers):
    """
    Gets a specific scan from Checkmarx SCA.

    Parameters:
        config (dict): Configuration dictionary with all necessary values.
        token (str): Bearer token for authentication.

    Returns:
        Response: The HTTP response object from the API request.
    """
    scan_id = "5ef07cc6-f3ae-4ee0-aff1-2a92afb7a5e0"
    endpoint = f"{config['api_url']}/sca/risk-management/risk-reports/{scan_id}/vulnerabilities"
    return requests.get(endpoint, headers=headers)



if __name__ == "__main__":
    # Load configuration
    config = load_config()

    # Generate OAuth token
    oauth_token = generate_oauth_token(config)

    if "Error" not in oauth_token:
        headers = {"Authorization": f"Bearer {oauth_token}", "Content-Type": "application/json"}
        # Update vulnerability status
        response = update_sca_vulnerability_status(config, headers)
        response = get_specific_scan_results(config, headers)
        # response = get_latest_scan_id(config, headers)
        # json_text = json.loads(response.text)
        if response.status_code in [200, 201]:
            print("Vulnerability status updated successfully!")
        else:
            print(f"Failed to update vulnerability status. Status: {response.status_code}, Response: {response.text}")
    else:
        print(oauth_token)
