import requests
import json


def load_config(config_file="config.json"):
    """
    Loads configuration values from a JSON file.

    Parameters:
        config_file (str): Path to the JSON configuration file.

    Returns:
        dict: Configuration values as a dictionary.
    """
    with open(config_file, "r") as file:
        return json.load(file)


def update_vulnerability_status(api_url, token, project_id, package_name, package_manager, package_version, vulnerability_id, comment, status="NotExploitable"):
    """
    Updates the status of a vulnerability in Checkmarx SCA.

    Parameters:
        api_url (str): Base URL of the Checkmarx SCA API.
        token (str): Bearer token for authentication.
        project_id (str): ID of the project affected by the vulnerability.
        package_name (str): Name of the package containing the vulnerability.
        package_manager (str): Package manager used (e.g., Maven, npm).
        package_version (str): Version of the package.
        vulnerability_id (str): ID of the vulnerability (e.g., CVE-xxxx-xxxx).
        comment (str): Justification for the status change.
        status (str): New status for the vulnerability (default: "NotExploitable").

    Returns:
        Response: The HTTP response object from the API request.
    """
    endpoint = f"{api_url}/sca/management-of-risk/package-vulnerabilities"
    payload = {
        "Actions": [
            {
                "Value": status,
                "Comment": comment,
                "ActionType": "ChangeState"
            }
        ],
        "ProjectIds": [project_id],
        "PackageName": package_name,
        "PackageManager": package_manager,
        "PackageVersion": package_version,
        "VulnerabilityId": vulnerability_id
    }
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    response = requests.post(endpoint, json=payload, headers=headers)
    return response


def generate_oauth_token(base_iam_url, api_key, tenant_name="your_tenant_name"):
    """
    Generates an OAuth token using the provided API key.

    Parameters:
        api_key (str): The API key or refresh token.
        tenant_name (str): The tenant name for the Checkmarx realm.

    Returns:
        str: The OAuth token if successful, or an error message if not.
    """
    url = f"{base_iam_url}{tenant_name}/protocol/openid-connect/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": api_key
    }
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            token = response.json().get("access_token")
            return token if token else "Error: Access token not found in response."
        else:
            return f"Error: Failed to generate token. Status code: {response.status_code}, Response: {response.text}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"


# Example usage
if __name__ == "__main__":
    config = load_config()  # Load config from JSON file

    API_URL = config["api_url"]
    API_KEY = config["api_key"]
    BASE_IAM_URL = config["iam_url"]
    TENANT_NAME = config["tenant_name"]
    PROJECT_ID = config["project_id"]
    PACKAGE_NAME = config["package_name"]
    PACKAGE_MANAGER = config["package_manager"]
    PACKAGE_VERSION = config["package_version"]
    VULNERABILITY_ID = config["vulnerability_id"]
    COMMENT = config["comment"]

    oauth_token = generate_oauth_token(base_iam_url=BASE_IAM_URL,api_key=API_KEY, tenant_name=TENANT_NAME)

    if not oauth_token.startswith("Error"):
        response = update_vulnerability_status(
            api_url=API_URL,
            token=f"Bearer {oauth_token}",
            project_id=PROJECT_ID,
            package_name=PACKAGE_NAME,
            package_manager=PACKAGE_MANAGER,
            package_version=PACKAGE_VERSION,
            vulnerability_id=VULNERABILITY_ID,
            comment=COMMENT
        )
        if response.status_code in [200, 201]:
            print("Vulnerability status updated successfully!")
        else:
            print(f"Failed to update vulnerability status. Status code: {response.status_code}")
            print(f"Response: {response.text}")
    else:
        print(f"Failed to generate OAuth token: {oauth_token}")
