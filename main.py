import os
import json
import logging
import requests
import sys
from typing import List, Dict, Tuple
from configparser import ConfigParser
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3 needed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config(config_path: str) -> ConfigParser:
    """Load configuration from the given file path."""
    logger.debug(f"Loading configuration from: {config_path}")
    config = ConfigParser()
    config.read(config_path)
    return config

if len(sys.argv) < 2:
    logger.error("Configuration file path must be provided as a command-line argument.")
    sys.exit(1)

config_path = sys.argv[1]
config = load_config(config_path)

WAZUH_API_URL = config.get("WAZUH", "API_URL")
WAZUH_API_USER = config.get("WAZUH", "API_USER")
WAZUH_API_PASS = config.get("WAZUH", "API_PASS")
CDB_SIZE_LIMIT = config.getint("WAZUH", "CDB_SIZE_LIMIT")

MINEMELD_API_URL = config.get("MINEMELD", "API_URL")

# Fetch feed names from the configuration file
FEED_NAMES = config.get("MINEMELD", "FEED_NAMES").split(',')

def parse_ip_range(ip_range: str) -> List[str]:
    """Parse an IP range into a list of individual IP addresses."""
    from ipaddress import ip_address
    start_ip, end_ip = ip_range.split('-')
    start_ip = ip_address(start_ip)
    end_ip = ip_address(end_ip)
    return [str(ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

def clean_url(url: str) -> str:
    """Remove http:// or https:// from the URL."""
    return url.replace("http://", "").replace("https://", "")

def parse_data(data: str, data_format: str) -> List[str]:
    """Parse data based on its format (json, xml, or plain list)."""
    if data_format == "json":
        return json.loads(data)
    elif data_format == "xml":
        import xml.etree.ElementTree as ET
        root = ET.fromstring(data)
        return [elem.text for elem in root.findall(".//indicator")]
    else:  # plain list
        return data.splitlines()

def fetch_iocs_from_feed(feed_name: str, limit: int = 10) -> Dict[str, List[str]]:
    """Fetch IOCs from a specific MineMeld feed and categorize them by type."""
    logger.debug(f"Starting to fetch IOCs from MineMeld feed: {feed_name}")
    try:
        response = requests.get(f"{MINEMELD_API_URL}/feeds/{feed_name}", headers={"Content-Type": "application/json"}, verify=False)
        response.raise_for_status()
        logger.debug(f"MineMeld API response: {response.text}")
        iocs = {"ip": [], "url": [], "hash": []}
        try:
            data_format = response.headers.get("Content-Type", "plain").split("/")[-1]
            data = parse_data(response.text, data_format)[:limit]  # Limit the number of IOCs fetched
            for value in data:
                value = value.strip()
                logger.debug(f"Processing indicator: {value}")
                if "-" in value:  # IP range
                    iocs["ip"].extend(parse_ip_range(value))
                elif "/" in value:  # CIDR notation
                    iocs["ip"].extend(parse_ip_range(value))
                elif is_valid_ip(value):
                    iocs["ip"].append(value)
                elif is_valid_url(value):
                    iocs["url"].append(clean_url(value))
                elif is_valid_hash(value):
                    iocs["hash"].append(value)
            logger.info(f"Fetched IOCs from MineMeld feed: {feed_name}")
            logger.debug(f"IOCs categorized: {iocs}")
            return iocs
        except json.JSONDecodeError as json_err:
            logger.error(f"JSON decode error: {json_err}")
            return {"ip": [], "url": [], "hash": []}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching IOCs from MineMeld feed {feed_name}: {e}")
        return {"ip": [], "url": [], "hash": []}

def fetch_current_cdb_list(cdb_name: str) -> List[str]:
    """Fetch the current CDB list from Wazuh."""
    logger.debug(f"Fetching current CDB list for: {cdb_name}")
    try:
        response = requests.get(f"{WAZUH_API_URL}/lists/{cdb_name}", headers=HEADERS, verify=False)
        response.raise_for_status()
        data = response.json().get("data", {}).get("items", [])
        logger.debug(f"Fetched CDB list for {cdb_name}: {data}")
        return data
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while fetching CDB list {cdb_name}: {http_err}")
    except Exception as err:
        logger.error(f"Other error occurred while fetching CDB list {cdb_name}: {err}")
    return []

def get_wazuh_jwt_token() -> str:
    """Retrieve JWT token from Wazuh API using basic authentication."""
    logger.debug("Retrieving JWT token from Wazuh API.")
    auth_response = requests.get(f"{WAZUH_API_URL}/security/user/authenticate", auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
    auth_response.raise_for_status()
    token = auth_response.json().get("data", {}).get("token")
    logger.debug(f"Retrieved JWT token: {token}")
    return token

def update_cdb_list(cdb_name: str, iocs: Dict[str, str], token: str) -> str:
    """Update the CDB list in Wazuh. Return the token in case it needs to be refreshed."""
    logger.debug(f"Updating CDB list: {cdb_name} with {len(iocs)} IOCs.")
    try:
        data = "\n".join(f"{ioc}:{ioc_type}" for ioc, ioc_type in iocs.items())
        headers = {
            "Content-Type": "application/octet-stream",
            "Authorization": f"Bearer {token}"
        }
        response = requests.put(f"{WAZUH_API_URL}/lists/files/{cdb_name}", headers=headers, data=data, verify=False, params={"overwrite": "true"})
        response.raise_for_status()
        logger.info(f"Successfully updated CDB list {cdb_name} with {len(iocs)} IOCs.")
        return token
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 401:
            logger.warning(f"JWT token expired or invalid. Refreshing token.")
            token = get_wazuh_jwt_token()
            return update_cdb_list(cdb_name, iocs, token)
        else:
            logger.error(f"HTTP error occurred while updating CDB list {cdb_name}: {http_err}")
            raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Error updating CDB list {cdb_name}: {e}")
        raise

def is_valid_ip(ip: str) -> bool:
    """Validate if a string is an IP address."""
    logger.debug(f"Validating IP address: {ip}")
    parts = ip.split('.')
    is_valid = len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    logger.debug(f"IP address {ip} is valid: {is_valid}")
    return is_valid


def is_valid_url(url: str) -> bool:
    """Validate if a string is a URL."""
    logger.debug(f"Validating URL: {url}")
    is_valid = url.startswith("http://") or url.startswith("https://")
    logger.debug(f"URL {url} is valid: {is_valid}")
    return is_valid


def is_valid_hash(hash_str: str) -> bool:
    """Validate if a string is a hash (MD5/SHA1/SHA256)."""
    logger.debug(f"Validating hash: {hash_str}")
    is_valid = len(hash_str) in {32, 40, 64} and all(c in "0123456789abcdefABCDEF" for c in hash_str)
    logger.debug(f"Hash {hash_str} is valid: {is_valid}")
    return is_valid


def split_data(data: List[str], max_size: int = CDB_SIZE_LIMIT) -> List[List[str]]:
    """Split data into chunks to meet the size limit."""
    logger.debug(f"Splitting data into chunks with max size {max_size}")
    chunks = []
    current_chunk = []
    current_size = 0
    for item in data:
        item_size = len(item) + 1  # Account for newline character
        if current_size + item_size > max_size:
            logger.debug(f"Chunk created with size {current_size}: {current_chunk}")
            chunks.append(current_chunk)
            current_chunk = []
            current_size = 0
        current_chunk.append(item)
        current_size += item_size
    if current_chunk:
        logger.debug(f"Final chunk created with size {current_size}: {current_chunk}")
        chunks.append(current_chunk)
    logger.info(f"Split data into {len(chunks)} chunks.")
    return chunks


def process_iocs():
    """Main function to process IOCs and update Wazuh CDB lists."""
    logger.debug("Starting IOC processing.")
    token = get_wazuh_jwt_token()
    for feed_name in FEED_NAMES:
        iocs = fetch_iocs_from_feed(feed_name, limit=50)  # Limit the number of IOCs fetched
        formatted_iocs = {}
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                if ioc_type == "ip":
                    formatted_iocs[ioc] = "any-ip"
                else:
                    formatted_iocs[ioc] = f"{ioc_type}-dst"
        cdb_name = f"{feed_name}-minemeld"
        current_cdb = set(fetch_current_cdb_list(cdb_name))
        new_iocs = {ioc: ioc_type for ioc, ioc_type in formatted_iocs.items() if ioc not in current_cdb}

        if not new_iocs:
            logger.info(f"No new IOCs to add for feed: {feed_name}.")
            continue

        logger.debug(f"New IOCs to add for feed: {feed_name}: {new_iocs}")

        # Split data into manageable chunks
        chunks = split_data(list(new_iocs.keys()))

        for idx, chunk in enumerate(chunks):
            chunk_cdb_name = f"{cdb_name}_{idx + 1}"
            chunk_data = {ioc: new_iocs[ioc] for ioc in chunk}
            logger.debug(f"Updating chunk {idx + 1} for feed: {feed_name}: {chunk_data}")
            token = update_cdb_list(chunk_cdb_name, chunk_data, token)

# Example usage
if __name__ == "__main__":
    logger.debug("Script started.")
    process_iocs()
    logger.debug("Script finished.")

