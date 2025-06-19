#!/usr/bin/env python3

import os
import jinja2
import colorama
import yaml
import subprocess
import sys
import pyfiglet
import re
import json
import datetime
import prompt_toolkit 
import psutil
import requests
import boto3
import botocore
import logging
from logging.handlers import RotatingFileHandler
import getpass
import socket
from ipaddress import IPv4Network, ip_network 

# --- Global Configuration ---
# Using uppercase for constants is a common convention
CONFIG = {
    # File and Path Configuration
    'CONFIG_FILENAME': "config.yaml",
    'VERSION_FILE': "version.json",
    'LOG_DIR': "logs", # Define log directory
    'LOG_FILENAME': "deployment.log",
    'TEMPLATE_DIR': "../templates", # Relative to script location
    'CONFIG_TEMPLATE': "config.template.yaml",
    'TERRAFORM_DIR': "..", # Relative to script location
    'BACKEND_VARS_FILENAME': "backend.config.tfvars", # For terraform init -backend-config
    'CONFIG_DIR': "../config", # Config directory relative to script location

    # AWS Regions (Example subset, add more as needed or rely solely on AWS fetch)
    'AWS_REGIONS': {
        'us-east-1': 'US East (N. Virginia)',
        'us-east-2': 'US East (Ohio)',
        'us-west-1': 'US West (N. California)',
        'us-west-2': 'US West (Oregon)',
        'ca-central-1': 'Canada (Central)',
        'eu-west-1': 'EU (Ireland)',
        'eu-west-2': 'EU (London)',
        'eu-central-1': 'EU (Frankfurt)',
        'ap-southeast-1': 'Asia Pacific (Singapore)',
        'ap-southeast-2': 'Asia Pacific (Sydney)',
        'ap-northeast-1': 'Asia Pacific (Tokyo)',
        'sa-east-1': 'South America (São Paulo)',
    },

    # Version Configuration
    'DEFAULT_EXTERNAL_SECRET_VERSION': "0.15.0", # Example, adjust as needed
    'DEFAULT_EXTERNAL_SECRET_CONCURRENT': 10, # Default concurrent processing
    'MIN_PYTHON_VERSION': (3, 8), # Increased minimum slightly
    'MIN_MEMORY_GB': 4,
    'MIN_DISK_SPACE_GB': 20, # Increased slightly

    # Logging Configuration
    'LOG_MAX_BYTES': 100 * 1024 * 1024,  # 100MB
    'LOG_BACKUP_COUNT': 5,

    # Display Configuration
    'DISPLAY_WIDTH': 80,
    'MAX_ROLE_NAME_LENGTH': 64,

    # AWS Configuration
    'DEFAULT_AWS_REGION': "us-east-1",
    'DEFAULT_AWS_OUTPUT': "json",
    'DEFAULT_TERRAFORM_LOCK_TABLE': "frontegg-terraform-state-lock", # Consistent naming
    'DEFAULT_TERRAFORM_STATE_KEY': "tf-state/frontegg/terraform.tfstate", # Default S3 key

    # Instance Type Configuration (Examples, adjust based on Frontegg needs)
    'DEFAULT_MSK_INSTANCE_TYPE': "kafka.m5.large",
    'DEFAULT_MYSQL_INSTANCE_TYPE': "db.t3.medium",
    'DEFAULT_REDIS_INSTANCE_TYPE': "cache.t3.medium",
    'DEFAULT_EKS_INSTANCE_TYPES': "t3.large,m5.large,m5d.large,m6i.large", # Example list
    'DEFAULT_EKS_DEFAULT_INSTANCE_TYPES': "m6i.large,m5.large,m5d.large", # Example default subset

    # Version Ranges (Examples, adjust)
    'MIN_REDIS_VERSION': (6, 0),
    'MAX_REDIS_VERSION': (7, 2),
    'MAX_SEMANTIC_VERSION_PART': 999, # Max value for each part of MAJOR.MINOR.PATCH

    # Default Values for Configuration Prompts
    'DEFAULT_CUSTOMER': "private-env",
    'DEFAULT_ENVIRONMENT': "prod",
    'DEFAULT_VPC_CIDR': "10.0.0.0/16",
    'DEFAULT_MSK_VERSION': "3.6.0", # Example current version
    'DEFAULT_MSK_BROKER_NODES': 3,
    'DEFAULT_MSK_VOLUME_SIZE': 500,
    'DEFAULT_MSK_SCALING_MAX': 500,
    'DEFAULT_MSK_SCALING_TARGET': 60,
    'DEFAULT_MYSQL_VERSION': "8.0.40", # Example current version
    'DEFAULT_MYSQL_FAMILY': "mysql8.0",
    'DEFAULT_MYSQL_MAJOR_VERSION': "8.0",
    'DEFAULT_MYSQL_MAX_STORAGE': 500,
    'DEFAULT_MYSQL_STORAGE': 100,
    'DEFAULT_MYSQL_PORT': 3306,
    'DEFAULT_MYSQL_PERFORMANCE_RETENTION': 7,
    'DEFAULT_MYSQL_MONITORING_INTERVAL': 60,
    'DEFAULT_MYSQL_STORAGE_TYPE': "gp3", # Set default storage type
    'DEFAULT_REDIS_VERSION': "7.0", # Example current version
    'DEFAULT_REDIS_FAMILY': "redis7",
    'DEFAULT_NUM_CACHE_CLUSTERS': 2,
    'DEFAULT_EKS_VERSION': "1.32", # Example current version
    'DEFAULT_EKS_MIN_SIZE': 2,
    'DEFAULT_EKS_MAX_SIZE': 5, # Increased default max slightly
    'DEFAULT_EKS_DESIRED_SIZE': 3, # Increased default desired slightly
    'DEFAULT_EXTERNAL_SECRET_REPLICAS': 2,

    # Time Windows
    'DEFAULT_MAINTENANCE_WINDOW': "sun:04:00-sun:05:00",
    'DEFAULT_BACKUP_WINDOW': "03:00-04:00",

    # Validation Patterns
    'CIDR_PATTERN': r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',
    'MAINTENANCE_WINDOW_PATTERN': r'^(mon|tue|wed|thu|fri|sat|sun):([0-1][0-9]|2[0-3]):[0-5][0-9]-(mon|tue|wed|thu|fri|sat|sun):([0-1][0-9]|2[0-3]):[0-5][0-9]$',
    'BACKUP_WINDOW_PATTERN': r'^([0-1][0-9]|2[0-3]):[0-5][0-9]-([0-1][0-9]|2[0-3]):[0-5][0-9]$',
    'IAM_ROLE_PATTERN': r'^[a-zA-Z0-9+=,.@_-]+$',
    'EKS_CLUSTER_PATTERN': r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$', # Adjusted max length
    'EKS_VERSION_PATTERN': r'^\d+\.\d+$',
    'SEMANTIC_VERSION_PATTERN': r'^\d+\.\d+\.\d+$',
    'REDIS_VERSION_PATTERN': r'^\d+\.\d+$',
    'AWS_ACCESS_KEY_PATTERN': r'^(AKIA|AIDA|ASIA)[0-9A-Z]{16}$', # More specific pattern
    'S3_BUCKET_PATTERN': r'^(?=.{3,63}$)(?!xn--|.*-s3alias$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)([a-z0-9][a-z0-9.-]*[a-z0-9])$', # Refined S3 pattern
}

# Global variables derived from CONFIG
AVAILABLE_AWS_REGIONS = None
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILEPATH = os.path.join(os.path.dirname(SCRIPT_DIR), "config", CONFIG['CONFIG_FILENAME'])
VERSION_FILEPATH = os.path.join(SCRIPT_DIR, CONFIG['VERSION_FILE'])
LOG_DIR_PATH = os.path.join(SCRIPT_DIR, CONFIG['LOG_DIR'])
LOG_FILEPATH = os.path.join(LOG_DIR_PATH, CONFIG['LOG_FILENAME'])
TEMPLATE_DIR_PATH = os.path.join(SCRIPT_DIR, CONFIG['TEMPLATE_DIR'])
TERRAFORM_DIR_PATH = os.path.join(SCRIPT_DIR, CONFIG['TERRAFORM_DIR'])
BACKEND_VARS_FILEPATH = os.path.join(TERRAFORM_DIR_PATH, CONFIG['BACKEND_VARS_FILENAME'])

# Initialize colorama
colorama.init()

# --- Logging Setup ---
def setup_logging():
    """Configure logging to write to both file and console."""
    os.makedirs(LOG_DIR_PATH, exist_ok=True)
    log_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    root_logger = logging.getLogger()
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    file_handler = RotatingFileHandler(
        LOG_FILEPATH,
        maxBytes=CONFIG['LOG_MAX_BYTES'],
        backupCount=CONFIG['LOG_BACKUP_COUNT']
    )
    file_handler.setFormatter(log_format)

    # Console handler (optional, prints logs to screen too)
    # console_handler = logging.StreamHandler()
    # console_handler.setFormatter(log_format)
    # console_handler.setLevel(logging.INFO) # Or DEBUG

    root_logger.setLevel(logging.INFO) # Set root level
    root_logger.addHandler(file_handler)
    # root_logger.addHandler(console_handler) # Uncomment to log to console

    root_logger.propagate = False
    logging.info("--- Logging system initialized ---")
    user = getpass.getuser()
    computer_name = socket.gethostname()
    logging.info(f"Script started by user: {user} on host: {computer_name}")

# --- Output Formatting Functions ---
# (print_section, print_error, print_success, print_warning, print_info, etc.)
# These seem well-implemented, keeping them largely the same but adding logging calls if missing.
# --- Output Formatting Functions ---
# (Existing functions like print_section, print_error, etc.)

# ADD THIS FUNCTION DEFINITION BACK:
def print_subsection(title):
    """Print a subsection title with color."""
    print(f"\n{colorama.Fore.MAGENTA}{colorama.Style.BRIGHT}--- {title} ---{colorama.Style.RESET_ALL}")
    logging.info(f"Subsection: {title}")

# (Other existing functions like print_info, print_step_header, etc.)
def print_section(title):
    """Print a section title with color and borders."""
    width = CONFIG['DISPLAY_WIDTH']
    print(f"\n{colorama.Fore.CYAN}{colorama.Style.BRIGHT}{'='*width}")
    print(f"{'='*2} {title.upper()} {'='*(width-4-len(title))}")
    print(f"{'='*width}{colorama.Style.RESET_ALL}\n")
    logging.info(f"--- Section: {title} ---")

def print_error(message):
    """Print an error message in red."""
    print(f"{colorama.Fore.RED}{colorama.Style.BRIGHT}❌ ERROR: {message}{colorama.Style.RESET_ALL}")
    logging.error(message)

def print_success(message):
    """Print a success message in green."""
    print(f"{colorama.Fore.GREEN}{colorama.Style.BRIGHT}✅ SUCCESS: {message}{colorama.Style.RESET_ALL}")
    logging.info(f"Success: {message}")

def print_warning(message):
    """Print a warning message in yellow."""
    print(f"{colorama.Fore.YELLOW}{colorama.Style.BRIGHT}⚠️ WARNING: {message}{colorama.Style.RESET_ALL}")
    logging.warning(message)

def print_info(message):
    """Print an info message in blue."""
    print(f"{colorama.Fore.BLUE}{colorama.Style.BRIGHT}ℹ️ INFO: {message}{colorama.Style.RESET_ALL}")
    logging.info(message)

def colorize_yaml(yaml_str):
    """Add colors to YAML output for better readability."""
    # Define color schemes for different YAML elements
    key_color = colorama.Fore.CYAN
    string_color = colorama.Fore.GREEN
    number_color = colorama.Fore.YELLOW
    boolean_color = colorama.Fore.MAGENTA
    comment_color = colorama.Fore.BLUE
    reset = colorama.Style.RESET_ALL
    
    # Process the YAML string line by line
    colored_lines = []
    for line in yaml_str.split('\n'):
        # Skip empty lines
        if not line.strip():
            colored_lines.append(line)
            continue
            
        # Handle comments
        if line.strip().startswith('#'):
            colored_lines.append(f"{comment_color}{line}{reset}")
            continue
            
        # Find the key-value separator
        parts = line.split(':', 1)
        if len(parts) == 2:
            key = parts[0]
            value = parts[1].strip()
            
            # Color the key
            colored_line = f"{key_color}{key}{reset}:"
            
            # Color the value based on its type
            if value:
                if value.lower() in ('true', 'false', 'yes', 'no', 'null'):
                    colored_line += f" {boolean_color}{value}{reset}"
                elif value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                    colored_line += f" {number_color}{value}{reset}"
                elif value.startswith('[') or value.startswith('{'):
                    colored_line += f" {string_color}{value}{reset}"
                else:
                    colored_line += f" {string_color}{value}{reset}"
            else:
                # Empty value (just a colon)
                colored_line += " "
                
            colored_lines.append(colored_line)
        else:
            # Line without a colon (likely a list item or special YAML syntax)
            if line.strip().startswith('-'):
                # List item
                colored_lines.append(f"{string_color}{line}{reset}")
            else:
                # Other YAML syntax
                colored_lines.append(line)
    
    return '\n'.join(colored_lines)

def print_welcome_message():
    """Print a welcome message with color."""
    # Log ASCII art first if possible
    try:
        ascii_art = pyfiglet.figlet_format("Frontegg\nPrivate Env Setup", justify='center', width=CONFIG['DISPLAY_WIDTH'])
        logging.info("\n" + ascii_art)
        print(f"{colorama.Fore.CYAN}{colorama.Style.BRIGHT}{ascii_art}{colorama.Style.RESET_ALL}")
    except Exception as e:
        logging.warning(f"Could not generate pyfiglet art: {e}")
        print(f"{colorama.Fore.CYAN}{colorama.Style.BRIGHT}--- Frontegg Private Environment Setup ---{colorama.Style.RESET_ALL}")

    print(f"\n{colorama.Fore.BLUE}{colorama.Style.BRIGHT}Welcome! This tool helps configure and manage Frontegg Private Cloud environments on AWS.{colorama.Style.RESET_ALL}")
    print(f"{colorama.Fore.WHITE}It uses Terraform to provision and manage the required AWS resources.")
    print(f"Visit Frontegg: {colorama.Fore.CYAN}https://frontegg.com{colorama.Style.RESET_ALL}\n")
    print_version()
    logging.info("Welcome message displayed")

def get_version():
    """Get the current version from the version file."""
    try:
        if os.path.exists(VERSION_FILEPATH):
            with open(VERSION_FILEPATH, 'r') as f:
                version_data = json.load(f)
                return version_data.get('version', '0.0.0')
        return '0.0.0' # Default if file doesn't exist
    except (json.JSONDecodeError, IOError, OSError) as e:
        print_error(f"Error reading version file ({VERSION_FILEPATH}): {e}")
        logging.error(f"Error reading version file: {e}")
        return '0.0.0' # Fallback version

def save_version(version_str):
    """Save the version to the version file."""
    try:
        # Validate format before saving
        if not re.match(r'^\d+\.\d+\.\d+$', version_str):
            raise ValueError("Invalid version format. Must be X.Y.Z")

        version_data = {
            'version': version_str,
            'last_updated': datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        with open(VERSION_FILEPATH, 'w') as f:
            json.dump(version_data, f, indent=2)
        logging.info(f"Version saved: {version_str}")
        return True
    except (IOError, OSError, ValueError) as e:
        print_error(f"Error saving version file ({VERSION_FILEPATH}): {e}")
        logging.error(f"Error saving version file: {e}")
        return False

def print_version():
    """Print the current version."""
    version = get_version()
    print(f"{colorama.Fore.BLUE}Script Version: {version}{colorama.Style.RESET_ALL}")
    logging.info(f"Current script version: {version}")


# --- Input and Validation Functions ---
def get_input(prompt, default=None, is_boolean=False, is_secret=False, validator=None, error_message="Invalid input."):
    """Enhanced helper function to get user input."""
    prompt_suffix = f" [{default}]" if default is not None else ""
    if is_boolean:
        default_str = 'y' if str(default).lower() in ['true', 'yes', 'y'] else 'n'
        prompt_suffix = f" (y/n) [{default_str}]"
    
    # full_prompt = f"{colorama.Fore.WHITE}{colorama.Style.BRIGHT}{prompt}{prompt_suffix}: {colorama.Style.RESET_ALL}"
    full_prompt = f"{prompt}{prompt_suffix}: "
    logging.info(f"Input prompt: {prompt}{prompt_suffix}")

    session = prompt_toolkit.PromptSession()

    while True:
        try:
            if is_secret:
                user_input_str = session.prompt(full_prompt, is_password=True)
            else:
                user_input_str = session.prompt(full_prompt)

            user_input_str = user_input_str.strip()

            # Handle default value
            if not user_input_str and default is not None:
                user_input = default
                # Ensure boolean default is handled correctly
                if is_boolean:
                     user_input = str(default).lower() in ['true', 'yes', 'y']
                # Validate the default value if validator exists
                if validator and not validator(str(user_input)): # Validate string representation
                     print_error(f"Default value '{default}' is invalid. {error_message}")
                     pass # Allow default even if validator *would* fail it if typed
                logging.info(f"User input (default): {user_input}")
                return user_input # Return the original type of default

            # Handle boolean input
            if is_boolean:
                clean_input = user_input_str.lower()
                if clean_input in ['y', 'yes']:
                    logging.info("User input: Yes")
                    return True
                elif clean_input in ['n', 'no']:
                    logging.info("User input: No")
                    return False
                else:
                    print_error("Please enter 'y' for yes or 'n' for no.")
                    continue # Re-prompt

            # Handle general validation
            if validator:
                if validator(user_input_str):
                    logging.info(f"User input: '{user_input_str}' (validated)")
                    return user_input_str # Return validated string
                else:
                    print_error(error_message)
                    # Log the failed input for debugging validation issues
                    logging.warning(f"Validation failed for input: '{user_input_str}' - Validator: {validator.__name__ if hasattr(validator, '__name__') else 'lambda'}")
                    continue # Re-prompt
            else:
                 logging.info(f"User input: '{user_input_str}' (no validation)")
                 return user_input_str # Return string if no validator

        except EOFError:
            print_error("\nInput cancelled (EOF). Exiting.")
            logging.warning("Input cancelled by EOF")
            sys.exit(1)
        except KeyboardInterrupt:
            print_error("\nInput cancelled by user. Exiting.")
            logging.warning("Input cancelled by user (KeyboardInterrupt)")
            sys.exit(1)


# --- Specific Validators (Adapted from original, improved where possible) ---

def validate_aws_region(region):
    """Validate AWS region format using known regions (can be fetched too)."""
    # Simple pattern check first
    if not re.match(r'^[a-z]{2}-[a-z]+-\d$', region):
        return False
    # Check against known good list (can be augmented by fetching live)
    known_regions = set(CONFIG['AWS_REGIONS'].keys())
    # Add more potential regions or fetch dynamically if needed
    # known_regions.update(get_live_aws_regions()) # Example dynamic fetch
    return region in known_regions

def validate_cidr(cidr):
    """Validate CIDR block format and basic correctness."""
    if not re.match(CONFIG['CIDR_PATTERN'], cidr):
        return False
    try:
        ip_network(cidr, strict=False) # Use ipaddress library for robust check
        return True
    except ValueError:
        return False

def validate_cidr_list(cidrs_str, vpc_cidr=None):
    """Validate a comma-separated list of CIDR blocks for format and overlaps."""
    if not cidrs_str: # Allow empty list if that's valid in context
        print_warning("CIDR list is empty.")
        return True # Or False depending on whether empty is allowed

    cidr_list = [cidr.strip() for cidr in cidrs_str.split(',') if cidr.strip()]
    if not cidr_list:
        print_warning("CIDR list is empty after stripping.")
        return True # Or False

    networks = []
    for cidr in cidr_list:
        if not validate_cidr(cidr):
            print_error(f"Invalid CIDR format: {cidr}")
            return False
        try:
            networks.append(ip_network(cidr, strict=False))
        except ValueError as e:
             print_error(f"Error parsing CIDR {cidr}: {e}")
             return False

    # Check for overlaps within the list
    for i in range(len(networks)):
        for j in range(i + 1, len(networks)):
            if networks[i].overlaps(networks[j]):
                print_error(f"CIDR blocks overlap: {networks[i]} and {networks[j]}")
                return False

    # Check if subnets are within VPC CIDR if provided
    if vpc_cidr:
        if not validate_cidr(vpc_cidr):
             print_error(f"Invalid VPC CIDR provided for comparison: {vpc_cidr}")
             return False # Cannot compare
        try:
            vpc_net = ip_network(vpc_cidr, strict=False)
            for net in networks:
                # Note: subnet_of was deprecated, use explicit checks
                if not (net.network_address >= vpc_net.network_address and
                        net.broadcast_address <= vpc_net.broadcast_address):
                     print_error(f"CIDR block {net} is not within VPC range {vpc_net}")
                     return False
        except ValueError as e:
             print_error(f"Error parsing VPC CIDR {vpc_cidr}: {e}")
             return False

    return True

def validate_semantic_version(version):
    """Validate semantic version format (e.g., 1.2.3)."""
    if not isinstance(version, str) or not re.match(CONFIG['SEMANTIC_VERSION_PATTERN'], version):
        return False
    parts = version.split('.')
    max_part = CONFIG['MAX_SEMANTIC_VERSION_PART']
    return all(0 <= int(part) <= max_part for part in parts)

def validate_redis_version(version):
    """Validate Redis version format (e.g., 7.0) and range."""
    if not isinstance(version, str) or not re.match(CONFIG['REDIS_VERSION_PATTERN'], version):
        return False
    try:
        major, minor = map(int, version.split('.'))
        min_major, min_minor = CONFIG['MIN_REDIS_VERSION']
        max_major, max_minor = CONFIG['MAX_REDIS_VERSION']
        # Check lower bound
        if major < min_major or (major == min_major and minor < min_minor):
            return False
        # Check upper bound
        if major > max_major or (major == max_major and minor > max_minor):
            return False
        return True
    except ValueError:
        return False

def validate_positive_int(value):
    """Validate that input is a string representing a positive integer."""
    try:
        num = int(value)
        return num > 0
    except (ValueError, TypeError):
        return False

def validate_non_negative_int(value):
    """Validate that input is a string representing a non-negative integer."""
    try:
        num = int(value)
        return num >= 0
    except (ValueError, TypeError):
        return False

def validate_instance_type(instance_type):
    """Basic validation for AWS instance type format (can be refined)."""
    # Example: t3.medium, m5.large, db.t3.medium, cache.t3.medium, kafka.m5.large
    return bool(re.match(r'^[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$', instance_type)) or \
           bool(re.match(r'^[a-zA-Z0-9]+\.[a-zA-Z0-9]+$', instance_type))


def validate_iam_role_name(role_name):
    """Validate AWS IAM role name format and length."""
    if not (1 <= len(role_name) <= CONFIG['MAX_ROLE_NAME_LENGTH']):
        return False
    # AWS IAM role names can contain alphanumeric characters and symbols: + = , . @ _ -
    return bool(re.match(CONFIG['IAM_ROLE_PATTERN'], role_name))

def validate_maintenance_window(window):
    """Validate maintenance window format (e.g., sun:04:00-sun:05:00)."""
    if not isinstance(window, str) or not re.match(CONFIG['MAINTENANCE_WINDOW_PATTERN'], window.lower()):
        return False
    try:
        start_part, end_part = window.lower().split('-')
        start_day, start_hour, start_minute = start_part.split(':')
        end_day, end_hour, end_minute = end_part.split(':')
        # Simple duration check (must be at least 60 mins based on AWS docs usually)
        # This validation could be more complex checking actual day order if needed
        start_total_minutes = int(start_hour) * 60 + int(start_minute)
        end_total_minutes = int(end_hour) * 60 + int(end_minute)
        # Assuming same day for simplicity here, AWS might allow cross-day windows
        if start_day == end_day and end_total_minutes <= start_total_minutes:
             return False
        # Add more complex day/time logic if needed
        return True
    except ValueError:
        return False

def validate_backup_window(window):
    """Validate backup window format (e.g., 03:00-04:00)."""
    if not isinstance(window, str) or not re.match(CONFIG['BACKUP_WINDOW_PATTERN'], window):
        return False
    try:
        start_part, end_part = window.split('-')
        start_hour, start_minute = map(int, start_part.split(':'))
        end_hour, end_minute = map(int, end_part.split(':'))
        start_total_minutes = start_hour * 60 + start_minute
        end_total_minutes = end_hour * 60 + end_minute
        # Basic check: end time must be after start time
        if end_total_minutes <= start_total_minutes:
            return False
        # AWS requires minimum 30 min duration typically
        if (end_total_minutes - start_total_minutes) < 30:
            print_warning("Backup window duration is less than 30 minutes.")
            # Allow it but warn, or return False if strict
        return True
    except ValueError:
        return False


def validate_eks_version(version):
    """Validate EKS Kubernetes version format (e.g., 1.29)."""
    return isinstance(version, str) and bool(re.match(CONFIG['EKS_VERSION_PATTERN'], version))


def validate_s3_bucket_name(bucket_name):
    """Validate S3 bucket name according to AWS rules using refined regex."""
    return isinstance(bucket_name, str) and bool(re.match(CONFIG['S3_BUCKET_PATTERN'], bucket_name))

def validate_aws_access_key(access_key):
    """Validate AWS access key format more specifically."""
    return isinstance(access_key, str) and bool(re.match(CONFIG['AWS_ACCESS_KEY_PATTERN'], access_key))

def validate_aws_secret_key(secret_key):
    """Validate AWS secret key format (length and printable chars)."""
    if not isinstance(secret_key, str) or len(secret_key) != 40:
        return False
    # Check if all characters are printable ASCII (basic check)
    return all(32 <= ord(c) <= 126 for c in secret_key)

def validate_yaml_file(filepath):
    """Validate that a file contains valid YAML."""
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print_success(f"YAML validation successful for {os.path.basename(filepath)}")
        logging.info(f"YAML validation successful for {filepath}")
        return True
    except yaml.YAMLError as e:
        print_error(f"YAML validation failed for {os.path.basename(filepath)}: {e}")
        logging.error(f"YAML validation failed for {filepath}: {e}")
        return False
    except (IOError, OSError) as e:
        print_error(f"Could not read file for YAML validation: {filepath} - {e}")
        logging.error(f"Could not read file for YAML validation: {filepath} - {e}")
        return False

def validate_redis_endpoint(endpoint):
    """Validate that the Redis endpoint is reachable (TCP connect)."""
    if not endpoint:
        print_error("No Redis endpoint provided.")
        return False
    try:
        # Split host:port
        if ':' not in endpoint:
            print_error("Redis endpoint must be in host:port format.")
            return False
        host, port = endpoint.split(':', 1)
        port = int(port)
        print_info(f"Attempting to connect to Redis endpoint {host}:{port} ...")
        logging.info(f"Attempting to connect to Redis endpoint {host}:{port} ...")
        with socket.create_connection((host, port), timeout=5):
            print_success(f"Successfully connected to Redis endpoint '{endpoint}'.")
            logging.info(f"Successfully connected to Redis endpoint '{endpoint}'.")
            return True
    except Exception as e:
        print_error(f"Could not connect to Redis endpoint '{endpoint}': {e}")
        logging.error(f"Could not connect to Redis endpoint '{endpoint}': {e}")
        return False

def validate_mysql_endpoint(endpoint):
    """Validate that the MySQL endpoint is reachable (TCP connect)."""
    if not endpoint:
        print_error("No MySQL endpoint provided.")
        return False
    try:
        # Allow host or host:port
        if ':' in endpoint:
            host, port = endpoint.split(':', 1)
            port = int(port)
        else:
            host = endpoint
            port = 3306
        print_info(f"Attempting to connect to MySQL endpoint {host}:{port} ...")
        logging.info(f"Attempting to connect to MySQL endpoint {host}:{port} ...")
        with socket.create_connection((host, port), timeout=5):
            print_success(f"Successfully connected to MySQL endpoint '{host}:{port}'.")
            logging.info(f"Successfully connected to MySQL endpoint '{host}:{port}'.")
            return True
    except Exception as e:
        print_error(f"Could not connect to MySQL endpoint '{endpoint}': {e}")
        logging.error(f"Could not connect to MySQL endpoint '{endpoint}': {e}")
        return False


# --- AWS Credential Management ---

def check_aws_credentials_configured():
    """Check if AWS credentials seem configured (via env vars or ~/.aws). Returns True/False."""
    # Check environment variables first
    if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
        logging.info("AWS credentials found in environment variables.")
        return True
    # Check shared credential file
    shared_credentials_file = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(shared_credentials_file):
        # Basic check, doesn't validate content deeply here
        logging.info(f"AWS credentials file found at {shared_credentials_file}.")
        return True
    logging.info("AWS credentials not found in environment variables or ~/.aws/credentials.")
    return False

def get_aws_identity(boto_session=None):
    """Get AWS caller identity using provided boto3 session or default."""
    try:
        if boto_session:
             sts = boto_session.client('sts')
        else:
             sts = boto3.client('sts') # Use default session resolution
        identity = sts.get_caller_identity()
        logging.info(f"AWS Identity: Account={identity.get('Account')}, UserID={identity.get('UserId')}, ARN={identity.get('Arn')}")
        return identity
    except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as e:
        logging.warning(f"Failed to get AWS caller identity: {e}")
        return None

def setup_aws_credentials_interactive():
    """Interactively prompt user for AWS credentials and configure ~/.aws files."""
    print_section("AWS Credential Setup (Interactive)")
    print_info("Please enter your AWS credentials. These will be saved to ~/.aws/credentials.")
    print_warning("Ensure you have the necessary permissions for the intended operations.")

    access_key = get_input(
        "AWS Access Key ID",
        validator=validate_aws_access_key,
        error_message="Invalid Access Key ID format.",
        is_secret=False # Access Keys are not typically treated as secrets like Secret Keys
    )
    secret_key = get_input(
        "AWS Secret Access Key",
        validator=validate_aws_secret_key,
        error_message="Invalid Secret Access Key format (must be 40 printable chars).",
        is_secret=True
    )
    session_token = None
    if access_key.startswith('ASIA'):
        print_info("Temporary credentials (ASIA prefix) detected.")
        session_token = get_input("AWS Session Token (if applicable)", is_secret=True)
        if not session_token:
             print_warning("No session token provided for temporary credentials.")
             # Allow proceeding but it might fail later

    # Get default region
    available_regions = get_cached_aws_regions() # Fetch or use static list
    selected_region = get_region_selection(available_regions, CONFIG['DEFAULT_AWS_REGION'])

    # Configure ~/.aws files
    try:
        aws_dir = os.path.expanduser('~/.aws')
        os.makedirs(aws_dir, exist_ok=True)

        # Write credentials file
        credentials_path = os.path.join(aws_dir, 'credentials')
        with open(credentials_path, 'w') as f:
            f.write("[default]\n")
            f.write(f"aws_access_key_id = {access_key}\n")
            f.write(f"aws_secret_access_key = {secret_key}\n")
            if session_token:
                f.write(f"aws_session_token = {session_token}\n")
        os.chmod(credentials_path, 0o600) # Set permissions
        logging.info(f"Credentials written to {credentials_path}")

        # Write config file
        config_path = os.path.join(aws_dir, 'config')
        with open(config_path, 'w') as f:
            f.write("[default]\n")
            f.write(f"region = {selected_region}\n")
            f.write(f"output = {CONFIG['DEFAULT_AWS_OUTPUT']}\n")
        os.chmod(config_path, 0o600) # Set permissions
        logging.info(f"Config written to {config_path}")

        print_success("AWS credentials have been configured in ~/.aws/")
        return True

    except (IOError, OSError) as e:
        print_error(f"Failed to write AWS configuration files: {e}")
        logging.error(f"Failed to write AWS configuration files: {e}")
        return False

def ensure_aws_credentials():
    """Check if AWS credentials are valid, prompt for setup if not."""
    print_info("Checking AWS credentials...")
    identity = get_aws_identity() # Try default resolution first

    if identity:
        print_success("AWS credentials are configured and valid.")
        print_info(f"Account: {identity.get('Account', 'N/A')}")
        print_info(f"User ID: {identity.get('UserId', 'N/A')}")
        if 'Arn' in identity:
            print_info(f"AWS Identity: {identity['Arn']}")
        if identity.get('UserId', '').startswith('ASIA'):
             print_warning("Temporary credentials (ASIA) detected.")
        return True
    else:
        print_warning("Could not validate AWS credentials using default methods.")
        if check_aws_credentials_configured():
             print_warning("Credentials might be configured but are invalid or lack permissions.")
             # Ask user if they want to reconfigure
             reconfigure = get_input("Credentials seem invalid. Reconfigure interactively?", default=False, is_boolean=True)
             if reconfigure:
                 return setup_aws_credentials_interactive()
             else:
                 print_error("Proceeding with potentially invalid credentials.")
                 logging.error("Proceeding with potentially invalid credentials.")
                 # Allow proceeding but it will likely fail
                 return False # Indicate failure to ensure valid creds
        else:
             print_info("AWS credentials are not configured.")
             configure_now = get_input("Configure AWS credentials interactively now?", default=True, is_boolean=True)
             if configure_now:
                 return setup_aws_credentials_interactive()
             else:
                 print_error("AWS credentials setup skipped. Cannot proceed with AWS operations.")
                 logging.error("AWS credentials setup skipped.")
                 return False


# --- AWS Resource Interaction ---
def get_cached_aws_regions():
    global AVAILABLE_AWS_REGIONS
    if AVAILABLE_AWS_REGIONS is None:
        AVAILABLE_AWS_REGIONS = get_available_aws_regions()
    return AVAILABLE_AWS_REGIONS

def get_available_aws_regions():
    """Get list of available AWS regions, preferring live data, fallback to static."""
    print_info("Fetching available AWS regions...")
    enabled_regions_map = {}
    try:
        # Use default session resolution (needs configured creds)
        ec2 = boto3.client('ec2', region_name=CONFIG['DEFAULT_AWS_REGION']) # Use a default region for the initial call
        response = ec2.describe_regions(AllRegions=False) # Get only enabled regions
        # Map region code to descriptive name from our CONFIG or region itself
        for region_info in response['Regions']:
            code = region_info['RegionName']
            enabled_regions_map[code] = CONFIG['AWS_REGIONS'].get(code, code) # Use config name or code itself
        print_success(f"Fetched {len(enabled_regions_map)} enabled AWS regions.")
        logging.info(f"Fetched {len(enabled_regions_map)} enabled AWS regions.")
        # Sort by region code for consistent display
        return dict(sorted(enabled_regions_map.items()))
    except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError, Exception) as e:
        print_warning(f"Failed to fetch live AWS regions: {e}. Using static list.")
        logging.warning(f"Failed to fetch live AWS regions: {e}. Using static list.")
        return dict(sorted(CONFIG['AWS_REGIONS'].items())) # Return sorted static list

def print_region_menu(regions_map, selected_region=None):
    """Print a formatted, colorful menu of available AWS regions. Optionally highlight the selected region."""
    if not regions_map:
        print_error("No AWS regions available to display.")
        return

    print(f"\n{colorama.Fore.CYAN}{colorama.Style.BRIGHT}Available AWS Regions:{colorama.Style.RESET_ALL}")
    idx = 1
    region_list_for_selection = []
    max_code_len = max(len(code) for code in regions_map.keys())
    max_name_len = max(len(name) for name in regions_map.values())

    border_color = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    header_color = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    code_colors = [colorama.Fore.GREEN, colorama.Fore.CYAN]
    name_colors = [colorama.Fore.WHITE, colorama.Fore.LIGHTBLACK_EX]
    highlight_style = colorama.Back.YELLOW + colorama.Fore.BLACK + colorama.Style.BRIGHT

    print(f"{border_color}" + "-" * (max_code_len + max_name_len + 10) + f"{colorama.Style.RESET_ALL}")
    print(f"{header_color}{'#':<4} {'Code':<{max_code_len}}   {'Name':<{max_name_len}}{colorama.Style.RESET_ALL}")
    print(f"{border_color}" + "-" * (max_code_len + max_name_len + 10) + f"{colorama.Style.RESET_ALL}")

    for i, (code, name) in enumerate(regions_map.items()):
        code_color = code_colors[i % len(code_colors)]
        name_color = name_colors[i % len(name_colors)]
        if selected_region and code == selected_region:
            print(f"{highlight_style}{idx:<4} {code:<{max_code_len}}   {name:<{max_name_len}}{colorama.Style.RESET_ALL}")
        else:
            print(f"{colorama.Fore.WHITE}{idx:<4}{colorama.Style.RESET_ALL} "
                  f"{code_color}{code:<{max_code_len}}{colorama.Style.RESET_ALL}   "
                  f"{name_color}{name:<{max_name_len}}{colorama.Style.RESET_ALL}")
        region_list_for_selection.append(code)
        idx += 1
    print(f"{border_color}" + "-" * (max_code_len + max_name_len + 10) + f"{colorama.Style.RESET_ALL}")
    return region_list_for_selection # Return list in display order

def get_region_selection(regions_map, default_region_code):
    """Get user selection for AWS region from the displayed menu."""
    ordered_regions = print_region_menu(regions_map, selected_region=default_region_code)
    if not ordered_regions:
        print_error("Cannot select region, no regions available.")
        return None

    default_index_str = ""
    if default_region_code in ordered_regions:
        default_index = ordered_regions.index(default_region_code) + 1
        default_index_str = str(default_index)

    while True:
        selection = get_input(f"Select region number (1-{len(ordered_regions)})", default=default_index_str)
        try:
            index = int(selection) - 1
            if 0 <= index < len(ordered_regions):
                selected = ordered_regions[index]
                # Reprint menu with the newly selected region highlighted
                print_region_menu(regions_map, selected_region=selected)
                print_success(f"Selected region: {selected} ({regions_map[selected]})")
                logging.info(f"User selected region {index+1}: {selected}")
                return selected
            else:
                print_error(f"Invalid number. Please enter between 1 and {len(ordered_regions)}.")
        except (ValueError, TypeError):
            print_error("Invalid input. Please enter a number.")

def _get_boto_client(service_name, region_name):
    """Helper to get a boto3 client, handling potential errors."""
    try:
        # Uses default credential resolution chain (env, ~/.aws, IAM role)
        client = boto3.client(service_name, region_name=region_name)
        return client
    except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ClientError) as e:
        print_error(f"Failed to create boto3 client for {service_name} in {region_name}: {e}")
        logging.error(f"Failed to create boto3 client for {service_name} in {region_name}: {e}")
        return None

def ensure_s3_bucket(bucket_name, region):
    """Check if S3 bucket exists, create if not. Enable versioning & encryption."""
    s3 = _get_boto_client('s3', region_name=region) # Use region for client
    if not s3: return False

    try:
        # head_bucket checks existence and permissions
        s3.head_bucket(Bucket=bucket_name)
        print_success(f"S3 bucket '{bucket_name}' exists and is accessible in region {region}.")
        logging.info(f"S3 bucket '{bucket_name}' exists in {region}.")
        # Optionally verify versioning/encryption status here if needed
        return True
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code')
        if error_code == '404': # Not Found
            print_warning(f"S3 bucket '{bucket_name}' not found in region {region}. Attempting creation...")
            logging.info(f"S3 bucket '{bucket_name}' not found in {region}. Creating...")
            try:
                # Handle us-east-1 specific create_bucket location constraint
                if region == 'us-east-1':
                    s3.create_bucket(Bucket=bucket_name)
                else:
                    s3.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': region}
                    )
                print_success(f"Successfully created S3 bucket '{bucket_name}' in {region}.")
                logging.info(f"Successfully created S3 bucket '{bucket_name}' in {region}.")

                # Wait for bucket to exist before configuring
                waiter = s3.get_waiter('bucket_exists')
                waiter.wait(Bucket=bucket_name)

                # Enable Versioning
                s3.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': 'Enabled'})
                print_success(f"Enabled versioning for bucket '{bucket_name}'.")
                logging.info(f"Enabled versioning for bucket '{bucket_name}'.")

                # Enable Encryption (SSE-S3)
                s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
                    }
                )
                print_success(f"Enabled server-side encryption (AES256) for bucket '{bucket_name}'.")
                logging.info(f"Enabled SSE-S3 for bucket '{bucket_name}'.")
                return True
            except (botocore.exceptions.ClientError, Exception) as create_err:
                print_error(f"Failed to create or configure S3 bucket '{bucket_name}': {create_err}")
                logging.error(f"Failed to create/configure S3 bucket '{bucket_name}': {create_err}")
                return False
        elif error_code == '403': # Forbidden
             print_error(f"Access denied to S3 bucket '{bucket_name}'. Check permissions.")
             logging.error(f"Access denied (403) to S3 bucket '{bucket_name}'.")
             return False
        else: # Other errors
             print_error(f"Error checking S3 bucket '{bucket_name}': {e}")
             logging.error(f"Error checking S3 bucket '{bucket_name}': {e}")
             return False

def ensure_dynamodb_table(table_name, region):
    """Check if DynamoDB table exists, create if not (for Terraform locking)."""
    dynamodb = _get_boto_client('dynamodb', region_name=region)
    if not dynamodb: return False

    try:
        dynamodb.describe_table(TableName=table_name)
        print_success(f"DynamoDB table '{table_name}' exists and is accessible in {region}.")
        logging.info(f"DynamoDB table '{table_name}' exists in {region}.")
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print_warning(f"DynamoDB table '{table_name}' not found in {region}. Attempting creation...")
            logging.info(f"DynamoDB table '{table_name}' not found in {region}. Creating...")
            try:
                dynamodb.create_table(
                    TableName=table_name,
                    AttributeDefinitions=[{'AttributeName': 'LockID', 'AttributeType': 'S'}],
                    KeySchema=[{'AttributeName': 'LockID', 'KeyType': 'HASH'}],
                    BillingMode='PAY_PER_REQUEST' # Use On-Demand capacity
                )
                print_success(f"Initiated creation of DynamoDB table '{table_name}'. Waiting for activation...")
                logging.info(f"Initiated creation of DynamoDB table '{table_name}'.")

                # Wait for table to become active
                waiter = dynamodb.get_waiter('table_exists')
                waiter.wait(TableName=table_name, WaiterConfig={'Delay': 5, 'MaxAttempts': 24}) # Wait up to 2 mins
                print_success(f"DynamoDB table '{table_name}' is now active.")
                logging.info(f"DynamoDB table '{table_name}' is now active.")
                return True
            except (botocore.exceptions.ClientError, Exception) as create_err:
                print_error(f"Failed to create DynamoDB table '{table_name}': {create_err}")
                logging.error(f"Failed to create DynamoDB table '{table_name}': {create_err}")
                return False
        else:
            print_error(f"Error checking DynamoDB table '{table_name}': {e}")
            logging.error(f"Error checking DynamoDB table '{table_name}': {e}")
            return False

def validate_vpc_id(vpc_id, region):
    """Validate that a VPC ID exists in the specified region using boto3."""
    if not vpc_id or not region: return False
    ec2 = _get_boto_client('ec2', region_name=region)
    if not ec2: return False
    try:
        response = ec2.describe_vpcs(VpcIds=[vpc_id])
        if response.get('Vpcs'):
            vpc_data = response['Vpcs'][0]
            tags = {t['Key']: t['Value'] for t in vpc_data.get('Tags', [])}
            name_tag = tags.get('Name', 'N/A')
            print_success(f"VPC {vpc_id} found in {region}. Name: '{name_tag}'. State: {vpc_data.get('State')}")
            logging.info(f"VPC validation successful for {vpc_id} in {region}.")
            return True
        else:
            print_error(f"VPC ID '{vpc_id}' not found in region '{region}'.")
            logging.warning(f"VPC validation failed: {vpc_id} not found in {region}.")
            return False
    except botocore.exceptions.ClientError as e:
        if 'InvalidVpcID.NotFound' in str(e):
            print_error(f"VPC ID '{vpc_id}' not found in region '{region}'.")
            logging.warning(f"VPC validation failed: {vpc_id} not found in {region}.")
        else:
            print_error(f"Error validating VPC ID '{vpc_id}' in {region}: {e}")
            logging.error(f"Error validating VPC ID {vpc_id}: {e}")
        return False

def validate_subnet_ids(subnet_ids_str, region):
    """Validate comma-separated subnet IDs exist in the region using boto3."""
    if not subnet_ids_str or not region: return False # Allow empty if needed by context? Assume non-empty needed.

    subnet_list = [sid.strip() for sid in subnet_ids_str.split(',') if sid.strip()]
    if not subnet_list:
        print_error("No valid subnet IDs provided.")
        return False

    ec2 = _get_boto_client('ec2', region_name=region)
    if not ec2: return False

    try:
        response = ec2.describe_subnets(SubnetIds=subnet_list)
        found_ids = {s['SubnetId'] for s in response.get('Subnets', [])}
        all_found = True
        for expected_id in subnet_list:
            if expected_id not in found_ids:
                print_error(f"Subnet ID '{expected_id}' not found in region '{region}'. (Failed on entry: {expected_id})")
                all_found = False
            else:
                 # Find the subnet details to print name/CIDR
                 subnet_data = next((s for s in response['Subnets'] if s['SubnetId'] == expected_id), None)
                 if subnet_data:
                      tags = {t['Key']: t['Value'] for t in subnet_data.get('Tags', [])}
                      name_tag = tags.get('Name', 'N/A')
                      print_success(f"Subnet {expected_id} found. Name: '{name_tag}', CIDR: {subnet_data.get('CidrBlock')}, AZ: {subnet_data.get('AvailabilityZone')}")
                 else: # Should not happen if found_ids contains it
                      print_success(f"Subnet {expected_id} found.")

        if not all_found:
             logging.warning(f"Subnet validation failed: One or more IDs not found in {region} from list: {subnet_list}")
             return False
        else:
             logging.info(f"Subnet validation successful for IDs: {subnet_list} in {region}.")
             return True
    except botocore.exceptions.ClientError as e:
        if 'InvalidSubnetID.NotFound' in str(e):
            # Try to extract which subnet failed
            msg = str(e)
            for expected_id in subnet_list:
                if expected_id in msg:
                    print_error(f"Subnet ID '{expected_id}' is invalid or not found in region '{region}'. (Failed on entry: {expected_id})")
            print_error(f"One or more subnet IDs are invalid or not found in region '{region}'.")
            logging.warning(f"Subnet validation failed (InvalidSubnetID.NotFound) for list: {subnet_list}")
        else:
            print_error(f"Error validating subnet IDs in {region}: {e}")
            logging.error(f"Error validating subnet IDs {subnet_list}: {e}")
        return False

# ADD THE NEW FUNCTION HERE
def get_subnet_cidrs(subnet_ids_str, region):
    """Fetch CIDR blocks for a comma-separated list of subnet IDs."""
    if not subnet_ids_str or not region:
        return ""

    subnet_list = [sid.strip() for sid in subnet_ids_str.split(',') if sid.strip()]
    if not subnet_list:
        return ""

    ec2 = _get_boto_client('ec2', region_name=region)
    if not ec2:
        print_error(f"Could not create EC2 client for region {region} to fetch subnet CIDRs.")
        return None # Indicate error

    try:
        response = ec2.describe_subnets(SubnetIds=subnet_list)
        cidrs = []
        found_ids = set()
        for subnet_data in response.get('Subnets', []):
            subnet_id = subnet_data.get('SubnetId')
            cidr_block = subnet_data.get('CidrBlock')
            if subnet_id and cidr_block:
                cidrs.append(cidr_block)
                found_ids.add(subnet_id)
            else:
                 print_warning(f"Could not retrieve CIDR block for subnet {subnet_id or 'unknown'}.")

        # Verify all requested IDs were found
        all_found = True
        for expected_id in subnet_list:
            if expected_id not in found_ids:
                print_error(f"Subnet ID '{expected_id}' not found when fetching CIDRs in region '{region}'.")
                all_found = False

        if not all_found:
             logging.error(f"Failed to fetch CIDRs for all requested subnets: {subnet_list} in {region}")
             return None # Indicate error: not all subnets were found

        cidr_string = ",".join(cidrs)
        logging.info(f"Successfully fetched CIDRs for subnets {subnet_list} in {region}: {cidr_string}")
        return cidr_string

    except botocore.exceptions.ClientError as e:
        if 'InvalidSubnetID.NotFound' in str(e):
            print_error(f"One or more subnet IDs are invalid or not found in region '{region}' when fetching CIDRs.")
        else:
            print_error(f"Error fetching subnet CIDRs in {region}: {e}")
        logging.error(f"Error fetching CIDRs for subnets {subnet_list}: {e}")
        return None # Indicate error
    except Exception as e:
        print_error(f"An unexpected error occurred fetching subnet CIDRs: {e}")
        logging.exception(f"Unexpected error fetching CIDRs for {subnet_list}")
        return None # Indicate error

# --- Terraform Backend Configuration ---

def configure_s3_backend():
    """Configure Terraform S3 backend: ensure resources exist and write backend config file."""
    print_section("Configure Terraform S3 Backend")
    print_info("This step ensures the S3 bucket and DynamoDB table for Terraform state exist.")
    print_info(f"Backend configuration will be saved to: {CONFIG['BACKEND_VARS_FILENAME']}")

    if not ensure_aws_credentials():
        return False # Cannot proceed without valid creds

    # Get Region
    available_regions = get_cached_aws_regions()
    selected_region = get_region_selection(available_regions, CONFIG['DEFAULT_AWS_REGION'])
    if not selected_region:
        return False

    # Get Bucket Name
    default_bucket_suggestion = f"frontegg-tfstate-{get_aws_identity().get('Account', 'unknownacc')}-{selected_region}"
    bucket_name = get_input(
        "Enter S3 bucket name for Terraform state",
        default=default_bucket_suggestion,
        validator=validate_s3_bucket_name,
        error_message="Invalid S3 bucket name."
    )
    if not bucket_name: return False # User cancelled or invalid input despite validator?

    # Get DynamoDB Table Name
    dynamodb_table = get_input(
        "Enter DynamoDB table name for state locking",
        default=CONFIG['DEFAULT_TERRAFORM_LOCK_TABLE']
        # Add validator if needed, names have rules too
    )
    if not dynamodb_table: return False

    # Ensure Resources Exist
    print_info(f"Ensuring S3 bucket '{bucket_name}' exists in {selected_region}...")
    if not ensure_s3_bucket(bucket_name, selected_region):
        return False

    print_info(f"Ensuring DynamoDB table '{dynamodb_table}' exists in {selected_region}...")
    if not ensure_dynamodb_table(dynamodb_table, selected_region):
        return False

    # Write backend config file (e.g., backend.config.tfvars)
    # Assumes backend.tf uses variables like tf_state_bucket, tf_state_key, etc.
    backend_config_content = f"""
# Terraform Backend Configuration - Generated by script
# Used with: terraform init -backend-config={CONFIG['BACKEND_VARS_FILENAME']}

bucket         = "{bucket_name}"
key            = "{CONFIG['DEFAULT_TERRAFORM_STATE_KEY']}"
region         = "{selected_region}"
dynamodb_table = "{dynamodb_table}"
encrypt        = true
"""
    try:
        # Ensure Terraform directory exists before writing into it
        os.makedirs(TERRAFORM_DIR_PATH, exist_ok=True)
        with open(BACKEND_VARS_FILEPATH, 'w') as f:
            f.write(backend_config_content.strip())
        print_success(f"Terraform backend configuration saved to: {BACKEND_VARS_FILEPATH}")
        logging.info(f"Terraform backend configuration written to {BACKEND_VARS_FILEPATH}")
        # Log the content excluding sensitive parts if necessary
        logging.debug(f"Backend config content:\n{backend_config_content}")
        return True
    except (IOError, OSError) as e:
        print_error(f"Failed to write Terraform backend config file ({BACKEND_VARS_FILEPATH}): {e}")
        logging.error(f"Failed to write backend config file {BACKEND_VARS_FILEPATH}: {e}")
        return False

# --- Terraform Execution ---

def _stream_subprocess_output(process):
    """Read stdout and stderr from subprocess and print/log in real-time."""
    stdout_lines = []
    stderr_lines = []
    try:
        # Print stdout line by line
        for line in iter(process.stdout.readline, ''):
            print(line, end='') # Print with original formatting
            stdout_lines.append(line)
            logging.debug(f"TF_STDOUT: {line.rstrip()}") # Log debug level
        # Capture any remaining stderr after stdout is closed
        stderr_output = process.stderr.read()
        if stderr_output:
             print(f"{colorama.Fore.RED}{stderr_output}{colorama.Style.RESET_ALL}", file=sys.stderr) # Print errors in red to stderr
             stderr_lines = stderr_output.splitlines()
             for line in stderr_lines:
                  logging.error(f"TF_STDERR: {line.rstrip()}")
    finally:
         process.stdout.close()
         process.stderr.close()
    return "".join(stdout_lines), "".join(stderr_lines)


def execute_terraform_commands(action, tf_dir):
    """Execute Terraform commands (init, plan, apply, destroy)."""
    if action not in ['init', 'plan', 'apply', 'destroy']:
        print_error(f"Invalid Terraform action: {action}")
        return False

    # Ensure Terraform directory exists
    if not os.path.isdir(tf_dir):
         print_error(f"Terraform directory not found: {tf_dir}")
         logging.error(f"Terraform directory not found: {tf_dir}")
         return False

    original_dir = os.getcwd()
    success = False
    try:
        os.chdir(tf_dir)
        logging.info(f"Changed directory to: {tf_dir}")
        print_info(f"Executing 'terraform {action}' in {tf_dir}...")

        if action == 'init':
            # Use the backend config file generated earlier
            cmd = ['terraform', 'init', f'-backend-config={CONFIG["BACKEND_VARS_FILENAME"]}']
            # Handle potential migration if backend changes (less likely now?)
            # Consider adding '-migrate-state' or '-reconfigure' based on context if needed
        elif action == 'plan':
            cmd = ['terraform', 'plan', '-detailed-exitcode', '-out=tfplan'] # Save plan
        elif action == 'apply':
             # Check if plan file exists
             if not os.path.exists("tfplan"):
                  print_error("Terraform plan file (tfplan) not found. Please run 'plan' first.")
                  logging.error("tfplan file not found for apply.")
                  return False
             cmd = ['terraform', 'apply', '-auto-approve', 'tfplan'] # Apply the saved plan
        elif action == 'destroy':
             cmd = ['terraform', 'destroy'] # Prompt user for confirmation by default
             # Alternatively: cmd = ['terraform', 'destroy', '-auto-approve'] # If script confirmation is enough

        logging.info(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, # Use text mode
            encoding='utf-8', # Specify encoding
            errors='replace' # Handle potential decoding errors
        )

        stdout_data, stderr_data = _stream_subprocess_output(process)
        return_code = process.wait() # Wait for process to complete

        logging.info(f"Terraform {action} exited with code: {return_code}")

        if action == 'plan':
            if return_code == 0:
                print_success("Terraform Plan: No changes detected.")
                success = True # Plan successful, no changes
            elif return_code == 2:
                print_warning("Terraform Plan: Changes detected (saved to tfplan).")
                logging.info("Terraform plan indicates changes to be applied.")
                success = True # Plan successful, changes detected
            else: # return_code == 1 or other
                print_error(f"Terraform Plan failed with exit code {return_code}.")
                # stderr should have already been logged by _stream_subprocess_output
                success = False
        elif action == 'init' or action == 'apply' or action == 'destroy':
            if return_code == 0:
                print_success(f"Terraform {action} completed successfully.")
                success = True
                # Clean up plan file after successful apply
                if action == 'apply' and os.path.exists("tfplan"):
                    try:
                        os.remove("tfplan")
                        logging.info("Removed tfplan file.")
                    except OSError as e:
                        print_warning(f"Could not remove tfplan file: {e}")
                        logging.warning(f"Could not remove tfplan file: {e}")
            else:
                print_error(f"Terraform {action} failed with exit code {return_code}.")
                success = False

    except FileNotFoundError:
        print_error(f"Terraform command not found. Is Terraform installed and in PATH?")
        logging.error("Terraform command not found.")
        success = False
    except subprocess.SubprocessError as e:
         print_error(f"Subprocess error during Terraform execution: {e}")
         logging.error(f"Subprocess error during Terraform {action}: {e}")
         success = False
    except Exception as e:
        print_error(f"An unexpected error occurred during Terraform {action}: {e}")
        logging.exception(f"Unexpected error during Terraform {action}") # Log full traceback
        success = False
    finally:
        os.chdir(original_dir) # Always change back to original directory
        logging.info(f"Changed directory back to: {original_dir}")

    return success

# --- System Scan --- Refactored into smaller checks

def check_python_environment():
    """Check Python version."""
    print_info("Checking Python version...")
    min_version = CONFIG['MIN_PYTHON_VERSION']
    current_version = sys.version_info
    if current_version >= min_version:
        print_success(f"Python version {current_version.major}.{current_version.minor}.{current_version.micro} (Required: >= {min_version[0]}.{min_version[1]})")
        return True
    else:
        print_error(f"Python version {current_version.major}.{current_version.minor}.{current_version.micro} is too old (Required: >= {min_version[0]}.{min_version[1]})")
        return False

def check_system_resources():
    """Check memory and disk space."""
    print_info("Checking system resources...")
    passed = True
    # Memory
    try:
        memory = psutil.virtual_memory()
        total_gb = memory.total / (1024**3)
        min_mem_gb = CONFIG['MIN_MEMORY_GB']
        if total_gb >= min_mem_gb:
            print_success(f"Memory: {total_gb:.1f} GB (Required: >= {min_mem_gb} GB)")
        else:
            print_error(f"Memory: {total_gb:.1f} GB (Required: >= {min_mem_gb} GB) - Insufficient memory.")
            passed = False
    except Exception as e:
        print_warning(f"Could not check memory: {e}")
        # Decide if this is critical - potentially allow user to continue?
        # passed = False # Uncomment to make memory check failure critical

    # Disk Space (check root '/' and potentially Terraform dir)
    try:
        disk_usage = psutil.disk_usage('/')
        free_gb = disk_usage.free / (1024**3)
        min_disk_gb = CONFIG['MIN_DISK_SPACE_GB']
        if free_gb >= min_disk_gb:
            print_success(f"Disk space (/): {free_gb:.1f} GB free (Required: >= {min_disk_gb} GB)")
        else:
            print_error(f"Disk space (/): {free_gb:.1f} GB free (Required: >= {min_disk_gb} GB) - Insufficient disk space.")
            passed = False
    except Exception as e:
        print_warning(f"Could not check disk space: {e}")
        # passed = False # Uncomment to make disk check failure critical

    return passed

def check_cli_tool(tool_name, version_args):
    """Check if a CLI tool is installed and optionally print its version."""
    print_info(f"Checking for {tool_name}...")
    try:
        result = subprocess.run([tool_name] + version_args, capture_output=True, text=True, check=True, encoding='utf-8', errors='replace')
        # Handle multi-line version outputs (like aws --version)
        version_info = result.stdout.strip() + (f" {result.stderr.strip()}" if result.stderr.strip() else "")
        version_info = version_info.replace('\n', ' ').strip() # Clean up version string
        print_success(f"{tool_name} found: {version_info}")
        logging.info(f"{tool_name} found: {version_info}")
        return True
    except FileNotFoundError:
        print_error(f"{tool_name} command not found. Please install it and ensure it's in your PATH.")
        logging.error(f"{tool_name} command not found.")
        return False
    except subprocess.CalledProcessError as e:
        # Tool exists but version command failed
        print_warning(f"Found {tool_name}, but version command failed (Exit code: {e.returncode}). Output:\n{e.stderr or e.stdout}")
        logging.warning(f"{tool_name} version command failed: {e}")
        return True # Assume installed if command found, but log warning
    except Exception as e:
        print_error(f"Error checking {tool_name}: {e}")
        logging.error(f"Error checking {tool_name}: {e}")
        return False

def check_python_packages():
    """Check for required Python packages using pip show and import."""
    print_info("Checking Python dependencies...")
    
    # Map pip install names to their import names
    requirements = {
        'jinja2': 'jinja2',
        'colorama': 'colorama',
        'PyYAML': 'yaml',  # Correct pip name is PyYAML
        'pyfiglet': 'pyfiglet',
        'prompt_toolkit': 'prompt_toolkit',
        'psutil': 'psutil',
        'requests': 'requests',
        'boto3': 'boto3',
        'botocore': 'botocore',
        'setuptools': 'setuptools',
    }
    
    passed = True

    for pip_name, import_name in requirements.items():
        # 1. Check installation using pip show
        try:
            # Use capture_output=True to hide pip show output unless debugging
            # check=True will raise CalledProcessError if package not found
            subprocess.run(['pip3', 'show', pip_name], check=True, capture_output=True, text=True)
            # If pip show succeeded, package is installed
            # print_success(f"Package '{pip_name}' is installed.") # Optional success message
        except FileNotFoundError:
             print_error(f"'pip3' command not found. Cannot verify packages.")
             return False # Cannot proceed without pip3
        except subprocess.CalledProcessError:
            # Package not found by pip show
            print_error(f"Python package '{pip_name}' is missing. Install using: pip3 install {pip_name}")
            passed = False
            continue # No need to check import if not installed
        except Exception as e:
             print_error(f"Error running 'pip3 show {pip_name}': {e}")
             passed = False # Unexpected error during check
             continue

        # 2. Check importability
        try:
            __import__(import_name)
            # Optional: print success for import check
            # print_success(f"Package '{pip_name}' (import '{import_name}') imported successfully.")
        except ImportError:
            print_error(f"Python package '{pip_name}' is installed but cannot be imported as '{import_name}'. Check environment or reinstall: pip3 install --force-reinstall {pip_name}")
            passed = False
        except Exception as e:
             print_error(f"Error importing '{import_name}' (from package '{pip_name}'): {e}")
             passed = False # Unexpected error during import

    if not passed:
        print_warning("Install or fix missing/broken packages. You might need: pip3 install -r requirements.txt")
    else:
         print_success("All required Python packages verified.")

    return passed

def check_network_connectivity(url='https://google.com', timeout=5):
    """Check basic internet connectivity."""
    print_info(f"Checking network connectivity to {url}...")
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        print_success(f"Network connectivity to {url} successful (Status: {response.status_code}).")
        return True
    except requests.exceptions.RequestException as e:
        print_error(f"Network connectivity check failed: {e}")
        logging.error(f"Network connectivity check failed: {e}")
        return False

def run_system_scan():
    """Run all system checks."""
    print_section("System Scan")
    results = {
        "Python Version": check_python_environment(),
        "System Resources": check_system_resources(),
        "AWS CLI": check_cli_tool('aws', ['--version']),
        "Terraform CLI": check_cli_tool('terraform', ['--version']),
        "kubectl CLI": check_cli_tool('kubectl', ['version', '--client=true']), # Use boolean flag
        "Python Packages": check_python_packages(),
        "Network Connectivity": check_network_connectivity(),
        # Add file permission checks if needed (e.g., for config template)
    }

    all_passed = all(results.values())

    print("\n--- System Scan Summary ---")
    # (No AWS Identity/Role info here)

    if all_passed:
        print_success("All system checks passed!")
    else:
        print_error("One or more system checks failed. Please review the messages above.")
        # List specific failures
        for check, passed in results.items():
             if not passed:
                  print_warning(f"- Check Failed: {check}")

    logging.info(f"System scan completed. Overall result: {'Passed' if all_passed else 'Failed'}")
    return all_passed


# --- Deployment Configuration ---

def create_deployment_configuration():
    """Guide user through creating the config.yaml file from the template."""
    print_section("Create Deployment Configuration")
    print_info(f"This will generate the '{CONFIG['CONFIG_FILENAME']}' file based on your input.")

    # Check if template exists
    template_filepath = os.path.join(TEMPLATE_DIR_PATH, CONFIG['CONFIG_TEMPLATE'])
    if not os.path.exists(template_filepath):
        print_error(f"Configuration template not found: {template_filepath}")
        logging.error(f"Configuration template not found: {template_filepath}")
        return None

    # Ensure config directory exists
    config_dir = os.path.dirname(CONFIG_FILEPATH)
    os.makedirs(config_dir, exist_ok=True)

    # Backup existing config file if it exists
    if os.path.exists(CONFIG_FILEPATH):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{CONFIG_FILEPATH}.{timestamp}.bak"
        try:
            os.rename(CONFIG_FILEPATH, backup_path)
            print_warning(f"Existing configuration file backed up to: {os.path.basename(backup_path)}")
            logging.info(f"Backed up existing config file to {backup_path}")
        except OSError as e:
            print_error(f"Could not back up existing config file: {e}")
            # Ask user if they want to overwrite?
            overwrite = get_input("Could not back up existing config. Overwrite?", default=False, is_boolean=True)
            if not overwrite:
                print_error("Configuration creation cancelled.")
                return None

    config_data = {} # Dictionary to hold user inputs

    # --- Prompt for Configuration Values ---
    # Use print_subsection helper and get_input with validators

    # Check AWS credentials if validation is needed during prompts
    needs_aws_validation = False # Set to True if any prompt requires validating AWS resources
    if needs_aws_validation:
        if not ensure_aws_credentials():
            print_error("AWS credentials needed for validation but are not configured/valid.")
            return None

    print_subsection("Environment Details")
    config_data['customer'] = get_input("Customer Name", CONFIG['DEFAULT_CUSTOMER'])
    config_data['environment'] = get_input("Environment Name", CONFIG['DEFAULT_ENVIRONMENT'])

    print_subsection("AWS Region")
    available_regions = get_cached_aws_regions()
    selected_region = get_region_selection(available_regions, CONFIG['DEFAULT_AWS_REGION'])
    if not selected_region: return None # User cancelled or error
    config_data['region'] = selected_region

    print_subsection("VPC Configuration")
    vpc_enabled = get_input("Create New VPC?", default=False, is_boolean=True)
    config_data['vpc_enabled'] = vpc_enabled
    if vpc_enabled:
        config_data['vpc_cidr'] = get_input("New VPC CIDR Block", CONFIG['DEFAULT_VPC_CIDR'], validator=validate_cidr)
        # If creating VPC, subnet IDs are typically outputs from Terraform, not inputs here
        config_data['vpc_id'] = ""
        config_data['private_subnets'] = []
        config_data['private_subnets_cidr_blocks'] = [] # Terraform likely calculates these
        config_data['intra_subnets'] = []
        
        # Create subnets object for template
        config_data['subnets'] = {
            'private': config_data['private_subnets'],
            'intra': config_data['intra_subnets']
        }
    else:
        # Using existing VPC - Requires validation which needs AWS creds
        if not ensure_aws_credentials(): return None # Check creds before AWS calls
        config_data['vpc_id'] = get_input("Existing VPC ID", validator=lambda v: validate_vpc_id(v, config_data['region']))
        
        # Get Subnet IDs (still needed)
        subnet_ids_input = get_input("Existing Private Subnet IDs (comma-separated)", validator=lambda s: validate_subnet_ids(s, config_data['region']))
        if not subnet_ids_input: return None # Exit if validation failed or input empty
        config_data['private_subnets'] = subnet_ids_input

        # Dynamically fetch CIDRs based on IDs
        print_info(f"Fetching CIDR blocks for subnets: {subnet_ids_input}...")
        fetched_cidrs = get_subnet_cidrs(subnet_ids_input, config_data['region'])
        
        if fetched_cidrs is None:
             print_error("Failed to fetch CIDR blocks for the provided subnet IDs. Please check the IDs and AWS permissions.")
             # Decide how to handle: exit, or prompt manually as fallback?
             # For now, let's exit:
             return None 
        elif not fetched_cidrs:
             print_warning("No CIDR blocks were fetched (maybe empty input or no subnets found?).")
             config_data['private_subnets_cidr_blocks'] = ""
        else:
             print_success(f"Successfully fetched Private Subnet CIDRs: {fetched_cidrs}")
             config_data['private_subnets_cidr_blocks'] = fetched_cidrs

        # Removed the old prompt for CIDRs
        
        # Keep prompts for other optional fields like intra_subnets
        def validate_optional_subnet_ids(subnet_ids_str):
            if not subnet_ids_str or not subnet_ids_str.strip():
                return True  # Allow empty for optional field
            return validate_subnet_ids(subnet_ids_str, config_data['region'])
        
        config_data['intra_subnets'] = get_input("Existing Intra Subnet IDs (comma-separated, optional)", validator=validate_optional_subnet_ids)
        # Prompt for existing VPC CIDR
        config_data['vpc_cidr'] = get_input("Existing VPC CIDR Block", CONFIG['DEFAULT_VPC_CIDR'], validator=validate_cidr)
        
        # Create subnets object for template
        config_data['subnets'] = {
            'private': config_data['private_subnets'],
            'intra': config_data['intra_subnets']
        }

    # Secrets Manager
    print_subsection("Secrets Manager")
    config_data['secrets_recovery_window_in_days'] = int(get_input(
         "Secrets Recovery Window (days, 7-30, or 0 for immediate delete)",
         default="7",
         validator=lambda v: validate_non_negative_int(v) and (int(v) == 0 or 7 <= int(v) <= 30),
         error_message="Must be 0 or between 7 and 30."
    ))

    # MSK (Kafka)
    print_subsection("MSK (Managed Kafka)")
    msk_enabled = get_input("Enable MSK?", default=False, is_boolean=True)
    config_data['msk_enabled'] = msk_enabled
    if msk_enabled:
        config_data['msk_version'] = get_input("MSK Kafka Version", CONFIG['DEFAULT_MSK_VERSION'], validator=validate_semantic_version)
        config_data['msk_broker_nodes'] = int(get_input("Number of Broker Nodes", str(CONFIG['DEFAULT_MSK_BROKER_NODES']), validator=validate_positive_int))
        config_data['msk_volume_size'] = int(get_input("Broker Volume Size (GB)", str(CONFIG['DEFAULT_MSK_VOLUME_SIZE']), validator=validate_positive_int))
        config_data['msk_instance_type'] = get_input("Broker Instance Type", CONFIG['DEFAULT_MSK_INSTANCE_TYPE'], validator=validate_instance_type)
        # Add MSK logs configuration
        config_data['msk_logs_enabled'] = get_input("Enable MSK logs?", default=True, is_boolean=True)
        # Add MSK scaling configuration
        config_data['msk_scaling_max'] = int(get_input("MSK scaling max capacity", str(CONFIG['DEFAULT_MSK_SCALING_MAX']), validator=validate_positive_int))
        config_data['msk_scaling_target'] = int(get_input("MSK scaling target value", str(CONFIG['DEFAULT_MSK_SCALING_TARGET']), validator=validate_positive_int))
        # --- Add prompt for unauthenticated access --- 
        config_data['msk_allow_unauthenticated'] = get_input("Allow UNSECURE unauthenticated access to MSK? (Not Recommended)", default=True, is_boolean=True)
        # --- Add prompts for SASL methods --- 
        config_data['msk_sasl_iam_enabled'] = get_input("Enable SASL/IAM authentication for MSK?", default=True, is_boolean=True)
        config_data['msk_sasl_scram_enabled'] = get_input("Enable SASL/SCRAM authentication for MSK?", default=False, is_boolean=True)
        # Clear external broker fields if creating MSK
        config_data['msk_bootstrap_brokers_plaintext'] = ""
        config_data['msk_bootstrap_brokers_sasl_iam'] = ""
        config_data['msk_bootstrap_brokers_sasl_scram'] = ""
        config_data['msk_bootstrap_brokers_tls'] = ""
        config_data['encryption_in_transit_client_broker'] = get_input("Encryption in transit client broker", "PLAINTEXT", validator=lambda v: v.upper() in ["PLAINTEXT", "TLS_PLAINTEXT"])
        # Prompt for Debezium only if EKS is enabled
        config_data['debezium_enabled'] = get_input("Enable Debezium connector?", default=False, is_boolean=True)
    else:
        print_info("MSK creation disabled. Please provide connection details for your existing Kafka cluster.")
        # Only one broker list should be provided; prompt in order and skip the rest if one is entered and valid
        broker_types = [
            ("PLAINTEXT", "msk_bootstrap_brokers_plaintext"),
            ("SASL/IAM", "msk_bootstrap_brokers_sasl_iam"),
            ("SASL/SCRAM", "msk_bootstrap_brokers_sasl_scram"),
            ("TLS", "msk_bootstrap_brokers_tls")
        ]
        broker_values = {}
        while True:
            for label, key in broker_types:
                value = get_input(
                    f"Existing Kafka Brokers ({label}, comma-separated, optional)",
                    default="",
                    validator=validate_msk_broker_list,
                    error_message=f"None of the provided {label} brokers are reachable. Please enter at least one reachable broker in host:port format."
                )
                if value:
                    broker_values = {k: "" for _, k in broker_types}  # Clear all
                    broker_values[key] = value
                    break
            if any(broker_values.values()):
                break
            print_warning("You must provide at least one valid broker list. Please try again.")
        config_data.update(broker_values)
        # Set authentication values when MSK is disabled
        config_data['msk_allow_unauthenticated'] = get_input("Allow UNSECURE unauthenticated access to MSK? (Not Recommended)", default=True, is_boolean=True)
        config_data['msk_sasl_iam_enabled'] = get_input("Enable SASL/IAM authentication for MSK?", default=False, is_boolean=True)
        config_data['msk_sasl_scram_enabled'] = get_input("Enable SASL/SCRAM authentication for MSK?", default=False, is_boolean=True)
        config_data['debezium_enabled'] = get_input("Enable Debezium connector?", default=False, is_boolean=True)
        # Set missing MSK attributes to defaults when disabled
        config_data['msk_version'] = CONFIG['DEFAULT_MSK_VERSION']
        config_data['msk_broker_nodes'] = CONFIG['DEFAULT_MSK_BROKER_NODES']
        config_data['msk_volume_size'] = CONFIG['DEFAULT_MSK_VOLUME_SIZE']
        config_data['msk_instance_type'] = CONFIG['DEFAULT_MSK_INSTANCE_TYPE']
        config_data['msk_logs_enabled'] = True
        config_data['msk_scaling_max'] = CONFIG['DEFAULT_MSK_SCALING_MAX']
        config_data['msk_scaling_target'] = CONFIG['DEFAULT_MSK_SCALING_TARGET']

    # MySQL (RDS)
    print_subsection("MySQL (RDS)")
    mysql_enabled = get_input("Enable MySQL?", default=False, is_boolean=True)
    config_data['mysql_enabled'] = mysql_enabled
    if mysql_enabled:
        config_data['mysql_engine_version'] = get_input("MySQL Version", CONFIG['DEFAULT_MYSQL_VERSION'], validator=validate_semantic_version)
        config_data['mysql_family'] = get_input("MySQL Family", CONFIG['DEFAULT_MYSQL_FAMILY'])
        config_data['mysql_major_version'] = get_input("MySQL Major Engine Version", CONFIG['DEFAULT_MYSQL_MAJOR_VERSION'])
        config_data['mysql_instance_class'] = get_input("MySQL Instance Class", CONFIG['DEFAULT_MYSQL_INSTANCE_TYPE'], validator=validate_instance_type)
        config_data['mysql_storage_type'] = get_input("MySQL Storage Type (e.g., gp3, io1)", CONFIG['DEFAULT_MYSQL_STORAGE_TYPE'])
        config_data['mysql_storage'] = int(get_input("Initial Storage (GB)", str(CONFIG['DEFAULT_MYSQL_STORAGE']), validator=validate_positive_int))
        config_data['mysql_max_storage'] = int(get_input("Maximum Storage (GB)", str(CONFIG['DEFAULT_MYSQL_MAX_STORAGE']), validator=validate_positive_int))
        config_data['mysql_port'] = int(get_input("MySQL Port", str(CONFIG['DEFAULT_MYSQL_PORT']), validator=validate_positive_int))
        config_data['mysql_multi_az'] = get_input("Enable Multi-AZ?", default=False, is_boolean=True)
        config_data['mysql_maintenance_window'] = get_input("Maintenance Window (ddd:hh:mm-ddd:hh:mm)", CONFIG['DEFAULT_MAINTENANCE_WINDOW'], validator=validate_maintenance_window)
        config_data['mysql_backup_window'] = get_input("Backup Window (hh:mm-hh:mm)", CONFIG['DEFAULT_BACKUP_WINDOW'], validator=validate_backup_window)
        config_data['mysql_backup_retention_period'] = int(get_input("MySQL Backup Retention Period (days)", "7", validator=validate_positive_int))
        config_data['mysql_cloudwatch_logs'] = get_input("Create CloudWatch log group for MySQL?", default=True, is_boolean=True)
        config_data['mysql_skip_snapshot'] = get_input("Skip final snapshot when deleting MySQL?", default=False, is_boolean=True)
        config_data['mysql_deletion_protection'] = get_input("Enable deletion protection for MySQL?", default=True, is_boolean=True)
        config_data['mysql_performance_insights'] = get_input("Enable performance insights for MySQL?", default=True, is_boolean=True)
        config_data['mysql_performance_insights_retention_period'] = int(get_input("Performance insights retention period (days)", str(CONFIG['DEFAULT_MYSQL_PERFORMANCE_RETENTION']), validator=validate_positive_int))
        config_data['mysql_endpoint'] = ""
    else:
        config_data['mysql_engine_version'] = CONFIG['DEFAULT_MYSQL_VERSION']
        config_data['mysql_family'] = CONFIG['DEFAULT_MYSQL_FAMILY']
        config_data['mysql_major_version'] = CONFIG['DEFAULT_MYSQL_MAJOR_VERSION']
        config_data['mysql_instance_class'] = CONFIG['DEFAULT_MYSQL_INSTANCE_TYPE']
        config_data['mysql_storage_type'] = CONFIG['DEFAULT_MYSQL_STORAGE_TYPE']
        config_data['mysql_storage'] = CONFIG['DEFAULT_MYSQL_STORAGE']
        config_data['mysql_max_storage'] = CONFIG['DEFAULT_MYSQL_MAX_STORAGE']
        config_data['mysql_port'] = CONFIG['DEFAULT_MYSQL_PORT']
        config_data['mysql_multi_az'] = False
        config_data['mysql_maintenance_window'] = CONFIG['DEFAULT_MAINTENANCE_WINDOW']
        config_data['mysql_backup_window'] = CONFIG['DEFAULT_BACKUP_WINDOW']
        config_data['mysql_backup_retention_period'] = 7
        config_data['mysql_cloudwatch_logs'] = True
        config_data['mysql_skip_snapshot'] = False
        config_data['mysql_deletion_protection'] = True
        config_data['mysql_performance_insights'] = True
        config_data['mysql_performance_insights_retention_period'] = CONFIG['DEFAULT_MYSQL_PERFORMANCE_RETENTION']
        while True:
            endpoint = get_input(
                "Enter Existing MySQL endpoint URL (host or host:port)",
                validator=validate_mysql_endpoint,
                error_message="Could not connect to the provided MySQL endpoint. Please enter a reachable host or host:port."
            )
            if validate_mysql_endpoint(endpoint):
                config_data['mysql_endpoint'] = endpoint
                break

    # Redis (ElastiCache)
    print_subsection("Redis (ElastiCache)")
    redis_enabled = get_input("Enable Redis?", default=False, is_boolean=True)
    config_data['redis_enabled'] = redis_enabled
    if redis_enabled:
        config_data['redis_engine_version'] = get_input("Redis Version", CONFIG['DEFAULT_REDIS_VERSION'], validator=validate_redis_version)
        config_data['redis_family'] = get_input("Redis Family", CONFIG['DEFAULT_REDIS_FAMILY'])
        config_data['redis_node_type'] = get_input("Redis Node Type", CONFIG['DEFAULT_REDIS_INSTANCE_TYPE'], validator=validate_instance_type)
        # Prompt for number of cache, default to 2 if empty
        num_cache_input = get_input("Number of cache", str(CONFIG['DEFAULT_NUM_CACHE_CLUSTERS']), validator=validate_positive_int)
        if not num_cache_input:
            num_cache_input = str(CONFIG['DEFAULT_NUM_CACHE_CLUSTERS'])
        config_data['num_cache_clusters'] = int(num_cache_input)
        config_data['redis_tls'] = get_input("Enable TLS for Redis?", default=True, is_boolean=True)
        config_data['transit_encryption_enabled'] = get_input("Enable Redis transit encryption? (recommended for production)", default=False, is_boolean=True)
        config_data['redis_endpoint'] = ""
        config_data['redis_port'] = 6379
    else:
        config_data['redis_engine_version'] = CONFIG['DEFAULT_REDIS_VERSION']
        config_data['redis_family'] = CONFIG['DEFAULT_REDIS_FAMILY']
        config_data['redis_node_type'] = CONFIG['DEFAULT_REDIS_INSTANCE_TYPE']
        config_data['num_cache_clusters'] = CONFIG['DEFAULT_NUM_CACHE_CLUSTERS']
        config_data['redis_tls'] = True
        config_data['transit_encryption_enabled'] = False
        # Always re-prompt until a valid endpoint is entered
        while True:
            endpoint = get_input(
                "Enter Existing Redis primary endpoint (host:port)",
                validator=validate_redis_endpoint,
                error_message="Could not connect to the provided Redis endpoint. Please enter a reachable host:port."
            )
            if validate_redis_endpoint(endpoint):
                config_data['redis_endpoint'] = endpoint
                break
        config_data['redis_port'] = 6379

    # EKS (Kubernetes)
    print_subsection("EKS (Managed Kubernetes)")
    eks_enabled = get_input("Enable EKS?", default=False, is_boolean=True)
    config_data['eks_enabled'] = eks_enabled
    if eks_enabled:
         config_data['eks_version'] = get_input("EKS Kubernetes Version", CONFIG['DEFAULT_EKS_VERSION'], validator=validate_eks_version)
         config_data['eks_min_size'] = int(get_input("Node Group Min Size", str(CONFIG['DEFAULT_EKS_MIN_SIZE']), validator=validate_non_negative_int))
         config_data['eks_max_size'] = int(get_input("Node Group Max Size", str(CONFIG['DEFAULT_EKS_MAX_SIZE']), validator=validate_positive_int))
         config_data['eks_desired_size'] = int(get_input("Node Group Desired Size", str(CONFIG['DEFAULT_EKS_DESIRED_SIZE']), validator=validate_non_negative_int))
         config_data['eks_cluster_name'] = get_input("EKS Cluster Name", default="frontegg-customer-env")
         def validate_capacity_type(val):
             return val.upper() in ['ON_DEMAND', 'SPOT']
         config_data['eks_capacity_type'] = get_input(
             "EKS Node Group Capacity Type (ON_DEMAND or SPOT)",
             default="ON_DEMAND",
             validator=validate_capacity_type,
             error_message="Must be 'ON_DEMAND' or 'SPOT' (case-insensitive)."
         ).upper()
         config_data['eks_auto_mode_enabled'] = get_input("Enable EKS Auto Mode? (Advanced feature for automatic node management)", default=False, is_boolean=True)
         config_data['cluster_endpoint_public_access'] = get_input("Enable public access to EKS cluster endpoint?", default=True, is_boolean=True)
         if config_data['cluster_endpoint_public_access']:
             config_data['cluster_endpoint_public_access_cidrs'] = get_input("Allowed CIDR blocks for public access (comma-separated)", default="0.0.0.0/0", validator=validate_cidr_list)
         else:
             config_data['cluster_endpoint_public_access_cidrs'] = []
         # Set default instance types for EKS
         config_data['eks_instance_types'] = CONFIG['DEFAULT_EKS_INSTANCE_TYPES'].split(',')
         config_data['eks_cidrs'] = config_data['cluster_endpoint_public_access_cidrs']
    else:
        # Set all EKS attributes to defaults if not enabled
        config_data['eks_version'] = CONFIG['DEFAULT_EKS_VERSION']
        config_data['eks_min_size'] = CONFIG['DEFAULT_EKS_MIN_SIZE']
        config_data['eks_max_size'] = CONFIG['DEFAULT_EKS_MAX_SIZE']
        config_data['eks_desired_size'] = CONFIG['DEFAULT_EKS_DESIRED_SIZE']
        config_data['eks_cluster_name'] = get_input("EKS Cluster Name", default="frontegg-customer-env")
        config_data['eks_capacity_type'] = "ON_DEMAND"
        config_data['eks_auto_mode_enabled'] = False
        config_data['cluster_endpoint_public_access'] = False
        config_data['cluster_endpoint_public_access_cidrs'] = []

    # External Secrets Operator
    print_subsection("External Secrets Operator")
    eso_enabled = get_input("Enable External Secrets Operator?", default=True, is_boolean=True)
    config_data['external_secret_enabled'] = eso_enabled
    if eso_enabled:
         config_data['external_secret_version'] = get_input("External Secrets Version", CONFIG['DEFAULT_EXTERNAL_SECRET_VERSION'], validator=validate_semantic_version)
         config_data['external_secret_replicas'] = int(get_input("External Secrets Replicas", str(CONFIG['DEFAULT_EXTERNAL_SECRET_REPLICAS']), validator=validate_positive_int))
         config_data['external_secret_concurrent'] = int(get_input("External Secrets Concurrent Processing", str(CONFIG['DEFAULT_EXTERNAL_SECRET_CONCURRENT']), validator=validate_positive_int))
    else:
         # Set defaults when disabled
         config_data['external_secret_version'] = CONFIG['DEFAULT_EXTERNAL_SECRET_VERSION']
         config_data['external_secret_replicas'] = CONFIG['DEFAULT_EXTERNAL_SECRET_REPLICAS']
         config_data['external_secret_concurrent'] = CONFIG['DEFAULT_EXTERNAL_SECRET_CONCURRENT']

    # MongoDB
    print_subsection("MongoDB (Atlas or External)")
    while True:
        endpoint = get_input(
            "Enter MongoDB endpoint (e.g., cluster0.mongodb.net)",
            default="mongodb://mongo-mongodb",
            validator=lambda v: bool(v.strip()),
            error_message="MongoDB endpoint cannot be empty."
        )
        if endpoint.strip():
            config_data['mongo_endpoint'] = endpoint.strip()
            break
    while True:
        username = get_input(
            "Enter MongoDB username",
            default="",
            validator=lambda v: bool(v.strip()),
            error_message="MongoDB username cannot be empty."
        )
        if username.strip():
            config_data['mongo_username'] = username.strip()
            break
    while True:
        password = get_input(
            "Enter MongoDB password",
            default="",
            is_secret=True,
            validator=lambda v: bool(v.strip()),
            error_message="MongoDB password cannot be empty."
        )
        if password.strip():
            config_data['mongo_password'] = password.strip()
            break
    # Print the connection string with password hidden
    hidden_password = '***'
    connection_string = f"mongodb+srv://{config_data['mongo_username']}:{hidden_password}@{config_data['mongo_endpoint']}"
    print_info(f"MongoDB connection string: {connection_string}")
    print_info("MongoDB connection details will be used as provided.")

    # --- Render and Save ---
    try:
        # Add a timestamp to the generated config
        config_data['generation_timestamp'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        config_data['generated_by_user'] = getpass.getuser()
        config_data['generated_on_host'] = socket.gethostname()

        # Jinja2 Rendering
        env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR_PATH), trim_blocks=True, lstrip_blocks=True)
        # Add filter to handle boolean values correctly in YAML
        env.filters['bool_to_yaml'] = lambda x: str(x).lower()
        template = env.get_template(CONFIG['CONFIG_TEMPLATE'])
        rendered_config = template.render(config_data)

        # Write to file
        with open(CONFIG_FILEPATH, 'w') as f:
            f.write(rendered_config)

        print_success(f"Configuration file generated: {CONFIG_FILEPATH}")
        logging.info(f"Configuration file generated: {CONFIG_FILEPATH}")

        # Validate the output YAML
        if not validate_yaml_file(CONFIG_FILEPATH):
             print_error("Generated configuration file has invalid YAML syntax.")
             return None

        # Print generated config automatically (no prompt)
        print("\n--- Generated Configuration ---")
        print(colorize_yaml(rendered_config))
        print("--- End Generated Configuration ---\n")
        logging.info("Generated configuration printed to screen.")
        logging.debug(f"Generated config content:\n{rendered_config}")

        return CONFIG_FILEPATH

    except jinja2.TemplateError as e:
        print_error(f"Error rendering configuration template: {e}")
        logging.error(f"Jinja2 template error: {e}")
        return None
    except (IOError, OSError) as e:
        print_error(f"Error writing configuration file: {e}")
        logging.error(f"Error writing configuration file {CONFIG_FILEPATH}: {e}")
        return None
    except Exception as e:
        print_error(f"An unexpected error occurred during configuration generation: {e}")
        logging.exception("Unexpected error during configuration generation")
        return None


# --- Main Application Logic ---

def display_main_menu():
    """Display the main menu options."""
    print_section("Main Menu")
    print(f"{colorama.Fore.CYAN}1.{colorama.Style.RESET_ALL} Create/Update Deployment Configuration ({CONFIG['CONFIG_FILENAME']})")
    print(f"{colorama.Fore.CYAN}2.{colorama.Style.RESET_ALL} Deploy Environment (Terraform Plan & Apply)")
    print(f"{colorama.Fore.CYAN}3.{colorama.Style.RESET_ALL} Destroy Environment (Terraform Destroy)")
    print(f"{colorama.Fore.CYAN}4.{colorama.Style.RESET_ALL} Exit")
    print("-" * CONFIG['DISPLAY_WIDTH'])

def main():
    """Main execution flow."""
    setup_logging() # Setup logging first
    print_welcome_message()
    
    # Run system scan and AWS credentials check automatically
    print_section("Initial System Check")
    if not run_system_scan():
        print_warning("System checks completed with warnings. You may continue, but some operations might fail.")
    else:
        print_success("System checks completed successfully.")
    
    if not ensure_aws_credentials():
        print_warning("AWS credentials check completed with warnings. You may continue, but AWS operations might fail.")
    else:
        print_success("AWS credentials check completed successfully.")

    while True:
        display_main_menu()
        choice = get_input("Select an option (1-4)", "1")

        if choice == '1':
            create_deployment_configuration()
        elif choice == '2':
            print_section("Deploy Environment")
            # Mandatory checks before deploy
            if not os.path.exists(BACKEND_VARS_FILEPATH):
                 print_warning(f"Backend config '{CONFIG['BACKEND_VARS_FILENAME']}' not found. Configuring automatically...")
                 if not configure_s3_backend(): continue # Try to configure it

            print_info("Initializing Terraform...")
            if not execute_terraform_commands('init', TERRAFORM_DIR_PATH):
                 print_error("Terraform initialization failed.")
                 continue

            print_info("Planning Terraform changes...")
            # Plan returns True if successful (regardless of changes)
            # Need to check exit code specifically if using detailed exit code logic here
            # Simplified: Assume plan func returns False on error only.
            if not execute_terraform_commands('plan', TERRAFORM_DIR_PATH):
                 print_error("Terraform plan failed.")
                 continue

            # Check if tfplan exists (plan succeeded and maybe has changes)
            plan_file = os.path.join(TERRAFORM_DIR_PATH, "tfplan")
            if not os.path.exists(plan_file):
                 print_info("Terraform plan indicates no changes or plan failed to save.")
                 continue # No plan to apply

            confirm_apply = get_input("Review the plan output above. Proceed with Terraform apply?", default=False, is_boolean=True)
            if confirm_apply:
                 print_info("Applying Terraform changes...")
                 if execute_terraform_commands('apply', TERRAFORM_DIR_PATH):
                      print_success("Deployment completed successfully!")
                      # Add post-deployment steps if any (e.g., configure kubectl)
                 else:
                      print_error("Terraform apply failed.")
            else:
                 print_info("Terraform apply cancelled by user.")

        elif choice == '3':
             print_section("Destroy Environment")
             # Mandatory checks before destroy
             if not os.path.exists(BACKEND_VARS_FILEPATH):
                  print_warning(f"Backend config '{CONFIG['BACKEND_VARS_FILENAME']}' not found. Configuring automatically...")
                  if not configure_s3_backend(): continue # Try to configure it

             confirm_destroy = get_input(
                  f"{colorama.Fore.RED}{colorama.Style.BRIGHT}DESTROY the environment? This is irreversible!{colorama.Style.RESET_ALL}",
                  default=False,
                  is_boolean=True
             )
             if confirm_destroy:
                  # Re-initialize just in case, using backend config
                  print_info("Initializing Terraform before destroy...")
                  if not execute_terraform_commands('init', TERRAFORM_DIR_PATH):
                       print_error("Terraform initialization failed. Cannot proceed with destroy.")
                       continue

                  print_info("Executing Terraform destroy...")
                  if execute_terraform_commands('destroy', TERRAFORM_DIR_PATH):
                       print_success("Environment destroyed successfully.")
                  else:
                       print_error("Terraform destroy failed.")
             else:
                  print_info("Destroy operation cancelled.")
        elif choice == '4':
            print_info("Exiting script. Goodbye!")
            break
        else:
            print_error("Invalid choice. Please enter a number between 1 and 5.")

        print("\n" + "="*CONFIG['DISPLAY_WIDTH'] + "\n") # Separator before showing menu again

def validate_msk_broker_list(broker_list):
    """Validate that at least one broker in the comma-separated list is reachable (TCP connect). Show status for all."""
    if not broker_list:
        print_warning("No MSK broker list provided.")
        return True  # Allow empty if not provided (optional field)
    brokers = [b.strip() for b in broker_list.split(',') if b.strip()]
    any_success = False
    for broker in brokers:
        try:
            if ':' not in broker:
                print_error(f"Broker '{broker}' must be in host:port format.")
                continue
            host, port = broker.split(':', 1)
            port = int(port)
            print_info(f"Attempting to connect to MSK broker {host}:{port} ...")
            logging.info(f"Attempting to connect to MSK broker {host}:{port} ...")
            with socket.create_connection((host, port), timeout=5):
                print_success(f"Successfully connected to MSK broker '{broker}'.")
                logging.info(f"Successfully connected to MSK broker '{broker}'.")
                any_success = True
        except Exception as e:
            print_warning(f"Could not connect to broker '{broker}': {e}")
            logging.warning(f"Could not connect to broker '{broker}': {e}")
    if not any_success:
        print_error("None of the provided brokers are reachable. Please enter at least one reachable broker in host:port format.")
        logging.error("None of the provided brokers are reachable. Please enter at least one reachable broker in host:port format.")
        return False
    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("\nOperation cancelled by user (Ctrl+C). Exiting.")
        logging.warning("Operation cancelled by user (KeyboardInterrupt)")
        sys.exit(1)
    except Exception as e:
         # Catch-all for unexpected errors in the main loop
         print_error(f"An unexpected critical error occurred: {e}")
         logging.exception("An unexpected critical error occurred in main loop") # Log traceback
         sys.exit(2)