import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import pandas as pd
from pandas_gbq import to_gbq
import time
import re
import json
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import warnings
import logging
from urllib3.util.retry import Retry
from google.cloud import secretmanager, bigquery, pubsub_v1
from google.cloud.bigquery import SchemaField, TimePartitioningType, Table, TimePartitioning
from google.cloud.exceptions import NotFound
from flask import Flask, request


# --- Create a Flask App ---
app = Flask(__name__)

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- GCP CONFIG ---
PROJECT_ID = "vulnerabilities-fetcher"
BIGQUERY_DATASET = "main_table"
TABLE_NAME = "vulnerabilities"
STAGING_TABLE_NAME = "vulnerabilities-staging"
UPDATE_HISTORY_TABLE_NAME = "last_update"
DASHBOARD_SECRET_NAME = "keep-secure"
N8N_WEBHOOK_URL = "webhook-n8n-url"
SAFE_MAX_WORKERS = 4
PUBSUB_PROJECT = PROJECT_ID
PUBSUB_TOPIC = "vulnerability-job-start"

# --- INIT GCP CLIENTS ---
secret_client = secretmanager.SecretManagerServiceClient()
bq_client = bigquery.Client()
publisher_client = pubsub_v1.PublisherClient()
topic_path = publisher_client.topic_path(PUBSUB_PROJECT, PUBSUB_TOPIC)

# --- GOST TEAM EMAILS ---
GOST_LIST = [
    "andre.marques@randstad.com", "emin.tosun@randstad.com", "emin.tosun@randstadgroep.nl",
    "francisco.santos@randstad.com", "iuri.picolini.moro@randstad.com", "rodrigo.magalhaes@randstad.com",
    "timothy.tjen.a.looi@randstad.com", "timothy.tjen.a.looi@randstad.nl", "vito.bonetti@randstadgroep.nl",
    "bruno.monteiro@randstad.com", "leandro.jales@randstad.com", "hugo.pinto@randstad.com", "ciska.boera@randstadgroep.nl",
    "ciska.boera@randstad.com", "wesley.groenestein@randstadgroep.nl", "wesley.groenestein@randstad.com"
]


VULNERABILITIES_MAP = {'Protection Mechanism Failure - Root Detection (CWE-693)': 'Risk 1: BYOD', 'Permissive Cross-domain Policy with Untrusted Domains (CWE-942)': 'Risk 5: AppSec', 'Missing Secure Headers': 'Risk 5: AppSec', 'Information Disclosure (CWE-200)': 'Risk 5: AppSec', 'Observable Response Discrepancy (CWE-204)': 'Risk 5: AppSec', 'Missing Cookie Attributes': 'Risk 5: AppSec', 'Using Components with Known Vulnerabilities (CWE-1035)': 'Risk 10: Vuln', 'SQL Injection (CWE-89)': 'Risk 5: AppSec', 'Improper Check or Handling of Exceptional Conditions (CWE-703)': 'Risk 5: AppSec', 'Authentication Bypass Using an Alternate Path or Channel (CWE-288)': 'Risk 2: IAM', 'Information Exposure Through Discrepancy (CWE-203)': 'Risk 5: AppSec', 'Improper Certificate Validation (CWE-295)': 'Risk 10: Vuln', 'Cross-site Scripting (XSS) - Reflected (CWE-79)': 'Risk 5: AppSec', 'Use of a Broken or Risky Cryptographic Algorithm (CWE-327)': 'Risk 3: DS & DLP', 'Incorrect Authorization (CWE-863)': 'Risk 2: IAM', 'Protection Mechanism Failure - Lack of Binary Protections (CWE-693)': 'Risk 5: AppSec', 'Incorrect Permission Assignment for Critical Resource (CWE-732)': 'Risk 7: Cloud', 'Missing Authorization (CWE-862)': 'Risk 2: IAM', 'Use of a Key Past its Expiration Date (CWE-324)': 'Risk 10: Vuln', 'Information Exposure Through Sent Data (CWE-201)': 'Risk 3: DS & DLP', 'MASTG-TEST-0235: Android App Configurations Allowing Cleartext Traffic': 'Risk 5: AppSec', 'Misconfigured Firewalls': 'Risk 7: Cloud', 'Use of Hard-coded Password (CWE-259)': 'Risk 5: AppSec', 'Cross-site Scripting (XSS) - Stored (CWE-79)': 'Risk 5: AppSec', 'Insecure Direct Object Reference (IDOR) (CWE-639)': 'Risk 5: AppSec', 'Insufficient Session Expiration (CWE-613)': 'Risk 2: IAM', 'Allocation of Resources Without Limits or Throttling (CWE-770)': 'Risk 5: AppSec', 'Improper Privilege Management (CWE-269)': 'Risk 2: IAM', 'Path Traversal (CWE-22)': 'Risk 5: AppSec', 'Unrestricted Upload of File with Dangerous Type (CWE-434)': 'Risk 5: AppSec', 'Server-Side Request Forgery (SSRF) (CWE-918)': 'Risk 5: AppSec', 'Weak Password Requirements (CWE-521)': 'Risk 2: IAM', 'Cleartext Transmission of Sensitive Information (CWE-319)': 'Risk 3: DS & DLP', 'Plaintext Storage of a Password (CWE-256)': 'Risk 3: DS & DLP', 'Information Exposure Through Debug Information (CWE-215)': 'Risk 5: AppSec', 'Improper Authentication - Generic (CWE-287)': 'Risk 2: IAM', 'Insufficiently Protected Credentials (CWE-522)': 'Risk 3: DS & DLP', 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) (CWE-338)': 'Risk 5: AppSec', 'Insufficient Verification of Data Authenticity (CWE-345)': 'Risk 5: AppSec', 'Improper Control of Interaction Frequency (CWE-799)': 'Risk 5: AppSec', 'Guessable CAPTCHA (CWE-804)': 'Risk 5: AppSec', 'Misconfigured Certificate Template': 'Risk 7: Cloud', 'XML External Entities (XXE) (CWE-611)': 'Risk 5: AppSec', 'Improper Access Control - Generic (CWE-284)': 'Risk 2: IAM', 'Misconfiguration (CWE-16)': 'Risk 7: Cloud', 'Improper Neutralization of Script-Related HTML Tags in a Web Page (CWE-80)': 'Risk 5: AppSec', 'Business Logic Errors (CWE-840)': 'Risk 5: AppSec', 'Information Exposure Through an Error Message (CWE-209)': 'Risk 5: AppSec', 'Cross-site Scripting (XSS) - Generic (CWE-79)': 'Risk 5: AppSec', 'Improperly Controlled Modification of Dynamically-Determined Object Attributes (CWE-915)': 'Risk 5: AppSec', 'Weak Password Recovery Mechanism for Forgotten Password (CWE-640)': 'Risk 2: IAM', 'Improper Authorization (CWE-285)': 'Risk 2: IAM', 'Remote File Inclusion (CWE-98)': 'Risk 5: AppSec', 'Cleartext Storage of Sensitive Information (CWE-312)': 'Risk 3: DS & DLP', 'Violation of Secure Design Principles (CWE-657)': 'Risk 5: AppSec', 'Improper Input Validation (CWE-20)': 'Risk 5: AppSec', 'Privilege Escalation (CAPEC-233)': 'Risk 2: IAM', 'Cross-site Scripting (XSS) - DOM (CWE-79)': 'Risk 5: AppSec', 'CWE-294: Authentication Bypass by Capture-replay': 'Risk 2: IAM', 'Missing Critical Step in Authentication (CWE-304)': 'Risk 2: IAM', 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code': 'Risk 5: AppSec', 'Execution with Unnecessary Privileges (CWE-250)': 'Risk 2: IAM', 'Use of Insufficiently Random Values (CWE-330)': 'Risk 5: AppSec', 'Use of Hard-coded Cryptographic Key (CWE-321)': 'Risk 5: AppSec', 'Cross-Site Request Forgery (CSRF) (CWE-352)': 'Risk 5: AppSec', 'Code Injection (CWE-94)': 'Risk 5: AppSec', 'Resource Injection (CWE-99)': 'Risk 5: AppSec', 'Use of Single-factor Authentication (CWE-308)': 'Risk 2: IAM', 'CWE-598: Use of GET Request Method With Sensitive Query Strings': 'Risk 3: DS & DLP', 'Insecure Storage of Sensitive Information (CWE-922)': 'Risk 3: DS & DLP', 'Improper Restriction of Authentication Attempts (CWE-307)': 'Risk 2: IAM', 'Session Fixation (CWE-384)': 'Risk 5: AppSec', 'Client-Side Enforcement of Server-Side Security (CWE-602)': 'Risk 5: AppSec', 'Weak Cryptography for Passwords (CWE-261)': 'Risk 3: DS & DLP', 'Use of Inherently Dangerous Function (CWE-242)': 'Risk 5: AppSec', 'Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) (CWE-75)': 'Risk 5: AppSec', 'Use of Unmaintained Third Party Components (CWE-1104)': 'Risk 10: Vuln', 'File and Directory Information Exposure (CWE-538)': 'Risk 3: DS & DLP', 'Unverified Password Change (CWE-620)': 'Risk 2: IAM', 'Open Redirect (CWE-601)': 'Risk 5: AppSec', 'Inadequate Encryption Strength (CWE-326)': 'Risk 3: DS & DLP', 'Denial of Service (CWE-400)': 'Risk 5: AppSec', 'Insecure File Shares': 'Risk 7: Cloud', 'Insecure Active Directory Configuration': 'Risk 2: IAM', 'Exposure of Backup File to an Unauthorized Control Sphere (CWE-530)': 'Risk 3: DS & DLP', 'Exposed Dangerous Method or Function (CWE-749)': 'Risk 5: AppSec', 'UI Redressing (Clickjacking) (CAPEC-103)': 'Risk 5: AppSec', 'Insecure Temporary File (CWE-377)': 'Risk 5: AppSec', 'Forced Browsing (CWE-425)': 'Risk 2: IAM', 'Credential Compromise & Weakness': 'Risk 3: DS & DLP', 'Certificate Services Exploitation': 'Risk 10: Vuln', 'Data Exposure & Information Disclosure': 'Risk 3: DS & DLP', 'Software & System Vulnerabilities': 'Risk 10: Vuln', 'Privilege Escalation Through Permissions': 'Risk 2: IAM', 'Authentication & Identity Weaknesses': 'Risk 2: IAM', 'Security Control Bypass': 'Risk 5: AppSec', 'Command & Script Execution Control': 'Risk 10: Vuln', 'Network Service Vulnerabilities': 'Risk 5: AppSec', 'Domain Configuration Weaknesses': 'Risk 2: IAM'}
ADVSIM_MAP_CATEGORY = {'PT-VULN-98': 'Authentication & Identity Weaknesses', 'IT-VULN-269': 'Authentication & Identity Weaknesses', 'FR-VULN-431': 'Authentication & Identity Weaknesses', 'FR-VULN-449': 'Authentication & Identity Weaknesses', 'MONST-VULN-111': 'Authentication & Identity Weaknesses', 'RS-VULN-170': 'Authentication & Identity Weaknesses', 'UK-VULN-43': 'Authentication & Identity Weaknesses', 'GIS-VULN-519': 'Authentication & Identity Weaknesses', 'GIS-VULN-555': 'Authentication & Identity Weaknesses', 'DIGIT-VULN-172': 'Authentication & Identity Weaknesses', 'CA-VULN-233': 'Authentication & Identity Weaknesses', 'TR-VULN-37': 'Authentication & Identity Weaknesses', 'CH-VULN-17': 'Authentication & Identity Weaknesses', 'CH-VULN-18': 'Authentication & Identity Weaknesses', 'MONST-VULN-118': 'Authentication & Identity Weaknesses', 'DIGIT-VULN-169': 'Authentication & Identity Weaknesses', 'NO-VULN-16': 'Authentication & Identity Weaknesses', 'IN-VULN-95': 'Authentication & Identity Weaknesses', 'GR-VULN-43': 'Authentication & Identity Weaknesses', 'RS-VULN-165': 'Authentication & Identity Weaknesses', 'GIS-VULN-486': 'Authentication & Identity Weaknesses', 'GIS-VULN-491': 'Authentication & Identity Weaknesses', 'DIGIT-VULN-166': 'Authentication & Identity Weaknesses', 'GIS-VULN-506': 'Authentication & Identity Weaknesses', 'GIS-VULN-533': 'Authentication & Identity Weaknesses', 'GIS-VULN-508': 'Authentication & Identity Weaknesses', 'GIS-VULN-517': 'Authentication & Identity Weaknesses', 'GIS-VULN-521': 'Authentication & Identity Weaknesses', 'ES-VULN-954': 'Authentication & Identity Weaknesses', 'ES-VULN-961': 'Authentication & Identity Weaknesses', 'PT-VULN-94': 'Authentication & Identity Weaknesses', 'TWAGO-VULN-96': 'Authentication & Identity Weaknesses', 'AU-VULN-203': 'Authentication & Identity Weaknesses', 'FR-VULN-437': 'Authentication & Identity Weaknesses', 'MONST-VULN-116': 'Authentication & Identity Weaknesses', 'NL-VULN-239': 'Authentication & Identity Weaknesses', 'DIGIT-VULN-165': 'Authentication & Identity Weaknesses', 'GIS-VULN-505': 'Authentication & Identity Weaknesses', 'DE-VULN-215': 'Authentication & Identity Weaknesses', 'DE-VULN-217': 'Authentication & Identity Weaknesses', 'GIS-VULN-605': 'Authentication & Identity Weaknesses', 'JP-VULN-165': 'Authentication & Identity Weaknesses', 'GIS-VULN-624': 'Authentication & Identity Weaknesses', 'GIS-VULN-642': 'Authentication & Identity Weaknesses', 'GIS-VULN-644': 'Authentication & Identity Weaknesses', 'RS-VULN-201': 'Authentication & Identity Weaknesses', 'RSR-VULN-27': 'Authentication & Identity Weaknesses', 'RSR-VULN-24': 'Authentication & Identity Weaknesses', 'FR-VULN-546': 'Authentication & Identity Weaknesses', 'DIGIT-VULN-139': 'Certificate Services Exploitation', 'FR-VULN-420': 'Certificate Services Exploitation', 'NL-VULN-236': 'Certificate Services Exploitation', 'DIGIT-VULN-148': 'Certificate Services Exploitation', 'US-VULN-324': 'Certificate Services Exploitation', 'US-VULN-354': 'Certificate Services Exploitation', 'FR-VULN-429': 'Certificate Services Exploitation', 'FR-VULN-457': 'Certificate Services Exploitation', 'NL-VULN-246': 'Certificate Services Exploitation', 'DIGIT-VULN-160': 'Certificate Services Exploitation', 'GIS-VULN-535': 'Certificate Services Exploitation', 'GIS-VULN-550': 'Certificate Services Exploitation', 'DIGIT-VULN-170': 'Certificate Services Exploitation', 'FR-VULN-543': 'Certificate Services Exploitation', 'NL-VULN-247': 'Certificate Services Exploitation', 'GIS-VULN-534': 'Certificate Services Exploitation', 'HU-VULN-60': 'Certificate Services Exploitation', 'CA-VULN-138': 'Command & Script Execution Control', 'CA-VULN-133': 'Command & Script Execution Control', 'IT-VULN-264': 'Command & Script Execution Control', 'FR-VULN-444': 'Command & Script Execution Control', 'NL-VULN-251': 'Command & Script Execution Control', 'UK-VULN-44': 'Command & Script Execution Control', 'CA-VULN-228': 'Command & Script Execution Control', 'MX-VULN-47': 'Command & Script Execution Control', 'AU-VULN-194': 'Command & Script Execution Control', 'AU-VULN-195': 'Command & Script Execution Control', 'PT-VULN-112': 'Command & Script Execution Control', 'DIGIT-VULN-137': 'Command & Script Execution Control', 'AT-VULN-19': 'Command & Script Execution Control', 'DK-VULN-13': 'Command & Script Execution Control', 'FR-VULN-445': 'Command & Script Execution Control', 'GIS-VULN-489': 'Command & Script Execution Control', 'PT-VULN-145': 'Command & Script Execution Control', 'GIS-VULN-650': 'Command & Script Execution Control', 'ES-VULN-962': 'Command & Script Execution Control', 'AU-VULN-197': 'Command & Script Execution Control', 'CZ-VULN-28': 'Command & Script Execution Control', 'LU-VULN-11': 'Command & Script Execution Control', 'DK-VULN-9': 'Command & Script Execution Control', 'FR-VULN-440': 'Command & Script Execution Control', 'FR-VULN-439': 'Command & Script Execution Control', 'FR-VULN-441': 'Command & Script Execution Control', 'MONST-VULN-112': 'Command & Script Execution Control', 'IN-VULN-94': 'Command & Script Execution Control', 'NL-VULN-242': 'Command & Script Execution Control', 'NL-VULN-253': 'Command & Script Execution Control', 'NL-VULN-254': 'Command & Script Execution Control', 'JP-VULN-144': 'Command & Script Execution Control', 'JP-VULN-143': 'Command & Script Execution Control', 'GR-VULN-41': 'Command & Script Execution Control', 'RS-VULN-168': 'Command & Script Execution Control', 'DIGIT-VULN-146': 'Command & Script Execution Control', 'DIGIT-VULN-152': 'Command & Script Execution Control', 'DIGIT-VULN-151': 'Command & Script Execution Control', 'UK-VULN-37': 'Command & Script Execution Control', 'UK-VULN-39': 'Command & Script Execution Control', 'UK-VULN-38': 'Command & Script Execution Control', 'GIS-VULN-492': 'Command & Script Execution Control', 'GIS-VULN-490': 'Command & Script Execution Control', 'GIS-VULN-493': 'Command & Script Execution Control', 'GIS-VULN-485': 'Command & Script Execution Control', 'GIS-VULN-526': 'Command & Script Execution Control', 'GIS-VULN-524': 'Command & Script Execution Control', 'GIS-VULN-525': 'Command & Script Execution Control', 'GIS-VULN-548': 'Command & Script Execution Control', 'NO-VULN-15': 'Command & Script Execution Control', 'SE-VULN-59': 'Command & Script Execution Control', 'SE-VULN-58': 'Command & Script Execution Control', 'US-VULN-325': 'Command & Script Execution Control', 'DE-VULN-218': 'Command & Script Execution Control', 'DE-VULN-213': 'Command & Script Execution Control', 'DIGIT-VULN-175': 'Command & Script Execution Control', 'DIGIT-VULN-174': 'Command & Script Execution Control', 'DIGIT-VULN-181': 'Command & Script Execution Control', 'DIGIT-VULN-182': 'Command & Script Execution Control', 'DIGIT-VULN-183': 'Command & Script Execution Control', 'DIGIT-VULN-184': 'Command & Script Execution Control', 'DIGIT-VULN-185': 'Command & Script Execution Control', 'DIGIT-VULN-186': 'Command & Script Execution Control', 'AT-VULN-20': 'Command & Script Execution Control', 'GIS-VULN-608': 'Command & Script Execution Control', 'CA-VULN-229': 'Command & Script Execution Control', 'AU-VULN-240': 'Command & Script Execution Control', 'NO-VULN-19': 'Command & Script Execution Control', 'NO-VULN-17': 'Command & Script Execution Control', 'NO-VULN-18': 'Command & Script Execution Control', 'GIS-VULN-640': 'Command & Script Execution Control', 'BR-VULN-117': 'Command & Script Execution Control', 'JP-VULN-183': 'Command & Script Execution Control', 'AU-VULN-265': 'Command & Script Execution Control', 'US-VULN-360': 'Command & Script Execution Control', 'DK-VULN-17': 'Command & Script Execution Control', 'SE-VULN-70': 'Command & Script Execution Control', 'FR-VULN-547': 'Command & Script Execution Control', 'FR-VULN-549': 'Command & Script Execution Control', 'ES-VULN-956': 'Credential Compromise & Weakness', 'PT-VULN-95': 'Credential Compromise & Weakness', 'CA-VULN-226': 'Credential Compromise & Weakness', 'GIS-VULN-584': 'Credential Compromise & Weakness', 'ES-VULN-957': 'Credential Compromise & Weakness', 'PT-VULN-96': 'Credential Compromise & Weakness', 'CA-VULN-135': 'Credential Compromise & Weakness', 'CA-VULN-131': 'Credential Compromise & Weakness', 'CA-VULN-132': 'Credential Compromise & Weakness', 'DIGIT-VULN-140': 'Credential Compromise & Weakness', 'IT-VULN-265': 'Credential Compromise & Weakness', 'IT-VULN-266': 'Credential Compromise & Weakness', 'LU-VULN-15': 'Credential Compromise & Weakness', 'LU-VULN-12': 'Credential Compromise & Weakness', 'LU-VULN-13': 'Credential Compromise & Weakness', 'FR-VULN-430': 'Credential Compromise & Weakness', 'FR-VULN-443': 'Credential Compromise & Weakness', 'FR-VULN-447': 'Credential Compromise & Weakness', 'MONST-VULN-114': 'Credential Compromise & Weakness', 'JP-VULN-145': 'Credential Compromise & Weakness', 'DIGIT-VULN-155': 'Credential Compromise & Weakness', 'DIGIT-VULN-158': 'Credential Compromise & Weakness', 'GIS-VULN-531': 'Credential Compromise & Weakness', 'GIS-VULN-527': 'Credential Compromise & Weakness', 'GIS-VULN-523': 'Credential Compromise & Weakness', 'GIS-VULN-552': 'Credential Compromise & Weakness', 'US-VULN-328': 'Credential Compromise & Weakness', 'DE-VULN-220': 'Credential Compromise & Weakness', 'IT-VULN-309': 'Credential Compromise & Weakness', 'CA-VULN-231': 'Credential Compromise & Weakness', 'GIS-VULN-625': 'Credential Compromise & Weakness', 'NL-VULN-263': 'Credential Compromise & Weakness', 'GIS-VULN-653': 'Credential Compromise & Weakness', 'GIS-VULN-655': 'Credential Compromise & Weakness', 'US-VULN-357': 'Credential Compromise & Weakness', 'US-VULN-361': 'Credential Compromise & Weakness', 'CZ-VULN-29': 'Credential Compromise & Weakness', 'RS-VULN-171': 'Credential Compromise & Weakness', 'UK-VULN-42': 'Credential Compromise & Weakness', 'GIS-VULN-487': 'Credential Compromise & Weakness', 'GIS-VULN-488': 'Credential Compromise & Weakness', 'HU-VULN-58': 'Credential Compromise & Weakness', 'ES-VULN-1161': 'Credential Compromise & Weakness', 'IN-VULN-111': 'Credential Compromise & Weakness', 'LU-VULN-39': 'Credential Compromise & Weakness', 'RS-VULN-199': 'Credential Compromise & Weakness', 'ES-VULN-960': 'Credential Compromise & Weakness', 'HU-VULN-48': 'Credential Compromise & Weakness', 'DE-VULN-398': 'Credential Compromise & Weakness', 'AU-VULN-192': 'Credential Compromise & Weakness', 'AU-VULN-198': 'Credential Compromise & Weakness', 'AU-VULN-202': 'Credential Compromise & Weakness', 'AU-VULN-201': 'Credential Compromise & Weakness', 'CZ-VULN-24': 'Credential Compromise & Weakness', 'DIGIT-VULN-135': 'Credential Compromise & Weakness', 'DIGIT-VULN-136': 'Credential Compromise & Weakness', 'AT-VULN-18': 'Credential Compromise & Weakness', 'LU-VULN-14': 'Credential Compromise & Weakness', 'DK-VULN-14': 'Credential Compromise & Weakness', 'FR-VULN-455': 'Credential Compromise & Weakness', 'FR-VULN-454': 'Credential Compromise & Weakness', 'BE-VULN-119': 'Credential Compromise & Weakness', 'DIGIT-VULN-157': 'Credential Compromise & Weakness', 'MX-VULN-48': 'Credential Compromise & Weakness', 'DIGIT-VULN-167': 'Credential Compromise & Weakness', 'GIS-VULN-539': 'Credential Compromise & Weakness', 'GIS-VULN-546': 'Credential Compromise & Weakness', 'DE-VULN-216': 'Credential Compromise & Weakness', 'IT-VULN-310': 'Credential Compromise & Weakness', 'BR-VULN-115': 'Credential Compromise & Weakness', 'BR-VULN-118': 'Credential Compromise & Weakness', 'RS-VULN-202': 'Credential Compromise & Weakness', 'RSR-VULN-26': 'Credential Compromise & Weakness', 'UK-VULN-53': 'Credential Compromise & Weakness', 'UK-VULN-54': 'Credential Compromise & Weakness', 'FR-VULN-544': 'Credential Compromise & Weakness', 'FR-VULN-419': 'Data Exposure & Information Disclosure', 'DIGIT-VULN-164': 'Data Exposure & Information Disclosure', 'AU-VULN-193': 'Data Exposure & Information Disclosure', 'AU-VULN-196': 'Data Exposure & Information Disclosure', 'AU-VULN-200': 'Data Exposure & Information Disclosure', 'DIGIT-VULN-141': 'Data Exposure & Information Disclosure', 'LU-VULN-16': 'Data Exposure & Information Disclosure', 'FR-VULN-446': 'Data Exposure & Information Disclosure', 'JP-VULN-147': 'Data Exposure & Information Disclosure', 'GR-VULN-42': 'Data Exposure & Information Disclosure', 'DIGIT-VULN-156': 'Data Exposure & Information Disclosure', 'UK-VULN-41': 'Data Exposure & Information Disclosure', 'UK-VULN-45': 'Data Exposure & Information Disclosure', 'US-VULN-329': 'Data Exposure & Information Disclosure', 'DIGIT-VULN-171': 'Data Exposure & Information Disclosure', 'AT-VULN-23': 'Data Exposure & Information Disclosure', 'AT-VULN-24': 'Data Exposure & Information Disclosure', 'AU-VULN-242': 'Data Exposure & Information Disclosure', 'AU-VULN-241': 'Data Exposure & Information Disclosure', 'IN-VULN-108': 'Data Exposure & Information Disclosure', 'CN-VULN-119': 'Data Exposure & Information Disclosure', 'LU-VULN-38': 'Data Exposure & Information Disclosure', 'MX-VULN-50': 'Data Exposure & Information Disclosure', 'FR-VULN-548': 'Data Exposure & Information Disclosure', 'DIGIT-VULN-168': 'Data Exposure & Information Disclosure', 'GIS-VULN-504': 'Data Exposure & Information Disclosure', 'DK-VULN-8': 'Data Exposure & Information Disclosure', 'NL-VULN-245': 'Data Exposure & Information Disclosure', 'PT-VULN-139': 'Data Exposure & Information Disclosure', 'ES-VULN-955': 'Data Exposure & Information Disclosure', 'ES-VULN-953': 'Data Exposure & Information Disclosure', 'PT-VULN-97': 'Data Exposure & Information Disclosure', 'HU-VULN-47': 'Data Exposure & Information Disclosure', 'DE-VULN-400': 'Data Exposure & Information Disclosure', 'IT-VULN-267': 'Data Exposure & Information Disclosure', 'FR-VULN-433': 'Data Exposure & Information Disclosure', 'BE-VULN-120': 'Data Exposure & Information Disclosure', 'MX-VULN-46': 'Data Exposure & Information Disclosure', 'GIS-VULN-507': 'Data Exposure & Information Disclosure', 'GIS-VULN-547': 'Data Exposure & Information Disclosure', 'SE-VULN-61': 'Data Exposure & Information Disclosure', 'ES-VULN-1160': 'Data Exposure & Information Disclosure', 'RSR-VULN-23': 'Data Exposure & Information Disclosure', 'FR-VULN-448': 'Domain Configuration Weaknesses', 'FR-VULN-450': 'Domain Configuration Weaknesses', 'FR-VULN-452': 'Domain Configuration Weaknesses', 'FR-VULN-453': 'Domain Configuration Weaknesses', 'FR-VULN-451': 'Domain Configuration Weaknesses', 'NL-VULN-243': 'Domain Configuration Weaknesses', 'NL-VULN-252': 'Domain Configuration Weaknesses', 'DIGIT-VULN-150': 'Domain Configuration Weaknesses', 'DIGIT-VULN-153': 'Domain Configuration Weaknesses', 'GIS-VULN-528': 'Domain Configuration Weaknesses', 'GIS-VULN-538': 'Domain Configuration Weaknesses', 'GIS-VULN-551': 'Domain Configuration Weaknesses', 'CA-VULN-232': 'Domain Configuration Weaknesses', 'ES-VULN-959': 'Domain Configuration Weaknesses', 'MONST-VULN-117': 'Domain Configuration Weaknesses', 'GR-VULN-46': 'Domain Configuration Weaknesses', 'RS-VULN-167': 'Domain Configuration Weaknesses', 'IT-VULN-308': 'Domain Configuration Weaknesses', 'GIS-VULN-627': 'Domain Configuration Weaknesses', 'IN-VULN-106': 'Domain Configuration Weaknesses', 'GIS-VULN-641': 'Domain Configuration Weaknesses', 'GIS-VULN-643': 'Domain Configuration Weaknesses', 'GIS-VULN-645': 'Domain Configuration Weaknesses', 'MONST-VULN-110': 'Domain Configuration Weaknesses', 'NL-VULN-244': 'Domain Configuration Weaknesses', 'NL-VULN-238': 'Domain Configuration Weaknesses', 'RS-VULN-166': 'Domain Configuration Weaknesses', 'DIGIT-VULN-147': 'Domain Configuration Weaknesses', 'UK-VULN-40': 'Domain Configuration Weaknesses', 'GIS-VULN-532': 'Domain Configuration Weaknesses', 'GIS-VULN-530': 'Domain Configuration Weaknesses', 'SE-VULN-60': 'Domain Configuration Weaknesses', 'US-VULN-326': 'Domain Configuration Weaknesses', 'JP-VULN-164': 'Domain Configuration Weaknesses', 'AU-VULN-239': 'Domain Configuration Weaknesses', 'GIS-VULN-623': 'Domain Configuration Weaknesses', 'GIS-VULN-626': 'Domain Configuration Weaknesses', 'IN-VULN-107': 'Domain Configuration Weaknesses', 'GIS-VULN-630': 'Domain Configuration Weaknesses', 'RSR-VULN-25': 'Domain Configuration Weaknesses', 'GIS-VULN-652': 'Domain Configuration Weaknesses', 'DK-VULN-16': 'Domain Configuration Weaknesses', 'DE-VULN-399': 'Network Service Vulnerabilities', 'AU-VULN-199': 'Network Service Vulnerabilities', 'FR-VULN-434': 'Network Service Vulnerabilities', 'FR-VULN-428': 'Network Service Vulnerabilities', 'FR-VULN-456': 'Network Service Vulnerabilities', 'DIGIT-VULN-159': 'Network Service Vulnerabilities', 'GIS-VULN-536': 'Network Service Vulnerabilities', 'FR-VULN-545': 'Network Service Vulnerabilities', 'TWAGO-VULN-98': 'Network Service Vulnerabilities', 'RS-VULN-172': 'Network Service Vulnerabilities', 'CN-VULN-118': 'Network Service Vulnerabilities', 'TWAGO-VULN-97': 'Network Service Vulnerabilities', 'CZ-VULN-25': 'Network Service Vulnerabilities', 'CH-VULN-16': 'Network Service Vulnerabilities', 'MONST-VULN-115': 'Network Service Vulnerabilities', 'IN-VULN-96': 'Network Service Vulnerabilities', 'JP-VULN-146': 'Network Service Vulnerabilities', 'DIGIT-VULN-154': 'Network Service Vulnerabilities', 'MX-VULN-49': 'Network Service Vulnerabilities', 'GIS-VULN-510': 'Network Service Vulnerabilities', 'GIS-VULN-514': 'Network Service Vulnerabilities', 'GIS-VULN-513': 'Network Service Vulnerabilities', 'GIS-VULN-515': 'Network Service Vulnerabilities', 'AT-VULN-21': 'Network Service Vulnerabilities', 'GIS-VULN-609': 'Network Service Vulnerabilities', 'IN-VULN-110': 'Network Service Vulnerabilities', 'BR-VULN-116': 'Network Service Vulnerabilities', 'RS-VULN-200': 'Network Service Vulnerabilities', 'GIS-VULN-651': 'Network Service Vulnerabilities', 'US-VULN-356': 'Network Service Vulnerabilities', 'US-VULN-358': 'Network Service Vulnerabilities', 'FR-VULN-542': 'Network Service Vulnerabilities', 'PL-VULN-136': 'Privilege Escalation Through Permissions', 'US-VULN-355': 'Privilege Escalation Through Permissions', 'DIGIT-VULN-194': 'Privilege Escalation Through Permissions', 'ES-VULN-958': 'Privilege Escalation Through Permissions', 'CA-VULN-137': 'Privilege Escalation Through Permissions', 'CA-VULN-134': 'Privilege Escalation Through Permissions', 'IT-VULN-270': 'Privilege Escalation Through Permissions', 'RS-VULN-173': 'Privilege Escalation Through Permissions', 'GIS-VULN-549': 'Privilege Escalation Through Permissions', 'US-VULN-327': 'Privilege Escalation Through Permissions', 'DE-VULN-219': 'Privilege Escalation Through Permissions', 'CA-VULN-230': 'Privilege Escalation Through Permissions', 'IN-VULN-109': 'Privilege Escalation Through Permissions', 'US-VULN-359': 'Privilege Escalation Through Permissions', 'GIS-VULN-606': 'Privilege Escalation Through Permissions', 'GR-VULN-49': 'Privilege Escalation Through Permissions', 'PT-VULN-99': 'Security Control Bypass', 'LU-VULN-9': 'Security Control Bypass', 'FR-VULN-432': 'Security Control Bypass', 'MONST-VULN-113': 'Security Control Bypass', 'GR-VULN-47': 'Security Control Bypass', 'GIS-VULN-520': 'Security Control Bypass', 'GIS-VULN-511': 'Security Control Bypass', 'GIS-VULN-509': 'Security Control Bypass', 'GIS-VULN-516': 'Security Control Bypass', 'GIS-VULN-522': 'Security Control Bypass', 'GIS-VULN-537': 'Security Control Bypass', 'GIS-VULN-518': 'Security Control Bypass', 'GIS-VULN-512': 'Security Control Bypass', 'GIS-VULN-556': 'Security Control Bypass', 'DE-VULN-214': 'Security Control Bypass', 'AT-VULN-22': 'Security Control Bypass', 'CA-VULN-227': 'Security Control Bypass', 'HU-VULN-59': 'Security Control Bypass', 'GIS-VULN-619': 'Security Control Bypass', 'TR-VULN-36': 'Security Control Bypass', 'GIS-VULN-628': 'Security Control Bypass', 'GIS-VULN-647': 'Security Control Bypass', 'GIS-VULN-656': 'Security Control Bypass', 'GIS-VULN-554': 'Security Control Bypass', 'GIS-VULN-646': 'Security Control Bypass', 'GIS-VULN-648': 'Security Control Bypass', 'GIS-VULN-649': 'Security Control Bypass', 'UK-VULN-52': 'Security Control Bypass', 'UK-VULN-51': 'Security Control Bypass', 'DIGIT-VULN-149': 'Software & System Vulnerabilities', 'ES-VULN-963': 'Software & System Vulnerabilities', 'CA-VULN-136': 'Software & System Vulnerabilities', 'DIGIT-VULN-138': 'Software & System Vulnerabilities', 'FR-VULN-438': 'Software & System Vulnerabilities', 'FR-VULN-442': 'Software & System Vulnerabilities', 'FR-VULN-435': 'Software & System Vulnerabilities', 'HU-VULN-49': 'Software & System Vulnerabilities', 'CH-VULN-19': 'Software & System Vulnerabilities', 'IT-VULN-268': 'Software & System Vulnerabilities', 'FR-VULN-436': 'Software & System Vulnerabilities', 'DIGIT-VULN-173': 'Software & System Vulnerabilities'}


# --- BQ SCHEMA (final table) ---
VULNERABILITIES_BQ_SCHEMA = [
    SchemaField("uuid", "STRING", mode="REQUIRED"),
    SchemaField("id", "STRING"),
    SchemaField("description", "STRING"),
    SchemaField("details", "STRING"),
    SchemaField("state", "STRING"),
    SchemaField("severity", "STRING"),
    SchemaField("original_severity", "STRING"),
    SchemaField("authenticated", "BOOLEAN"),
    SchemaField("cvss_vector", "STRING"),
    SchemaField("base_score", "FLOAT"),
    SchemaField("temporal_score", "FLOAT"),
    SchemaField("environmental_score", "FLOAT"),
    SchemaField("reopened_count", "INTEGER"),
    SchemaField("auto_unpark_at", "TIMESTAMP"),
    SchemaField("sub_state", "STRING"),
    SchemaField("tags", "STRING"),
    SchemaField("created_at", "TIMESTAMP"),
    SchemaField("published_at", "TIMESTAMP"),
    SchemaField("closed_at", "TIMESTAMP"),
    SchemaField("assigned_at", "TIMESTAMP"),
    SchemaField("contact_name", "STRING"),
    SchemaField("contact_email", "STRING"),
    SchemaField("vuln_type", "STRING"),
    SchemaField("test_id", "STRING"),
    SchemaField("test_state", "STRING"),
    SchemaField("market", "STRING"),
    SchemaField("created_email", "STRING"),
    SchemaField("published_by_email", "STRING"),
    SchemaField("asset_name", "STRING"),
    SchemaField("closed_by_email", "STRING"),
    SchemaField("time_to_solve_days", "INTEGER"),
    SchemaField("is_overdue", "BOOLEAN"),
    SchemaField("total_open_days", "FLOAT"),
    SchemaField("total_parked_days", "FLOAT"),
    SchemaField("total_validating_days", "FLOAT"),
    SchemaField("service", "STRING"),
    SchemaField("vuln_url", "STRING"),
    SchemaField("index_year", "INTEGER"),

    SchemaField("risk_category", "STRING"),
    SchemaField("kpi_category", "STRING"),
    SchemaField("remediation_risk", "FLOAT"),

]

# --- BQ SCHEMA (update history table) ---
UPDATE_HISTORY_SCHEMA = [
    SchemaField("update_time", "DATETIME", mode="REQUIRED"),
]


# --- Get Secret Function ---
def get_secret(secret_name):
    name = f"projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest"
    try:
        response = secret_client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.error(f"Failed to retrieve {secret_name} API key from Secret Manager: {e}")
        return None


# --- Dashboard setup ---
api_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "x-api-key": get_secret(DASHBOARD_SECRET_NAME)
}
base_url = "https://randstad.eu.vulnmanager.com/api/v3/"
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


# --- Build HTTP session with retries ---
def build_session():
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update(api_headers)
    return session

session = build_session()


# --- BigQuery helpers ---
def ensure_table_exists():
    table_id = f"{PROJECT_ID}.{BIGQUERY_DATASET}.{TABLE_NAME}"
    existed = True
    try:
        bq_client.get_table(table_id)
        logger.info(f"Table {table_id} already exists.")
    except NotFound:
        existed = False
        logger.info(f"Table {table_id} not found. Creating table...")
        table = Table(table_id, schema=VULNERABILITIES_BQ_SCHEMA)
        table.time_partitioning = TimePartitioning(type_=TimePartitioningType.MONTH, field="published_at")
        table.clustering_fields = ["market", "severity"]
        bq_client.create_table(table)
        logger.info(f"Created table {table.project}.{table.dataset_id}.{table.table_id}")
    return table_id, existed


def ensure_update_history_table_exists():
    table_id = f"{PROJECT_ID}.{BIGQUERY_DATASET}.{UPDATE_HISTORY_TABLE_NAME}"
    try:
        bq_client.get_table(table_id)
        logger.info(f"Update history table {table_id} already exists.")
    except NotFound:
        logger.info(f"Update history table {table_id} not found. Creating table...")
        table = Table(table_id, schema=UPDATE_HISTORY_SCHEMA)
        bq_client.create_table(table)
        logger.info(f"Created update history table {table.project}.{table.dataset_id}.{table.table_id}")
    return table_id


def insert_update_history():
    table_id = ensure_update_history_table_exists()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    df = pd.DataFrame([{'update_time': pd.to_datetime(current_time)}])
    try:
        to_gbq(df, f"{BIGQUERY_DATASET}.{UPDATE_HISTORY_TABLE_NAME}", project_id=PROJECT_ID, if_exists="append")
        logger.info(f"Inserted update time {current_time} into {table_id}.")
    except Exception as e:
        logger.error(f"Failed to insert into update history table {table_id}: {e}")


# --- Fetcher helper functions ---
def parse_time_spent(time_str: str) -> float:
    years = months = days = hours = minutes = seconds = 0
    matches = re.findall(r"(\d+)([YMdhs])", time_str)
    for value, unit in matches:
        value = int(value)
        if unit == 'Y':
            years = value
        elif unit == 'M':
            months = value
        elif unit == 'd':
            days = value
        elif unit == 'h':
            hours = value
        elif unit == 'm':
            minutes = value
        elif unit == 's':
            seconds = value
    return years * 365 + months * 30 + days + hours / 24 + minutes / 1440 + seconds / 86400


def get_data_range(year: int) -> str:
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31)
    return f"{start_date.strftime('%Y-%m-%d')}/{end_date.strftime('%Y-%m-%d')}"


def check_overdue(time_to_solve, history):
    total_days = 0.0
    for entry in history:
        if entry.get("state") in ("New", "Open") and entry.get("time_spent"):
            total_days = (parse_time_spent(entry["time_spent"]))
    return (total_days >= time_to_solve), total_days


def count_parked_time(history):
    return sum(parse_time_spent(h["time_spent"]) for h in history if h.get("state") == "Parked" and h.get("time_spent"))


def count_validating_time(history):
    return sum(
        parse_time_spent(h["time_spent"]) for h in history if h.get("state") == "Validating" and h.get("time_spent"))


def assign_time_to_solve(severity: str) -> int:
    return {"Critical": 14, "High": 30, "Medium": 45, "Low": 60, "Info": 270}.get(severity, 0)


def clean_details_for_item(item: dict) -> dict:
    raw_html = item.get("details")
    cleaned_text = ""
    if raw_html:
        soup = BeautifulSoup(raw_html, "html.parser")
        cleaned_text = soup.get_text(separator="\n", strip=True)
    item["details"] = cleaned_text
    return item


def check_normalize_service(tags, asset, creator, vuln_type):
    adv_sim_vuln_types = [
        'Adversary Simulation Finding', 'Adv. Sim. - Users can join computers into domain',
        'Adv. Sim. - SMTP open relay', 'Adv. Sim. - SMB signing is not enforced',
        'Adv. Sim. - PowerShell controls / In-Memory execution', 'Adv. Sim. - MachineAccountQuota',
        'Adv. Sim. - LDAP signing is not enforced', 'Adv. Sim. - Generic Template',
        'Adv. Sim. - Command and Scripting Interpreter: PowerShell', 'Adv. Sim. - Bypass: Zscaler'
    ]

    if vuln_type in adv_sim_vuln_types:
        return "Adversary Simulation"

    if "adversary simulation" in tags:
        return "Adversary Simulation"
    elif "whitebox" in tags:
        return "White Box"
    elif "blackbox" in tags:
        return "Black Box"
    elif "greybox" in tags:
        return "Black Box"
    else:
        if "Adversary" in (asset or ""):
            return "Adversary Simulation"
        elif "Adversary" not in (asset or "") and creator in GOST_LIST:
            return "White Box"
        elif "Adversary" not in (asset or "") and creator not in GOST_LIST:
            return "Black Box"
        else:
            return None


def normalize_tag(tag: list) -> list:
    tags = []
    for item in tag:
        tags.append(item["name"]) if item["name"] else None

    return tags


def add_tag(tags: list) -> str:
    tags_str = ""
    for item in tags:
        tags_str += f"{item}, "
    return tags_str


def kpi_category(severity: str) -> str:
    kpi_cat = None
    if severity in ['critical', 'high']:
        kpi_cat = "HIGH KPI"
    else:
        kpi_cat = "LOW KPI"
    return kpi_cat


def advsim_map_category(vuln_id: str) -> str | None:
    return ADVSIM_MAP_CATEGORY.get(vuln_id)


def assign_category(vuln_type: str) -> str | None:
    return VULNERABILITIES_MAP.get(vuln_type)


def calculate_remediation_risk(open_time: float, time_to_solve: int) -> float:
    if open_time and open_time > 0 and time_to_solve and time_to_solve > 0:
        remediation_risk =float (open_time / time_to_solve)
        return remediation_risk
    return 0


# -- Fetchers ---
def fetch_history(uuid):
    url = f"{base_url}vulnerabilities/{uuid}/history"
    page, all_items = 1, []
    while True:
        try:
            response = session.post(f"{url}?page={page}", json={}, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching history for {uuid}: {e}")
            break
        if response.status_code == 200:
            try:
                json_response = response.json()
                if json_response.get("items"):
                    all_items.extend(json_response["items"])
                else:
                    break
            except ValueError:
                logger.error(f"JSON decode error for {uuid}: {response.text[:200]}")
                break
        else:
            break
        page += 1
    return [h for h in all_items if h.get("state") != "Unpublished"]


def fetch_tags(uuid):
    url = f"{base_url}tags"
    page, all_items = 1, []
    body = {"vulnerabilities": [uuid]}

    while True:
        try:
            response = session.post(f"{url}?page={page}", json=body, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching tag for {uuid}: {e}")
            break
        if response.status_code == 200:
            try:
                json_response = response.json()
                if json_response.get("items"):
                    all_items.extend(json_response["items"])
                else:
                    break
            except ValueError:
                logger.error(f"JSON decode error for {uuid}: {response.text[:200]}")
                break
        else:
            break
        page += 1

    if all_items:
        tags = normalize_tag(all_items)
        return tags
    else:
        return []


def fetch_vulnerabilities(year: int):
    page = 1
    data = {}
    date_range = get_data_range(year)
    api_body = {"published_at": date_range}
    url = f"{base_url}vulnerabilities"
    logger.info(f"Fetching vulnerabilities for year {year}...")

    while True:
        response = session.post(f"{url}?page={page}", json=api_body, timeout=30)
        if response.status_code == 200:
            try:
                json_response = response.json()
                if json_response.get("items"):
                    data[page] = json_response["items"]
                else:
                    break
            except ValueError:
                logger.error("[!] Response is not in JSON format.")
                break
        else:
            if response.status_code == 400 and page == 1:
                raise RuntimeError("API issue: check key/permissions.")
            else:
                logger.warning(f"Request failed with {response.status_code} at page {page}.")
                break
        logger.info(f"[+] Fetching page {page}...")
        page += 1

    flatten_data = [item for sublist in data.values() for item in sublist]
    if not flatten_data:
        logger.warning(f"[!] No vulnerabilities found for year {year}.")
        return []

    logger.info(f"[+] Adjust Netherlands organization name.")
    for item in flatten_data:
        org = item.get("organisation")
        if org and org.get("name") == "Randstad Groep Nederland":
            org["name"] = "Netherlands"

    # Filter out unwanted organisations
    logger.info("[+] Filtering out organisation 'Integrity'...")
    flatten_data = [
        item for item in flatten_data
        if not (item.get("organisation") and item["organisation"].get("name") == "Integrity")
    ]
    logger.info(f"[+] Flattened {len(flatten_data)} vulnerabilities.")

    return flatten_data


def process_vulnerabilities(year: int, existing: dict = None):
    vulnerabilities = fetch_vulnerabilities(year)

    items_new = []
    items_update = []
    for item in vulnerabilities:
        try:
            uuid = item.get("uuid")
            if not uuid:
                continue

            if existing is None:
                items_new.append(item)
                continue

            if uuid not in existing:
                items_new.append(item)
            else:
                bq_state = existing[uuid]
                api_state = item.get("state")
                if api_state == "Closed" and bq_state == "Closed":
                    continue
                items_update.append(item)
        except Exception as e:
            logger.error(f"Error checking item {item.get('uuid')}: {e}")

    # Fetch additional data in parallel
    # For new items
    if items_new:
        logger.info(f"[+] Fetching tags for {len(items_new)} new items...")
        with ThreadPoolExecutor(max_workers=SAFE_MAX_WORKERS) as executor:
            future_to_item = {executor.submit(fetch_tags, item["uuid"]): item for item in items_new}
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    item["tags"] = future.result()
                except Exception as e:
                    logger.error(f"Error fetching tags for {item['uuid']}: {e}")
                    item["tags"] = None

        logger.info(f"[+] Fetching history for {len(items_new)} new items...")
        with ThreadPoolExecutor(max_workers=SAFE_MAX_WORKERS) as executor:
            future_to_item = {executor.submit(fetch_history, item["uuid"]): item for item in items_new}
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    item["history"] = future.result()
                except Exception as e:
                    logger.error(f"Error fetching history for {item['uuid']}: {e}")
                    item["history"] = None

    # For update items
    if items_update:
        logger.info(f"[+] Fetching history for {len(items_update)} update items...")
        with ThreadPoolExecutor(max_workers=SAFE_MAX_WORKERS) as executor:
            future_to_item = {executor.submit(fetch_history, item["uuid"]): item for item in items_update}
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    item["history"] = future.result()
                except Exception as e:
                    logger.error(f"Error fetching history for {item['uuid']}: {e}")
                    item["history"] = None

    # Process new items fully
    processed_items = []
    keys_to_remove = ["overdue", "due_date", "review_date_park", "ready_to_publish", "jira_issue", "due_date_by",
                      "assignee", "vulnerability_type", "test", "organisation", "asset_groups", "fields",
                      "attachments", "created_by", "last_modified_at", "last_modified_by", "published_by",
                      "asset", "opened_at", "opened_by", "validating_at", "validating_by", "last_reopened", "closed_by",
                      "parked_at", "parked_by", "assigned_by", "history"]

    for item in items_new:
        try:
            if item.get("history") is None or item.get("tags") is None:
                logger.warning(f"Skipping new item {item['uuid']} due to missing additional data.")
                continue

            if item.get("state") == "New":
                item["state"] = "Open"
            item["base_score"] = float(item.get("base_score")) if item.get("base_score") else 0
            item["temporal_score"] = float(item.get("temporal_score")) if item.get("temporal_score") else 0
            item["environmental_score"] = float(item.get("environmental_score")) if item.get("environmental_score") else 0
            item["contact_name"] = item.get("assignee", {}).get("name") if item.get("assignee") else None
            item["contact_email"] = item.get("assignee", {}).get("email") if item.get("assignee") else None

            vuln_id = item.get("id") if item.get("id") else None
            if ADVSIM_MAP_CATEGORY.get(vuln_id):
                item["vuln_type"] = advsim_map_category(vuln_id)
            else:
                item["vuln_type"] =  item.get("vulnerability_type", {}).get("name") if item.get("vulnerability_type") else None

            item["test_id"] = item.get("test", {}).get("id") if item.get("test") else None
            item["test_state"] = item.get("test", {}).get("state") if item.get("test") else None
            item["market"] = item.get("organisation", {}).get("name") if item.get("organisation") else None
            item["created_email"] = item.get("created_by", {}).get("email") if item.get("created_by") else None
            item["published_by_email"] = item.get("published_by", {}).get("email") if item.get("published_by") else None
            item["asset_name"] = item.get("asset", {}).get("name") if item.get("asset") else None
            item["closed_by_email"] = item.get("closed_by", {}).get("email") if item.get("closed_by") else None
            item["time_to_solve_days"] = assign_time_to_solve(item.get("severity")) if item.get("severity") else None
            item["is_overdue"], item["total_open_days"] = check_overdue(item["time_to_solve_days"], item.get("history") or [])
            item["total_parked_days"] = count_parked_time(item.get("history") or [])
            item["total_validating_days"] = count_validating_time(item.get("history") or [])
            item["service"] = check_normalize_service(item.get("tags"), item.get("asset_name"), item.get("created_email"), item["vuln_type"])
            item["tags"] = add_tag(item.get("tags"))
            item["vuln_url"] = f"https://randstad.eu.vulnmanager.com/vulnerabilities/{item['uuid']}/show"
            item["index_year"] = int(year)
            item["risk_category"] = assign_category(item["vuln_type"])
            item["remediation_risk"] = calculate_remediation_risk(float(item["total_open_days"]), int(item["time_to_solve_days"]))
            item["kpi_category"] = kpi_category(item.get("severity") if item.get("severity") else None)
            item = clean_details_for_item(item)
            for k in keys_to_remove:
                item.pop(k, None)
            processed_items.append(item)
        except Exception as e:
            logger.error(f"Error processing new item {item.get('uuid')}: {e}")

    # Process update items partially
    for item in items_update:
        try:
            if item.get("history") is None:
                logger.warning(f"Skipping update for {item['uuid']} due to missing additional data.")
                continue

            update_dict = {"uuid": item["uuid"]}

            if item.get("state") == "New":
                item["state"] = "Open"
            update_dict["state"] = item.get("state")
            update_dict["severity"] = item.get("severity")
            update_dict["original_severity"] = item.get("original_severity")
            update_dict["reopened_count"] = item.get("reopened_count")
            update_dict["auto_unpark_at"] = item.get("auto_unpark_at")
            update_dict["sub_state"] = item.get("sub_state")
            update_dict["closed_at"] = item.get("closed_at")
            update_dict["assigned_at"] = item.get("assigned_at")
            update_dict["contact_name"] = item.get("assignee", {}).get("name") if item.get("assignee") else None
            update_dict["contact_email"] = item.get("assignee", {}).get("email") if item.get("assignee") else None
            update_dict["closed_by_email"] = item.get("closed_by", {}).get("email") if item.get("closed_by") else None
            time_to_solve_days = assign_time_to_solve(item.get("severity")) if item.get("severity") else None
            update_dict["time_to_solve_days"] = time_to_solve_days
            is_overdue, total_open_days = check_overdue(time_to_solve_days, item.get("history") or [])
            update_dict["is_overdue"] = is_overdue
            update_dict["total_open_days"] = total_open_days
            update_dict["total_parked_days"] = count_parked_time(item.get("history") or [])
            update_dict["total_validating_days"] = count_validating_time(item.get("history") or [])
            update_dict["remediation_risk"] = calculate_remediation_risk(float(update_dict["total_open_days"]), int(update_dict["time_to_solve_days"]))

            processed_items.append(update_dict)
        except Exception as e:
            logger.error(f"Error processing update item {item.get('uuid')}: {e}")

    return processed_items


def run_job_logic(year: int, chat_id: str = None):
    start_time = time.time()
    table_id, table_existed = ensure_table_exists()

    float_cols = [
        "base_score", "temporal_score", "environmental_score",
        "total_open_days", "total_parked_days", "total_validating_days",
        "remediation_risk"
    ]

    int_cols = [
        "reopened_count", "time_to_solve_days", "index_year"
    ]
    bool_cols = [
        "authenticated", "is_overdue"
    ]
    timestamp_cols = [
        "auto_unpark_at", "created_at", "published_at", "closed_at",
        "assigned_at"
    ]

    if not table_existed:
        # Full load
        processed_items = process_vulnerabilities(year)
        df = pd.DataFrame(processed_items)

        for col in float_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        for col in int_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')

        for col in bool_cols:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda x: True if str(x).lower() in ['true', '1'] else (
                        False if str(x).lower() in ['false', '0'] else None)
                ).astype('boolean')

        for col in timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce', utc=True)

        table_name = f"{BIGQUERY_DATASET}.{TABLE_NAME}"
        try:
            to_gbq(df, table_name, project_id=PROJECT_ID, if_exists="replace")
            logger.info(f"Table {table_name} successfully created with full load.")
            insert_update_history()
            end_time = time.time()
            duration = end_time - start_time
            returning_message = f"[+] Successfully processed and loaded data for year {year}. Duration: {duration:.2f}s"
            logger.info(returning_message)
            try:
                webhook_url = get_secret(N8N_WEBHOOK_URL)
                if webhook_url:
                    payload = {
                        "status": "success",
                        "message": returning_message,
                        "chatId": chat_id
                    }
                    requests.post(webhook_url, json=payload)
            except Exception as e:
                logger.error(f"Failed to call 'job finished' webhook: {e}")

            return returning_message, 200
        except Exception as e:
            logger.error(f"Table {table_name} could not be created. {e}")
            end_time = time.time()
            duration = end_time - start_time
            returning_message = f"[-] Failed to process data for year {year}. Error: {e}"
            logger.error(f"{returning_message} {duration:.2f}s")
            try:
                webhook_url = get_secret(N8N_WEBHOOK_URL)
                payload = {
                    "status": "error",
                    "message": returning_message,
                    "chatId": chat_id
                }
                if webhook_url:
                    requests.post(webhook_url, json=payload)
            except Exception as e:
                logger.error(f"Failed to call 'job finished' webhook: {e}")
            return returning_message, 500
    else:
        # Incremental load
        query = f"SELECT uuid, state FROM `{table_id}`"
        try:
            job = bq_client.query(query)
            existing = {row['uuid']: row['state'] for row in job.result()}
        except Exception as e:
            logger.error(f"Error querying existing uuids: {e}")
            return f"Failed to query existing data for year {year}. Error: {e}", 500

        processed_items = process_vulnerabilities(year, existing)
        if not processed_items:
            logger.info(f"No items to process for year {year}. Skipping merge.")
            insert_update_history()
            end_time = time.time()
            duration = end_time - start_time
            returning_message = f"No updates or new items for year {year}. Duration: {duration:.2f}s"
            return returning_message, 200

        df = pd.DataFrame(processed_items)

        # Fix types only for columns that may be present (since updates have fewer columns)
        for col in float_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')

        for col in int_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')

        for col in bool_cols:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda x: True if str(x).lower() in ['true', '1'] else (
                        False if str(x).lower() in ['false', '0'] else None)
                ).astype('boolean')

        for col in timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce', utc=True)

        staging_table_name = f"{BIGQUERY_DATASET}.{STAGING_TABLE_NAME}"
        try:
            to_gbq(df, staging_table_name, project_id=PROJECT_ID, if_exists="replace")
            logger.info(f"Staging table {staging_table_name} loaded.")
        except Exception as e:
            logger.error(f"Failed to load staging table: {e}")
            return f"Failed to load staging data for year {year}. Error: {e}", 500

        # Define update fields (common to all updates)
        update_fields = [
            "state", "severity", "original_severity", "reopened_count", "auto_unpark_at", "sub_state",
            "closed_at", "assigned_at", "contact_name", "contact_email", "closed_by_email",
            "time_to_solve_days", "is_overdue", "total_open_days", "total_parked_days",
            "total_validating_days", "remediation_risk"
        ]
        update_set_clause = ", ".join(f"{field} = S.{field}" for field in update_fields)

        # Define insert fields (based on DataFrame columns)
        all_possible_fields = [field.name for field in VULNERABILITIES_BQ_SCHEMA]
        insert_fields = [col for col in df.columns if col in all_possible_fields]
        insert_clause = ", ".join(insert_fields)
        values_clause = ", ".join(f"S.{col}" for col in insert_fields)

        merge_query = f"""
        MERGE `{table_id}` T
        USING `{PROJECT_ID}.{staging_table_name}` S
        ON T.uuid = S.uuid
        WHEN MATCHED THEN
          UPDATE SET
            {update_set_clause}
        WHEN NOT MATCHED THEN
          INSERT ({insert_clause})
          VALUES ({values_clause})
        """
        try:
            job = bq_client.query(merge_query)
            job.result()
            insert_update_history()
            end_time = time.time()
            duration = end_time - start_time
            returning_message = f"Successfully processed incremental data for year {year}. Duration: {duration:.2f}s"
            logger.info(returning_message)
            try:
                webhook_url = get_secret(N8N_WEBHOOK_URL)
                payload = {
                    "status": "success",
                    "message": returning_message,
                    "chatId": chat_id
                }
                if webhook_url:
                    requests.post(webhook_url, json=payload)
            except Exception as e:
                logger.error(f"Failed to call 'job finished' webhook: {e}")


            return returning_message, 200
        except Exception as e:
            returning_message = f"Failed to merge data for year {year}. Error: {e}"
            logger.info(returning_message)
            try:
                webhook_url = get_secret(N8N_WEBHOOK_URL)
                payload = {
                    "status": "error",
                    "message": returning_message,
                    "chatId": chat_id
                }
                if webhook_url:
                    requests.post(webhook_url, json=payload)
            except Exception as e:
                logger.error(f"Failed to call 'job finished' webhook: {e}")
            return returning_message, 500


@app.route("/run-job", methods=["POST"])
def run_job():
    # Pub/Sub sends a specific JSON envelope
    try:
        envelope = request.get_json()
        if not envelope or "message" not in envelope:
            logger.error(f"Bad Pub/Sub request: {envelope}")
            return "Bad Request: Invalid Pub/Sub message format", 400

        # Decode the actual data, which is base64 encoded
        pubsub_message = envelope["message"]
        data_str = base64.b64decode(pubsub_message["data"]).decode("utf-8")
        data = json.loads(data_str)

    except Exception as e:
        logger.error(f"Failed to decode Pub/Sub message: {e}")
        # Return 500 so Pub/Sub retries the message
        return f"Failed to decode message: {e}", 500

    if not data or 'year' not in data:
        error_msg = "Bad Request: Pub/Sub data must contain a 'year' key."
        logger.error(error_msg)
        # Return 200 OK to Pub/Sub to *acknowledge* the bad message
        # so it doesn't retry a message that will *never* work.
        return error_msg, 200

    year = int(data['year'])
    chat_id = data.get('chatId')
    logger.info(f"Starting job for year {year} from Pub/Sub. Notifying chatId: {chat_id}.")

    # Call the actual logic
    message, code = run_job_logic(year, chat_id)

    # Return 200 or 500 to Pub/Sub to acknowledge/retry
    return message, code

@app.route("/", methods=["POST"])
def start_job():
    data = request.get_json()
    if not data or 'year' not in data:
        error_msg = "Bad Request: JSON body must contain a 'year' key."
        logger.error(error_msg)
        return error_msg, 400

    year = int(data['year'])

    try:
        # --- Publish the message to Pub/Sub ---
        # Data must be bytes
        data_bytes = json.dumps(data).encode("utf-8")

        future = publisher_client.publish(topic_path, data_bytes)
        message_id = future.get()  # Waits for publish to complete

        logger.info(f"Published message {message_id} for year {year} to {PUBSUB_TOPIC}.")

        # --- Immediately return 202 to n8n ---
        return f"Job for year {year} successfully queued.", 202

    except Exception as e:
        logger.error(f"Failed to publish to Pub/Sub for year {year}: {e}")
        return f"Failed to queue job: {e}", 500

