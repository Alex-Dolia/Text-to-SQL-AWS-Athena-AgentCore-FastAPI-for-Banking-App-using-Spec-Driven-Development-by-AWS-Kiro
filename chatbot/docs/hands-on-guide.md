# Setting Up AWS Services for the Athena Chatbot

After you've created your Python project, this guide walks you through every AWS service setup step-by-step — with real AWS CLI commands, Python (boto3) code, and SQL statements you can copy and run.

## Prerequisites

### Tools & Accounts You Need

| Tool | Install | Verify |
|------|---------|--------|
| AWS CLI v2 | `msiexec /i https://awscli.amazonaws.com/AWSCLIV2.msi` | `aws --version` |
| Python 3.11+ | [python.org](https://python.org) | `python --version` |
| boto3 | `pip install boto3` | `python -c "import boto3; print(boto3.__version__)"` |
| AWS account | With permissions for S3, Athena, Glue, Cognito, Bedrock AgentCore | `aws sts get-caller-identity` |

### Configure AWS CLI

```bash
# Set your region and credentials
aws configure
# AWS Access Key ID: <your-key>
# AWS Secret Access Key: <your-secret>
# Default region name: eu-west-2  (or your bank's region)
# Default output format: json
```

## Python Project Setup

Assuming you already have a project folder. Here's the minimal structure we'll build on:

```
athena-chatbot/
├── api/
│   ├── __init__.py
│   ├── main.py          # FastAPI app
│   ├── auth.py          # JWT validation
│   └── config.py        # Settings
├── scripts/
│   ├── setup_athena.py  # Athena table creation
│   ├── setup_cognito.py # Cognito provisioning
│   └── setup_cedar.py   # Cedar policy deployment
├── policies/
│   └── chatbot.cedar    # Cedar policy files
├── data/
│   └── sample.csv       # Sample CSV for testing
├── requirements.txt
└── pyproject.toml
```

### requirements.txt

```
fastapi==0.115.0
uvicorn[standard]==0.30.0
boto3==1.35.0
python-jose[cryptography]==3.3.0
httpx==0.27.0
pydantic==2.9.0
pydantic-settings==2.5.0
```

```bash
# Install dependencies
pip install -r requirements.txt
```

## Lab 1 — Athena Tables from CSV

### 1. Upload CSV Files to S3

Athena queries data stored in S3. Your CSV files must be in a bucket before you can create tables over them.

#### Sample CSV (data/orders.csv)

```
order_id,customer_id,order_date,amount,region,product_category
1001,C-2341,2025-01-15,1250.00,EMEA,Fixed Income
1002,C-1892,2025-01-16,3400.50,APAC,Equities
1003,C-0045,2025-01-16,890.25,EMEA,Derivatives
1004,C-2341,2025-01-17,5600.00,AMER,Fixed Income
1005,C-1100,2025-01-18,2100.75,EMEA,Equities
```

#### AWS CLI: Create bucket & upload

```bash
# Create the data lake bucket (use your own unique name)
aws s3 mb s3://fi-datalake-dev-eu-west-2 --region eu-west-2

# Upload CSV files (organized by database/table/)
aws s3 cp data/orders.csv s3://fi-datalake-dev-eu-west-2/trading/orders/orders.csv

# Upload multiple CSVs at once
aws s3 sync data/ s3://fi-datalake-dev-eu-west-2/trading/orders/ \
  --exclude "*" --include "*.csv"

# Verify upload
aws s3 ls s3://fi-datalake-dev-eu-west-2/trading/orders/
```

#### Python (boto3): Upload programmatically

```python
# scripts/upload_csv.py
# Purpose: Upload local CSV files to S3 so Athena can query them.
# Athena reads data directly from S3 — this script puts it there.

import boto3              # AWS SDK for Python — lets us call S3 APIs
from pathlib import Path  # Modern file path handling (cross-platform)

# Create an S3 client — this handles authentication automatically
# using credentials from 'aws configure' or environment variables
s3 = boto3.client('s3', region_name='eu-west-2')

BUCKET = 'fi-datalake-dev-eu-west-2'  # Target S3 bucket name (must be globally unique)
DATA_DIR = Path('data')                     # Local folder containing your CSV files

# Create the S3 bucket if it doesn't already exist
# LocationConstraint is required for any region other than us-east-1
try:
    s3.create_bucket(
        Bucket=BUCKET,                                                  # Bucket name
        CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}  # Region where bucket lives
    )
    print(f"Created bucket: {BUCKET}")
except s3.exceptions.BucketAlreadyOwnedByYou:  # Safe to ignore if we already own it
    print(f"Bucket already exists: {BUCKET}")

# Upload every .csv file from the local data/ folder to S3
# Files are organized as: s3://bucket/database/table/filename.csv
# This path structure matches what Athena's LOCATION will point to
for csv_file in DATA_DIR.glob('*.csv'):           # Find all CSV files in data/
    key = f"trading/orders/{csv_file.name}"        # S3 key (path inside the bucket)
    s3.upload_file(str(csv_file), BUCKET, key)      # Upload local file → S3
    print(f"Uploaded: {csv_file.name} → s3://{BUCKET}/{key}")
```

> **Bank best practice:** In production, enable S3 bucket encryption (SSE-KMS with a customer-managed key), versioning, and block all public access. For this lab, we keep it simple.

### 2. Create a Glue Database

Athena uses the AWS Glue Data Catalog as its metadata store. Tables belong to databases in the catalog.

#### AWS CLI

```bash
# Create a Glue database — this is a metadata container for tables.
# It does NOT create storage. Think of it like CREATE SCHEMA in PostgreSQL.
aws glue create-database --database-input '{
  "Name": "trading",
  "Description": "Trading data lake - orders, positions, clients"
}' --region eu-west-2

# Verify the database was created successfully
aws glue get-database --name trading --region eu-west-2
```

#### Python (boto3)

```python
# scripts/setup_athena.py (excerpt — database creation only)
# This snippet shows just the database creation part.
# The full script (step 4) combines this with table creation + test query.

import boto3  # AWS SDK — handles auth and API calls

# Connect to the Glue service (manages the Data Catalog)
glue = boto3.client('glue', region_name='eu-west-2')

# Create the database in the Glue Data Catalog
# DatabaseInput is a dict with metadata about the database
glue.create_database(
    DatabaseInput={
        'Name': 'trading',
        'Description': 'Trading data lake - orders, positions, clients'
    }
)
print("Database 'trading' created in Glue Catalog")
```

### 3. CREATE TABLE for CSV in Athena

Now we tell Athena how to read our CSV files by creating an external table pointing to the S3 location.

#### SQL (run in Athena console or via CLI)

```sql
-- Create table for CSV data with headers
CREATE EXTERNAL TABLE IF NOT EXISTS trading.orders (
  order_id      STRING,
  customer_id   STRING,
  order_date    DATE,
  amount        DOUBLE,
  region        STRING,
  product_category STRING
)
ROW FORMAT DELIMITED
  FIELDS TERMINATED BY ','
  LINES TERMINATED BY '\n'
LOCATION 's3://fi-datalake-dev-eu-west-2/trading/orders/'
TBLPROPERTIES (
  'skip.header.line.count' = '1',
  'classification' = 'csv'
);
```

> **Key points:**
> - `skip.header.line.count = '1'` — skips the CSV header row
> - `ROW FORMAT DELIMITED FIELDS TERMINATED BY ','` — uses the LazySimpleSerDe (default for delimited data)
> - If your CSV has quoted fields (commas inside values), use `ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde'` instead
> - LOCATION points to the S3 **folder**, not a specific file — Athena reads all files in that path

#### For CSV with quoted fields (OpenCSVSerDe)

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS trading.clients (
  client_id     STRING,
  client_name   STRING,
  address       STRING,    -- may contain commas
  tier          STRING,
  onboard_date  STRING     -- OpenCSVSerDe treats all as STRING
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde'
WITH SERDEPROPERTIES (
  'separatorChar' = ',',
  'quoteChar'     = '"',
  'escapeChar'    = '\\'
)
LOCATION 's3://fi-datalake-dev-eu-west-2/trading/clients/'
TBLPROPERTIES ('skip.header.line.count' = '1');
```

#### AWS CLI: Run the CREATE TABLE

```bash
# Run DDL via Athena CLI
aws athena start-query-execution \
  --query-string "CREATE EXTERNAL TABLE IF NOT EXISTS trading.orders (
    order_id STRING, customer_id STRING, order_date DATE,
    amount DOUBLE, region STRING, product_category STRING
  ) ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
  LOCATION 's3://fi-datalake-dev-eu-west-2/trading/orders/'
  TBLPROPERTIES ('skip.header.line.count'='1')" \
  --work-group "primary" \
  --region eu-west-2

# Check execution status
aws athena get-query-execution \
  --query-execution-id <id-from-above> \
  --region eu-west-2

# Test: query the table
aws athena start-query-execution \
  --query-string "SELECT * FROM trading.orders LIMIT 5" \
  --work-group "primary" \
  --result-configuration "OutputLocation=s3://fi-datalake-dev-eu-west-2/query-results/" \
  --region eu-west-2
```

### 4. Athena via Python (Complete Script)

This script automates everything from steps 2-3 into a single runnable Python file. Here's what it does:

| Function | What it does | AWS API calls |
|----------|-------------|---------------|
| `create_database()` | Creates the `trading` database in the Glue Data Catalog. If it already exists, skips without error. | `glue.create_database()` |
| `run_query(sql)` | Submits any SQL statement to Athena, then **polls every 1 second** until the query completes (SUCCEEDED, FAILED, or CANCELLED). Returns the query execution ID for fetching results. | `athena.start_query_execution()`, `athena.get_query_execution()` |
| `create_orders_table()` | Runs the `CREATE EXTERNAL TABLE` DDL that maps your CSV files in S3 to a queryable Athena table. Tells Athena: where the data is (S3 path), what format it's in (comma-delimited CSV), and to skip the header row. | Uses `run_query()` internally |
| `test_query()` | Runs `SELECT * FROM trading.orders LIMIT 5` and prints the results to confirm everything works. This proves: S3 has data, Glue knows the schema, and Athena can read the CSV. | `athena.get_query_results()` |

> **How it works end-to-end:**
> 1. Script connects to AWS using your configured credentials (`aws configure`)
> 2. Creates the Glue database (metadata container for tables)
> 3. Submits the CREATE TABLE DDL to Athena — this doesn't move or copy data, it just tells Athena "there are CSV files at this S3 path, here's how to read them"
> 4. Athena registers the table in the Glue Data Catalog
> 5. Runs a test query to prove the pipeline works
> 6. Prints results to terminal — if you see your CSV data, everything is connected correctly

```python
# scripts/setup_athena.py — Full script: create DB, table, run test query
import boto3
import time

# ─── CONFIGURATION ───────────────────────────────────────────────────
# Change these values to match your AWS environment
REGION = 'eu-west-2'                          # AWS region where your S3 bucket lives
BUCKET = 'fi-datalake-dev-eu-west-2'      # S3 bucket containing your CSV files
DATABASE = 'trading'                           # Glue database name (logical grouping)
TABLE = 'orders'                               # Table name that will appear in Athena
WORKGROUP = 'primary'                          # Athena workgroup (controls cost/access)
OUTPUT_LOCATION = f's3://{BUCKET}/query-results/'  # Where Athena writes query results

# ─── AWS CLIENTS ─────────────────────────────────────────────────────
# boto3 clients for the two services we interact with:
# - Glue: manages the Data Catalog (databases + table metadata)
# - Athena: runs SQL queries against data in S3
glue = boto3.client('glue', region_name=REGION)
athena = boto3.client('athena', region_name=REGION)


# ─── FUNCTION 1: CREATE DATABASE ─────────────────────────────────────
# A Glue database is just a logical container for tables.
# Think of it like a schema in PostgreSQL — it groups related tables.
# This does NOT create storage; it only creates a metadata entry.
def create_database():
    """Create Glue database if it doesn't exist."""
    try:
        glue.create_database(
            DatabaseInput={'Name': DATABASE, 'Description': 'Trading data lake'}
        )
        print(f"✓ Database '{DATABASE}' created")
    except glue.exceptions.AlreadyExistsException:
        print(f"• Database '{DATABASE}' already exists")


# ─── FUNCTION 2: RUN QUERY ───────────────────────────────────────────
# Athena queries are ASYNCHRONOUS. When you submit SQL:
#   1. Athena returns immediately with a query ID
#   2. The query runs in the background (may take seconds to minutes)
#   3. You must poll get_query_execution() to check if it's done
#   4. Once SUCCEEDED, you can fetch results with get_query_results()
# This function handles steps 1-3 (submit + poll until done).
def run_query(sql: str) -> str:
    """Execute an Athena query and wait for results."""
    # Step 1: Submit the query to Athena
    response = athena.start_query_execution(
        QueryString=sql,                                   # The SQL to run
        QueryExecutionContext={'Database': DATABASE},        # Default database for unqualified table names
        WorkGroup=WORKGROUP,                               # Controls concurrency limits and cost tracking
        ResultConfiguration={'OutputLocation': OUTPUT_LOCATION}  # S3 path for result CSV files
    )
    query_id = response['QueryExecutionId']
    print(f"  Query started: {query_id}")

    # Step 2: Poll until the query finishes (check every 1 second)
    while True:
        status = athena.get_query_execution(QueryExecutionId=query_id)
        state = status['QueryExecution']['Status']['State']
        if state in ('SUCCEEDED', 'FAILED', 'CANCELLED'):
            break
        time.sleep(1)  # Wait 1 second before checking again

    # Step 3: If query failed, raise an error with the reason
    if state != 'SUCCEEDED':
        reason = status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
        raise RuntimeError(f"Query failed: {reason}")

    return query_id  # Return ID so caller can fetch results


# ─── FUNCTION 3: CREATE TABLE ────────────────────────────────────────
# This tells Athena how to read your CSV files. Specifically:
#   - "There are files at this S3 location"
#   - "They are CSV format (comma-delimited)"
#   - "Here are the column names and types"
#   - "Skip the first line (it's a header)"
# IMPORTANT: This does NOT copy or move data. The CSV stays in S3.
# Athena reads it directly from S3 every time you query.
def create_orders_table():
    """Create the orders table over CSV in S3."""
    ddl = f"""
    CREATE EXTERNAL TABLE IF NOT EXISTS {DATABASE}.{TABLE} (
      order_id         STRING,        -- column 1 from CSV
      customer_id      STRING,        -- column 2 from CSV
      order_date       DATE,          -- column 3 (Athena parses YYYY-MM-DD)
      amount           DOUBLE,        -- column 4 (decimal number)
      region           STRING,        -- column 5
      product_category STRING         -- column 6
    )
    ROW FORMAT DELIMITED
      FIELDS TERMINATED BY ','        -- CSV = comma-separated
      LINES TERMINATED BY '\\n'       -- one row per line
    LOCATION 's3://{BUCKET}/trading/orders/'   -- S3 folder with CSV files
    TBLPROPERTIES ('skip.header.line.count' = '1')  -- skip header row
    """
    run_query(ddl)
    print(f"✓ Table '{DATABASE}.{TABLE}' created")


# ─── FUNCTION 4: TEST QUERY ──────────────────────────────────────────
# Runs a simple SELECT to prove everything works:
#   - S3 has the CSV data
#   - Glue Catalog has the table metadata
#   - Athena can parse the CSV using the schema we defined
# If this returns data, your Athena setup is complete.
def test_query():
    """Run a test SELECT to verify data is accessible."""
    query_id = run_query(f"SELECT * FROM {DATABASE}.{TABLE} LIMIT 5")
    # Fetch the actual results using the query ID
    results = athena.get_query_results(QueryExecutionId=query_id)

    print("\n✓ Test query results:")
    for row in results['ResultSet']['Rows']:
        # Each row is a list of columns; extract the string value from each
        print("  " + " | ".join(col.get('VarCharValue', '') for col in row['Data']))


if __name__ == '__main__':
    create_database()
    create_orders_table()
    test_query()
    print("\n✓ Athena setup complete!")
```

#### Run it

```bash
python scripts/setup_athena.py
```

#### Expected output

```
✓ Database 'trading' created
  Query started: a1b2c3d4-e5f6-7890-abcd-ef1234567890
✓ Table 'trading.orders' created
  Query started: b2c3d4e5-f6a7-8901-bcde-f12345678901
  
✓ Test query results:
  order_id | customer_id | order_date | amount | region | product_category
  1001 | C-2341 | 2025-01-15 | 1250.0 | EMEA | Fixed Income
  1002 | C-1892 | 2025-01-16 | 3400.5 | APAC | Equities
  1003 | C-0045 | 2025-01-16 | 890.25 | EMEA | Derivatives
  1004 | C-2341 | 2025-01-17 | 5600.0 | AMER | Fixed Income
  1005 | C-1100 | 2025-01-18 | 2100.75 | EMEA | Equities

✓ Athena setup complete!
```

#### Common errors and fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `AccessDeniedException` | IAM user lacks Glue/Athena permissions | Add `AmazonAthenaFullAccess` and `AWSGlueConsoleFullAccess` policies to your user |
| `BucketAlreadyExists` (not OwnedByYou) | Someone else owns that bucket name | Change BUCKET to a unique name (e.g., add your account ID) |
| `Query failed: SYNTAX_ERROR` | Typo in CREATE TABLE SQL | Check column types match CSV data. DATE requires YYYY-MM-DD format. |
| `HIVE_CANNOT_OPEN_SPLIT` | S3 location doesn't have any files | Verify upload: `aws s3 ls s3://your-bucket/trading/orders/` |
| All rows show NULL | Header row counted as data OR wrong delimiter | Ensure `skip.header.line.count = '1'` is set |

> **Partitioned tables (production):**
> For large tables, add partitions by date or region:
> ```sql
> CREATE EXTERNAL TABLE trading.orders (
>   order_id STRING, customer_id STRING, amount DOUBLE, product_category STRING
> )
> PARTITIONED BY (order_date DATE, region STRING)
> ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
> LOCATION 's3://bucket/trading/orders/'
> TBLPROPERTIES ('skip.header.line.count'='1');
>
> -- Then load partitions:
> MSCK REPAIR TABLE trading.orders;
> ```
> S3 structure: `s3://bucket/trading/orders/order_date=2025-01-15/region=EMEA/file.csv`

## Lab 2 — Amazon Cognito

### 5. Create a Cognito User Pool

Cognito provides authentication and JWT token issuance. For a bank, you'll federate to your corporate IdP, but first let's create the User Pool itself.

#### AWS CLI: Create User Pool

```bash
# Create a Cognito User Pool — this is your user directory + auth server.
# It issues JWT tokens after authentication, which your API validates.
aws cognito-idp create-user-pool \
  --pool-name "athena-chatbot-users" \
  --policies '{
    "PasswordPolicy": {
      "MinimumLength": 12,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireNumbers": true,
      "RequireSymbols": true,
      "TemporaryPasswordValidityDays": 1
    }
  }' \
  --mfa-configuration "ON" \
  --auto-verified-attributes "email" \
  --schema '[
    {"Name": "department", "AttributeDataType": "String", "Mutable": true, "Required": false},
    {"Name": "data_tier", "AttributeDataType": "String", "Mutable": true, "Required": false}
  ]' \
  --account-recovery-setting '{
    "RecoveryMechanisms": [{"Priority": 1, "Name": "verified_email"}]
  }' \
  --region eu-west-2

# Note the UserPoolId from the response — you'll need it everywhere
```

#### Python (boto3): Create User Pool

```python
# scripts/setup_cognito.py
# Purpose: Provision a Cognito User Pool with MFA, custom attributes,
# and bank-grade password policy. Saves config to a JSON file for
# later use by the FastAPI app and other setup scripts.

import boto3  # AWS SDK for Python
import json   # To save config to a file

REGION = 'eu-west-2'  # AWS region — must match your other services

# Create a Cognito Identity Provider client
# 'cognito-idp' is the service name for User Pool operations
cognito = boto3.client('cognito-idp', region_name=REGION)

# Create the User Pool — this is your authentication server.
# After creation, it can issue JWTs, enforce MFA, and federate to IdPs.
response = cognito.create_user_pool(
    PoolName='athena-chatbot-users',  # Display name in AWS Console
    Policies={
        'PasswordPolicy': {         # Bank-grade password requirements
            'MinimumLength': 12,       # At least 12 characters
            'RequireUppercase': True,  # Must include A-Z
            'RequireLowercase': True,  # Must include a-z
            'RequireNumbers': True,    # Must include 0-9
            'RequireSymbols': True,    # Must include special chars
        }
    },
    MfaConfiguration='ON',             # MFA mandatory (not optional)
    AutoVerifiedAttributes=['email'],  # Auto-verify email via link
    Schema=[                            # Custom attributes for authorization
        {'Name': 'department', 'AttributeDataType': 'String', 'Mutable': True},
        {'Name': 'data_tier', 'AttributeDataType': 'String', 'Mutable': True},
    ],
    AccountRecoverySetting={            # How users recover locked accounts
        'RecoveryMechanisms': [{'Priority': 1, 'Name': 'verified_email'}]
    },
)

user_pool_id = response['UserPool']['Id']
print(f"✓ User Pool created: {user_pool_id}")

# Save for later use
config = {'user_pool_id': user_pool_id, 'region': REGION}
with open('cognito_config.json', 'w') as f:
    json.dump(config, f, indent=2)
    print("✓ Config saved to cognito_config.json")
```

### 6. Create App Client & Domain

The app client is how your FastAPI service authenticates with Cognito. The domain is needed for the hosted login UI and token endpoint.

#### AWS CLI

```bash
# Create App Client (no client secret for public clients; with secret for server-side)
aws cognito-idp create-user-pool-client \
  --user-pool-id <YOUR_POOL_ID> \
  --client-name "chatbot-api" \
  --generate-secret \
  --explicit-auth-flows "ALLOW_REFRESH_TOKEN_AUTH" "ALLOW_USER_SRP_AUTH" \
  --supported-identity-providers "COGNITO" \
  --callback-urls '["http://localhost:8000/auth/callback"]' \
  --logout-urls '["http://localhost:8000/auth/logout"]' \
  --allowed-o-auth-flows "code" \
  --allowed-o-auth-scopes "openid" "email" "profile" \
  --allowed-o-auth-flows-user-pool-client \
  --access-token-validity 15 \
  --id-token-validity 15 \
  --refresh-token-validity 480 \
  --token-validity-units '{
    "AccessToken": "minutes",
    "IdToken": "minutes",
    "RefreshToken": "minutes"
  }' \
  --region eu-west-2

# Create a domain for the hosted UI
aws cognito-idp create-user-pool-domain \
  --user-pool-id <YOUR_POOL_ID> \
  --domain "fi-chatbot-dev" \
  --region eu-west-2
```

#### Python (boto3)

```python
# Continue in scripts/setup_cognito.py
# An App Client is how your application (FastAPI) talks to Cognito.
# It defines: which auth flows are allowed, token lifetimes, OAuth scopes.

# Create App Client — this gives your FastAPI app credentials to talk to Cognito
client_response = cognito.create_user_pool_client(
    UserPoolId=user_pool_id,                    # Attach to the pool we just created
    ClientName='chatbot-api',                    # Human-readable name
    GenerateSecret=True,                        # Server-side app needs a secret (not public)
    ExplicitAuthFlows=[                          # Which auth methods are allowed:
        'ALLOW_REFRESH_TOKEN_AUTH',               #   - Refresh expired access tokens
        'ALLOW_USER_SRP_AUTH'                    #   - Secure Remote Password (no plaintext pw)
    ],
    SupportedIdentityProviders=['COGNITO'],    # Will add SAML IdP later
    CallbackURLs=['http://localhost:8000/auth/callback'],  # OAuth redirect after login
    LogoutURLs=['http://localhost:8000/auth/logout'],      # Redirect after logout
    AllowedOAuthFlows=['code'],                 # Authorization Code flow (most secure)
    AllowedOAuthScopes=['openid', 'email', 'profile'],  # What info the token contains
    AllowedOAuthFlowsUserPoolClient=True,      # Enable OAuth for this client
    AccessTokenValidity=15,                      # Access token expires in 15 minutes
    IdTokenValidity=15,                          # ID token expires in 15 minutes
    RefreshTokenValidity=480,                    # Refresh token expires in 8 hours (480 min)
    TokenValidityUnits={                         # Units for the validity values above
        'AccessToken': 'minutes',
        'IdToken': 'minutes',
        'RefreshToken': 'minutes',
    },
)

# Extract the client credentials from the response
client_id = client_response['UserPoolClient']['ClientId']          # Public identifier
client_secret = client_response['UserPoolClient']['ClientSecret']  # Keep secret!
print(f"✓ App Client created: {client_id}")

# Create domain
cognito.create_user_pool_domain(
    UserPoolId=user_pool_id,
    Domain='fi-chatbot-dev'
)
print("✓ Domain created: fi-chatbot-dev")

# Update config
config['client_id'] = client_id
config['client_secret'] = client_secret
config['domain'] = f'https://fi-chatbot-dev.auth.{REGION}.amazoncognito.com'
with open('cognito_config.json', 'w') as f:
    json.dump(config, f, indent=2)
```

### 7. Add SAML Federation (Corporate IdP)

For production at a bank, Cognito federates to your corporate identity provider (Okta, Entra ID, Ping). Here's how to set it up.

#### AWS CLI: Add SAML IdP

```bash
# You need the SAML metadata XML from your IdP (usually a URL)
# For Okta: Admin → Applications → Your App → Sign On → Metadata URL
# For Entra ID: Azure AD → Enterprise Apps → Your App → SAML → Metadata

# Create the identity provider
aws cognito-idp create-identity-provider \
  --user-pool-id <YOUR_POOL_ID> \
  --provider-name "CorporateIdP" \
  --provider-type "SAML" \
  --provider-details '{
    "MetadataURL": "https://your-idp.okta.com/app/xxxx/sso/saml/metadata"
  }' \
  --attribute-mapping '{
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "custom:department": "department",
    "custom:data_tier": "dataClassificationTier",
    "given_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    "family_name": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
  }' \
  --region eu-west-2

# Update app client to include the new IdP
aws cognito-idp update-user-pool-client \
  --user-pool-id <YOUR_POOL_ID> \
  --client-id <YOUR_CLIENT_ID> \
  --supported-identity-providers "CorporateIdP" "COGNITO" \
  --region eu-west-2
```

#### Python (boto3)

```python
# Add SAML Identity Provider to Cognito
# This tells Cognito: "trust this external IdP to authenticate users"
# After this, users can log in via their corporate SSO (Okta, Entra, etc.)
cognito.create_identity_provider(
    UserPoolId=user_pool_id,               # Which User Pool to add the IdP to
    ProviderName='CorporateIdP',            # Name you'll reference in app client config
    ProviderType='SAML',                    # Protocol type (SAML 2.0)
    ProviderDetails={                       # How Cognito finds the IdP's configuration:
        'MetadataURL': 'https://your-idp.okta.com/app/xxxx/sso/saml/metadata'
    },
    AttributeMapping={                      # Map IdP SAML attributes → Cognito attributes:
        'email': 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'custom:department': 'department',
        'custom:data_tier': 'dataClassificationTier',
    }
)
print("✓ SAML IdP 'CorporateIdP' added")
```

> **What your IdP needs from you:**
> Give your IdP administrator these values (from the Cognito User Pool):
> - **ACS URL:** `https://fi-chatbot-dev.auth.eu-west-2.amazoncognito.com/saml2/idpresponse`
> - **Entity ID:** `urn:amazon:cognito:sp:<YOUR_POOL_ID>`
> - **Attribute statements:** Map department, groups, data tier claims

### 8. Create a Test User (for local dev)

```bash
# AWS CLI: Create a user for testing (bypasses IdP for local dev)
aws cognito-idp admin-create-user \
  --user-pool-id <YOUR_POOL_ID> \
  --username "testuser@example.com" \
  --user-attributes '[
    {"Name": "email", "Value": "testuser@example.com"},
    {"Name": "email_verified", "Value": "true"},
    {"Name": "custom:department", "Value": "Finance"},
    {"Name": "custom:data_tier", "Value": "Confidential"}
  ]' \
  --temporary-password "TempP@ss123!" \
  --region eu-west-2

# Set permanent password (skip force-change flow for testing)
aws cognito-idp admin-set-user-password \
  --user-pool-id <YOUR_POOL_ID> \
  --username "testuser@example.com" \
  --password "Pr0duction$ecure!" \
  --permanent \
  --region eu-west-2
```

#### Python: Get a token (for testing your FastAPI app)

```python
# scripts/get_test_token.py
# Purpose: Obtain a JWT access token from Cognito for local API testing.
# This uses ADMIN_USER_PASSWORD_AUTH (direct username/password) which is
# fine for dev/test but NOT how production works (production uses SAML SSO).

import boto3  # AWS SDK
import json   # Load saved config

# Load the Cognito config we saved during setup (Pool ID, Client ID, etc.)
with open('cognito_config.json') as f:
    config = json.load(f)

# Create Cognito client using the region from our config
cognito = boto3.client('cognito-idp', region_name=config['region'])

# Authenticate the test user and get JWT tokens back
# admin_initiate_auth bypasses the hosted UI — only for testing!
response = cognito.admin_initiate_auth(
    UserPoolId=config['user_pool_id'],       # Which pool to authenticate against
    ClientId=config['client_id'],            # Which app client to use
    AuthFlow='ADMIN_USER_PASSWORD_AUTH',      # Direct password auth (admin-only flow)
    AuthParameters={                          # Credentials:
        'USERNAME': 'testuser@example.com',   # The test user we created earlier
        'PASSWORD': 'Pr0duction$ecure!',     # The password we set
    }
)

# Extract tokens from the response
# AccessToken: used for API authorization (what FastAPI validates)
# IdToken: contains user identity claims (email, groups, etc.)
access_token = response['AuthenticationResult']['AccessToken']  # Use this for API calls
id_token = response['AuthenticationResult']['IdToken']          # Contains user info

# Print the token so you can copy it into curl/httpx for testing
print(f"Access Token (first 50 chars): {access_token[:50]}...")
print(f"\nUse this header for FastAPI testing:")
print(f'  Authorization: Bearer {access_token}')
```

## Lab 3 — Cedar Policies (AgentCore Policy)

### 9. What Cedar Is and Where It Lives

Cedar is a policy language for authorization. In this architecture, Cedar policies are attached to the **AgentCore Gateway** via a **Policy Engine**. They control which users can call which tools.

#### The architecture of Policy

```
How Cedar fits in:

Your Code (policies/*.cedar)   ← You write these
        │
        ▼
AgentCore Policy Engine        ← AWS hosts this; stores your Cedar policies
        │
        ▼
AgentCore Gateway              ← Engine is attached here; evaluates every tool call
        │
        ▼
Your MCP Tools (Athena)        ← Only reached if Cedar says ALLOW
```

#### Where policies live

| Location | Purpose | Who manages |
|----------|---------|-------------|
| `policies/*.cedar` (your repo) | Source of truth — version controlled, peer reviewed | Your team |
| AgentCore Policy Engine (AWS) | Runtime evaluation — Gateway queries this | Deployed via CI/CD or boto3 script |

> **Key principle:** Cedar files in your repo are the **source of truth**. You deploy them to the Policy Engine via API. The Engine evaluates them at runtime. You never edit policies directly in AWS — always go through your repo + review process.

### 10. Writing Cedar Policies

Cedar policies follow a simple structure: `permit` or `forbid`, targeting a principal/action/resource combination.

#### File: policies/chatbot.cedar

```
// ============================================================
// Athena Chatbot — Cedar Authorization Policies
// Author: Platform Security Team
// Date: 2026-07-18
// Review: Required before deployment (PR #xxx)
// ============================================================

// ---- DEFAULT DENY ----
// Cedar is default-deny: if no permit matches, the request is denied.
// We don't need to write an explicit "deny all" — it's built in.

// ---- GLOBAL FORBIDS (cannot be overridden by any permit) ----

// Nobody can ever query the HR PII database via this agent
forbid (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"hr_pii"
);

// Nobody can ever query the compliance-restricted database
forbid (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"compliance_restricted"
);

// ---- READ-ONLY DISCOVERY (all authenticated users) ----

// Anyone can list tables and get schemas (read-only metadata)
permit (
  principal,
  action == Athena::Action::"list_tables",
  resource
);

permit (
  principal,
  action == Athena::Action::"get_schema",
  resource
);

permit (
  principal,
  action == Athena::Action::"estimate_cost",
  resource
);

// ---- PER-GROUP QUERY PERMISSIONS ----

// Finance Analysts can query sales and finance databases
permit (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"sales"
) when {
  principal.groups.contains("Finance-Analysts")
};

permit (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"finance"
) when {
  principal.groups.contains("Finance-Analysts")
};

// Marketing team can query marketing and campaigns databases
permit (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"marketing"
) when {
  principal.groups.contains("Marketing-Team")
};

permit (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"campaigns"
) when {
  principal.groups.contains("Marketing-Team")
};

// Trading desk can query the trading database
permit (
  principal,
  action == Athena::Action::"run_query",
  resource == Athena::Database::"trading"
) when {
  principal.groups.contains("Trading-Desk")
};
```

> **Security review required:** Never deploy Cedar policies without human review. Natural-language authoring (AgentCore feature) can generate initial policies, but the generated Cedar must be inspected by a security engineer before it reaches production.

### 11. Deploy Cedar Policies via Python/CLI

Deploying Cedar policies involves: (1) creating a Policy Engine, (2) adding policies to it, and (3) attaching it to your Gateway.

#### Python (boto3): Full deployment script

```python
# scripts/setup_cedar.py — Deploy Cedar policies to AgentCore
# Purpose: Read Cedar policy files from your repo and deploy them to AWS.
# This creates: (1) a Policy Engine, (2) policies inside it, (3) attaches to Gateway.
# After this runs, every tool call through the Gateway is authorized by Cedar.

import boto3              # AWS SDK
from pathlib import Path  # File path handling

REGION = 'eu-west-2'  # Must match your Gateway's region

# Create client for the AgentCore Control Plane API
# This is the management API for Policy Engines, Gateways, etc.
client = boto3.client('bedrock-agentcore-control', region_name=REGION)

# ─── STEP 1: Create a Policy Engine ─────────────────────────────────
# A Policy Engine is a container that holds Cedar policies.
# You attach it to a Gateway, and it evaluates every tool call.
print("Creating Policy Engine...")
engine_response = client.create_policy_engine(
    name='chatbot-authorization',
    description='Cedar policies for the Athena chatbot agent'
)
engine_id = engine_response['policyEngineId']
print(f"✓ Policy Engine created: {engine_id}")

# ─── STEP 2: Read Cedar policies from your local repository ─────────
# The .cedar file in your repo is the source of truth.
# It was peer-reviewed in a PR before being merged.
cedar_file = Path('policies/chatbot.cedar')
cedar_content = cedar_file.read_text()
print(f"  Read {len(cedar_content)} characters from {cedar_file}")

# ─── STEP 3: Upload the Cedar policy to the Engine ──────────────────
# This takes the Cedar text and stores it in the Policy Engine.
# The Engine will evaluate this policy on every tool call through the Gateway.
policy_response = client.create_policy(
    policyEngineId=engine_id,
    name='chatbot-main-policy',
    description='Main authorization policy for Athena chatbot',
    definition={
        'cedar': {
            'statement': cedar_content
        }
    }
)
policy_id = policy_response['policyId']
print(f"✓ Policy created: {policy_id}")

# ─── STEP 4: Attach the Policy Engine to your Gateway ────────────────
# This is the moment authorization goes live.
# After this call, EVERY tool call through this Gateway will be evaluated
# by the Cedar policies. If no permit matches → DENIED (default-deny).
GATEWAY_ID = 'your-gateway-id'  # Replace with your actual Gateway ID

client.update_gateway(
    gatewayId=GATEWAY_ID,
    policyEngineId=engine_id
)
print(f"✓ Policy Engine attached to Gateway: {GATEWAY_ID}")
print("\n✓ Cedar deployment complete!")
print("  Default-deny is now active.")
print("  All tool calls must match an explicit permit.")
```

#### AWS CLI equivalent

```bash
# Create Policy Engine
aws bedrock-agentcore-control create-policy-engine \
  --name "chatbot-authorization" \
  --description "Cedar policies for Athena chatbot" \
  --region eu-west-2

# Create a policy (using the Cedar file content)
aws bedrock-agentcore-control create-policy \
  --policy-engine-id <ENGINE_ID> \
  --name "chatbot-main-policy" \
  --definition '{
    "cedar": {
      "statement": "forbid(principal, action == Athena::Action::\"run_query\", resource == Athena::Database::\"hr_pii\"); permit(principal, action == Athena::Action::\"list_tables\", resource);"
    }
  }' \
  --region eu-west-2

# Or generate policies from natural language (still requires human review!)
aws bedrock-agentcore-control start-policy-generation \
  --policy-engine-id <ENGINE_ID> \
  --description "Finance Analysts can query the sales database, nobody can query hr_pii" \
  --region eu-west-2
```

### 12. Policy Workflow: Where Everything Goes

#### Development workflow

```
1. Write Cedar in your repo:          policies/chatbot.cedar
2. Validate locally:                   cedar validate --policies ./policies/
3. Peer review:                        Pull request → security engineer reviews
4. CI validates:                       cedar validate runs in CI pipeline
5. Deploy to AWS:                     python scripts/setup_cedar.py (or CI/CD)
6. Gateway evaluates at runtime:      Every tool call hits the Policy Engine
```

#### Local validation (install Cedar CLI)

```bash
# Install Cedar CLI (Rust-based)
cargo install cedar-policy-cli

# Or download pre-built binary from GitHub releases
# https://github.com/cedar-policy/cedar/releases

# Validate your policies
cedar validate --policies ./policies/ --schema ./policies/schema.cedarschema

# Test a specific authorization request
cedar authorize \
  --policies ./policies/ \
  --entities ./policies/test-entities.json \
  --principal 'User::"jsmith"' \
  --action 'Athena::Action::"run_query"' \
  --resource 'Athena::Database::"sales"'
```

> **File organization:**
> ```
> policies/
> ├── chatbot.cedar              # Main policy file
> ├── schema.cedarschema         # Entity/action type definitions
> ├── test-entities.json         # Test data for local validation
> └── README.md                  # Policy documentation + change log
> ```

## Lab 4 — FastAPI Application

### 13. Scaffold the FastAPI App

FastAPI is the thin API layer between the chat UI and AgentCore Runtime. It validates JWTs, rate-limits, and delegates to the agent. It does NOT implement orchestration logic.

#### File: api/config.py

```python
# api/config.py — Application settings from environment variables
# Uses pydantic-settings to automatically load values from a .env file.
# This keeps secrets out of code — never hardcode Pool IDs or keys.

from pydantic_settings import BaseSettings  # Auto-loads from .env file


class Settings(BaseSettings):
    # ─── Cognito settings (needed for JWT validation) ───
    cognito_user_pool_id: str              # e.g. "eu-west-2_ABcDeFgHi"
    cognito_region: str = "eu-west-2"      # Region where Cognito pool lives
    cognito_app_client_id: str             # App client ID (audience check)

    # ─── AgentCore settings (for production — calls to Runtime) ───
    agentcore_runtime_id: str = ""         # Empty in dev (uses mock)
    agentcore_region: str = "eu-west-2"    # Region where Runtime is deployed

    # ─── Application settings ───
    environment: str = "development"        # "development" or "production"
    rate_limit_per_minute: int = 30        # Max requests per user per minute

    class Config:
        env_file = ".env"  # Load settings from .env file in project root


settings = Settings()
```

#### File: api/auth.py

```python
# api/auth.py — JWT validation against Cognito
# This module validates that incoming requests have a valid JWT token
# issued by our Cognito User Pool. It checks:
#   1. Token signature (was it signed by Cognito's private key?)
#   2. Token expiry (has the 15-minute lifetime passed?)
#   3. Audience (is this token meant for our app client?)
#   4. Issuer (did it come from our specific User Pool?)

import httpx                             # HTTP client to fetch Cognito's public keys
from jose import jwt, JWTError            # JWT decoding and verification library
from fastapi import HTTPException, Security  # Error responses + dependency injection
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # Extract Bearer token
from functools import lru_cache            # Cache the JWKS so we don't fetch every request
from api.config import settings            # Our Cognito Pool ID, region, client ID

# HTTPBearer extracts the token from "Authorization: Bearer <token>" header
security = HTTPBearer()


@lru_cache(maxsize=1)  # Cache result — JWKS changes rarely (key rotation)
def get_jwks() -> dict:
    """Fetch Cognito's public keys (JWKS) for verifying token signatures.
    
    Cognito publishes its public keys at a well-known URL.
    We fetch them once and cache — they only change on key rotation.
    """
    url = (
        f"https://cognito-idp.{settings.cognito_region}.amazonaws.com/"
        f"{settings.cognito_user_pool_id}/.well-known/jwks.json"
    )
    response = httpx.get(url, timeout=10)  # Fetch public keys from Cognito
    response.raise_for_status()              # Raise if HTTP error
    return response.json()                   # Returns {keys: [{kid, n, e, ...}, ...]}


def find_key(token: str) -> dict:
    """Find the specific signing key that matches this token's 'kid' header.
    
    JWTs have a 'kid' (key ID) in their header telling you which key signed them.
    We look it up in the JWKS to get the public key for verification.
    """
    headers = jwt.get_unverified_headers(token)
    kid = headers.get("kid")
    jwks = get_jwks()
    for key in jwks["keys"]:
        if key["kid"] == kid:
            return key
    raise HTTPException(status_code=401, detail="Token signing key not found")


def validate_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> dict:
    """Validate JWT and return decoded claims.

    Checks: signature, expiry, audience, issuer.
    Returns: dict with sub, email, groups, department, data_tier.
    """
    token = credentials.credentials
    key = find_key(token)

    issuer = (
        f"https://cognito-idp.{settings.cognito_region}.amazonaws.com/"
        f"{settings.cognito_user_pool_id}"
    )

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.cognito_app_client_id,
            issuer=issuer,
            options={"verify_exp": True},
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    return {
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "groups": payload.get("cognito:groups", []),
        "department": payload.get("custom:department", ""),
        "data_tier": payload.get("custom:data_tier", ""),
    }
```

#### File: api/main.py

```python
# api/main.py — FastAPI application
# This is the thin API layer between the chat UI and AgentCore Runtime.
# It handles: JWT validation, rate limiting, and request forwarding.
# It does NOT: generate SQL, call Athena, or implement AI logic.

from fastapi import FastAPI, Depends, HTTPException  # Web framework
from pydantic import BaseModel       # Request/response validation
from api.auth import validate_token   # Our JWT validation function
from api.config import settings       # Environment settings (.env)
import boto3                          # AWS SDK (for AgentCore calls in prod)
import time                           # For rate limiting timestamps
from collections import defaultdict   # Simple dict with default values

# ─── APP CONFIGURATION ───────────────────────────────────────────────
# In production (ENVIRONMENT=production), /docs and /redoc are disabled
# to prevent API documentation from being publicly accessible.
docs_url = "/docs" if settings.environment == "development" else None
redoc_url = "/redoc" if settings.environment == "development" else None

app = FastAPI(
    title="Athena Chatbot API",
    version="1.0.0",
    docs_url=docs_url,
    redoc_url=redoc_url,
)

# Simple in-memory rate limiter (use Redis in production)
rate_limit_store: dict = defaultdict(list)


def check_rate_limit(user: dict = Depends(validate_token)):
    """Rate limit: max N requests per minute per user."""
    user_id = user["sub"]
    now = time.time()
    window = 60  # 1 minute

    # Clean old entries
    rate_limit_store[user_id] = [
        t for t in rate_limit_store[user_id] if now - t < window
    ]

    if len(rate_limit_store[user_id]) >= settings.rate_limit_per_minute:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    rate_limit_store[user_id].append(now)
    return user


# --- Request/Response models ---

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None


class ChatResponse(BaseModel):
    response: str
    session_id: str
    sql_generated: str | None = None


# --- Endpoints ---

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/chat", response_model=ChatResponse)
def chat(
    request: ChatRequest,
    user: dict = Depends(check_rate_limit),
):
    """Send a question to the Athena chatbot agent.

    The agent runs on AgentCore Runtime. This endpoint:
    1. Validates the JWT (done by dependency)
    2. Rate-limits the user (done by dependency)
    3. Forwards the request to AgentCore Runtime
    4. Returns the agent's response
    """
    # In production, this calls AgentCore Runtime:
    # agentcore = boto3.client('bedrock-agentcore', region_name=settings.agentcore_region)
    # response = agentcore.invoke_agent(
    #     runtimeId=settings.agentcore_runtime_id,
    #     sessionId=request.session_id or str(uuid4()),
    #     input={'message': request.message},
    #     headers={'X-Amzn-Bedrock-AgentCore-Runtime-User-Id': user['sub']}
    # )

    # For local development, return a mock response:
    return ChatResponse(
        response=f"[Mock] User {user['email']} asked: {request.message}",
        session_id=request.session_id or "dev-session-001",
        sql_generated=None,
    )


@app.get("/me")
def get_current_user(user: dict = Depends(validate_token)):
    """Return the authenticated user's claims (for debugging)."""
    return user
```

### 14. Configure JWT Validation

Create a `.env` file for local development with your Cognito configuration:

#### File: .env

```
# .env — Local development settings (DO NOT commit to git)
COGNITO_USER_POOL_ID=eu-west-2_XXXXXXXXX
COGNITO_REGION=eu-west-2
COGNITO_APP_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AGENTCORE_RUNTIME_ID=
AGENTCORE_REGION=eu-west-2
ENVIRONMENT=development
RATE_LIMIT_PER_MINUTE=30
```

#### File: .gitignore (add these)

```
# Never commit secrets
.env
cognito_config.json
*.pem
*.key
```

> **How JWT validation works:**
> 1. User authenticates via Cognito (hosted UI or SAML redirect)
> 2. Cognito returns a signed JWT (access token)
> 3. Frontend sends `Authorization: Bearer <token>` with each request
> 4. FastAPI fetches Cognito's public keys (JWKS) and verifies the signature
> 5. Checks: signature valid, not expired, correct audience (client ID), correct issuer (pool ID)
> 6. Extracts claims: user ID, email, groups, department, data tier

### 15. Run FastAPI Locally

#### Start the development server

```bash
# From your project root:
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# You should see:
# INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
# INFO:     Started reloader process
```

#### Verify it's running

```bash
# Health check (no auth needed)
curl http://localhost:8000/health
# {"status": "healthy"}

# Try without token (should get 403)
curl http://localhost:8000/me
# {"detail": "Not authenticated"}

# Open docs (only in development)
# Browse to: http://localhost:8000/docs
```

#### Test with a real Cognito token

```bash
# First, get a token using the script from Lab 2:
python scripts/get_test_token.py

# Then use it:
curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  http://localhost:8000/me

# Should return your user claims:
# {"sub": "xxx", "email": "testuser@example.com",
#  "groups": ["Finance-Analysts"], "department": "Finance",
#  "data_tier": "Confidential"}
```

#### Test the chat endpoint

```bash
# Send a chat message
curl -X POST http://localhost:8000/chat \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"message": "How many orders were placed last month?"}'

# Response (mock in dev):
# {"response": "[Mock] User testuser@example.com asked: How many orders...",
#  "session_id": "dev-session-001", "sql_generated": null}
```

#### Python test script (alternative to curl)

```python
# scripts/test_api.py — Test the FastAPI app programmatically
import httpx
import json

# Load token from the get_test_token script
# (In practice, run get_test_token.py first and copy the token)
TOKEN = "your-access-token-here"

BASE_URL = "http://localhost:8000"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Test health
r = httpx.get(f"{BASE_URL}/health")
print(f"Health: {r.json()}")

# Test auth
r = httpx.get(f"{BASE_URL}/me", headers=headers)
print(f"User: {json.dumps(r.json(), indent=2)}")

# Test chat
r = httpx.post(
    f"{BASE_URL}/chat",
    headers=headers,
    json={"message": "Show me total orders by region for Q1 2025"}
)
print(f"Chat: {json.dumps(r.json(), indent=2)}")

# Test rate limiting (send 31 requests quickly)
print("\nTesting rate limit...")
for i in range(32):
    r = httpx.post(
        f"{BASE_URL}/chat",
        headers=headers,
        json={"message": f"Query {i}"}
    )
    if r.status_code == 429:
        print(f"  Rate limited at request {i+1}: {r.json()}")
        break
```

### 16. End-to-End Local Test

Here's the complete local development flow from start to finish:

```bash
# Terminal 1: Start FastAPI
uvicorn api.main:app --reload --port 8000

# Terminal 2: Run the full test sequence

# 1. Verify Athena tables exist
python scripts/setup_athena.py

# 2. Get a Cognito token
python scripts/get_test_token.py

# 3. Test the API
python scripts/test_api.py
```

#### What happens in production (vs. local dev)

| Step | Local Dev | Production |
|------|-----------|------------|
| Authentication | `admin_initiate_auth` with username/password | SAML redirect to corporate IdP → Cognito → JWT |
| Chat endpoint | Returns mock response | Invokes AgentCore Runtime → LangGraph agent runs |
| Tool calls | None (mocked) | Agent → Gateway → Policy (Cedar) → Identity (OBO) → MCP server → Athena |
| Authorization | JWT validated only | JWT + Cedar Policy + Lake Formation (three layers) |
| Rate limiting | In-memory dict | Redis or API Gateway throttling |
| Docs endpoint | Available at /docs | Disabled (ENVIRONMENT=production) |

> **Next steps after local development:**
> 1. **Deploy FastAPI to ECS Fargate** behind a private ALB (no public access)
> 2. **Provision AgentCore Runtime** and deploy the LangGraph agent
> 3. **Wire the /chat endpoint** to invoke AgentCore Runtime instead of returning mock responses
> 4. **Register MCP tools on Gateway** and attach your Cedar policies
> 5. **Enable Lake Formation** and configure OBO token exchange
>
> Each of these steps is a task in `tasks.md` — Kiro can implement them one by one via `#spec:athena-chatbot implement task N`.

## Summary

### What You've Built

| Lab | What you set up | Files created |
|-----|----------------|---------------|
| Lab 1 | S3 bucket with CSV data, Glue database, Athena tables | `scripts/setup_athena.py` |
| Lab 2 | Cognito User Pool with MFA, app client, SAML federation, test user | `scripts/setup_cognito.py` |
| Lab 3 | Cedar policies (forbids + per-group permits), deployed to Policy Engine | `policies/chatbot.cedar`, `scripts/setup_cedar.py` |
| Lab 4 | FastAPI app with JWT validation, rate limiting, chat endpoint | `api/main.py`, `api/auth.py`, `api/config.py` |

### Complete setup script (run all labs)

```bash
# Run everything in sequence
pip install -r requirements.txt

# Lab 1: Athena
python scripts/upload_csv.py
python scripts/setup_athena.py

# Lab 2: Cognito
python scripts/setup_cognito.py

# Lab 3: Cedar (requires Gateway to be provisioned first)
# python scripts/setup_cedar.py

# Lab 4: FastAPI
uvicorn api.main:app --reload --port 8000
```

### AWS CLI quick-reference

| Service | Key commands |
|---------|-------------|
| S3 | `aws s3 mb`, `aws s3 cp`, `aws s3 ls` |
| Glue | `aws glue create-database`, `aws glue get-tables` |
| Athena | `aws athena start-query-execution`, `aws athena get-query-results` |
| Cognito | `aws cognito-idp create-user-pool`, `aws cognito-idp create-user-pool-client` |
| AgentCore | `aws bedrock-agentcore-control create-policy-engine`, `aws bedrock-agentcore-control create-policy` |

> **How this connects to the main course:** This hands-on guide covers the **foundational AWS setup** (Waves 1-2 in `tasks.md`). The main course (`kiro-course.md`) covers the full architecture, the agent build (Wave 3+), security design, and governance. Use both together: this guide to get services running, the main course to understand why they're configured the way they are.
