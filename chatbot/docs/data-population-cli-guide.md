# Data Population CLI Guide

How to populate the Athena Chatbot data layer using the AWS CLI. Covers uploading CSV data to S3, creating Athena tables via the Glue Catalog, provisioning Cognito users and groups, and manually verifying queries.

## Table of Contents

- [Prerequisites](#prerequisites)
- [1. Create Athena Tables from CSV Files](#1-create-athena-tables-from-csv-files)
  - [1.1 Upload CSV to S3](#11-upload-csv-to-s3)
  - [1.2 Create a Glue Database](#12-create-a-glue-database)
  - [1.3 Create Table (via Athena DDL)](#13-create-table-via-athena-ddl)
  - [1.4 Notes on CREATE TABLE DDL](#14-notes-on-create-table-ddl)
  - [1.5 Verify the Table Exists](#15-verify-the-table-exists)
- [2. Create Users and Groups in Cognito](#2-create-users-and-groups-in-cognito)
  - [2.1 Identify Your User Pool ID](#21-identify-your-user-pool-id)
  - [2.2 Create Groups](#22-create-groups)
  - [2.3 Create a User](#23-create-a-user)
  - [2.4 Add User to a Group](#24-add-user-to-a-group)
  - [2.5 Verify User and Group Membership](#25-verify-user-and-group-membership)
  - [2.6 Example: Create Multiple Users (Batch)](#26-example-create-multiple-users-batch)
- [3. Manually Verify Athena Queries](#3-manually-verify-athena-queries)
  - [3.1 Using the AWS Console (Athena Query Editor)](#31-using-the-aws-console-athena-query-editor)
  - [3.2 Using the AWS CLI](#32-using-the-aws-cli)
  - [3.3 Example Verification Queries](#33-example-verification-queries)
  - [3.4 Common Errors and Fixes](#34-common-errors-and-fixes)
  - [3.5 Checking Query Results in S3](#35-checking-query-results-in-s3)
- [4. Clean Up Resources](#4-clean-up-resources)
- [Quick Reference](#quick-reference)
- [Further Reading](#further-reading)

---

## Prerequisites

| Tool | Install | Verify |
|------|---------|--------|
| AWS CLI v2 | `msiexec /i https://awscli.amazonaws.com/AWSCLIV2.msi` ([Install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)) | `aws --version` |
| Configured credentials | `aws configure` (Access Key, Secret Key, region `eu-west-2`) ([Configuration guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html)) | `aws sts get-caller-identity` |
| S3 bucket for data | Created manually or via CDK | `aws s3 ls` |

### Required IAM Permissions

Your IAM user or role needs these AWS managed policies (or equivalent custom policies):

| Service | Managed Policy | What it allows |
|---------|---------------|----------------|
| S3 | `AmazonS3FullAccess` | Create buckets, upload/list/download objects |
| Glue | `AWSGlueConsoleFullAccess` | Create/read databases and tables in the Data Catalog |
| Athena | `AmazonAthenaFullAccess` | Submit queries, read results, manage workgroups |
| Cognito | `AmazonCognitoPowerUser` | Create/manage user pools, users, and groups |

> **Least privilege:** In production, create custom policies scoped to specific resources. The managed policies above are broad and suitable only for development/testing. See [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

### Sample CSV Data

This guide uses the following sample CSV. Save it as `data/orders.csv`:

```csv
order_id,customer_id,order_date,amount,region,product_category
1001,C-2341,2025-01-15,1250.00,EMEA,Fixed Income
1002,C-1892,2025-01-16,3400.50,APAC,Equities
1003,C-0045,2025-01-16,890.25,EMEA,Derivatives
1004,C-2341,2025-01-17,5600.00,AMER,Fixed Income
1005,C-1100,2025-01-18,2100.75,EMEA,Equities
```

---

## 1. Create Athena Tables from CSV Files

Athena reads data directly from S3 — you do not load data *into* Athena. Instead, you:
1. Upload CSV files to S3
2. Create a Glue database (metadata container)
3. Create an external table pointing to the S3 location

> **How it works:** Athena is a serverless query engine that reads data in-place from S3. The Glue Data Catalog stores table metadata (column names, types, S3 location, file format). When you query a table, Athena uses the catalog metadata to parse files directly from S3. See [Amazon Athena concepts](https://docs.aws.amazon.com/athena/latest/ug/what-is.html) and [AWS Glue Data Catalog](https://docs.aws.amazon.com/glue/latest/dg/catalog-and-crawler.html).

### 1.1 Upload CSV to S3

```bash
# Create a bucket (use a unique name — e.g. include your account ID)
aws s3 mb s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2 --region eu-west-2

# Upload a single CSV file
aws s3 cp data/orders.csv s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/

# Upload an entire folder of CSVs
aws s3 sync data/ s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/ ^
  --exclude "*" --include "*.csv"

# Verify the upload
aws s3 ls s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/
```

> **S3 path convention:** `s3://bucket-name/database-name/table-name/`. Athena reads all files under the LOCATION path — organize one folder per table. See [S3 CLI reference](https://docs.aws.amazon.com/cli/latest/reference/s3/index.html).

#### Command-by-command explanation

**`aws s3 mb s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2 --region eu-west-2`**

| Input | What it is |
|-------|-----------|
| `aws s3 mb` | "make bucket" — creates a new S3 bucket. |
| `s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2` | The bucket name. S3 bucket names are globally unique across all AWS accounts, so you include your account ID (e.g. `123456789012`) and region to avoid collisions. Replace `<ACCOUNT_ID>` with your actual 12-digit AWS account number. |
| `--region eu-west-2` | The AWS region where the bucket is physically created. Must match the region your Athena workgroup and Glue Catalog are in. |

**`aws s3 cp data/orders.csv s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/`**

| Input | What it is |
|-------|-----------|
| `aws s3 cp` | Copy a file (local → S3, S3 → local, or S3 → S3). |
| `data/orders.csv` | **Source** — the local file path on your machine, relative to where you run the command. This is your CSV file. |
| `s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/` | **Destination** — the S3 path. The structure is deliberate: `trading` is the Glue database name, `orders` is the table name. Athena's `LOCATION` will point to this folder and read every file inside it. The trailing `/` means "put the file inside this folder." |

**`aws s3 sync data/ s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/ ^ --exclude "*" --include "*.csv"`**

| Input | What it is |
|-------|-----------|
| `aws s3 sync` | Syncs a local directory to S3. Only uploads files that are new or changed (like rsync). |
| `data/` | **Source directory** — the local folder containing your files. |
| `s3://.../trading/orders/` | **Destination folder** in S3 (same as above). |
| `^` | Windows CMD line continuation character (lets you split a long command across multiple lines). On Linux/Mac this would be `\`. |
| `--exclude "*"` | Start by excluding everything. This filter says "by default, skip all files." |
| `--include "*.csv"` | Then re-include only files matching `*.csv`. Combined with the exclude, this means: "sync only `.csv` files and ignore everything else (e.g. `.gitignore`, `.DS_Store`, READMEs)." Filters are evaluated in order. |

**`aws s3 ls s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/`**

| Input | What it is |
|-------|-----------|
| `aws s3 ls` | List objects in an S3 path (like `dir` or `ls`). |
| `s3://.../trading/orders/` | The S3 "folder" to list. Shows all files uploaded there — use this to confirm your CSVs arrived. Output looks like: `2025-01-15 10:32:00  1234 orders.csv` |

#### Why the path structure matters

```
s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/
     └── bucket name                          └── db  └── table
```

When you later run `CREATE EXTERNAL TABLE trading.orders ... LOCATION 's3://bucket/trading/orders/'`, Athena reads **all files** in that folder as rows of the table. Each table must have its own subfolder — if you mix CSVs from different tables in the same folder, Athena will try to parse them all with the same schema and produce errors or garbage data.

### 1.2 Create a Glue Database

```bash
aws glue create-database ^
  --database-input "{\"Name\": \"trading\", \"Description\": \"Trading data lake\"}" ^
  --region eu-west-2

# Verify
aws glue get-database --name trading --region eu-west-2
```

#### Command-by-command explanation

**`aws glue create-database --database-input "{\"Name\": \"trading\", \"Description\": \"Trading data lake\"}" --region eu-west-2`**

| Input | What it is |
|-------|-----------|
| `aws glue create-database` | Creates a new database in the AWS Glue Data Catalog. This is a metadata-only operation — it does not create storage or move data. Think of it like `CREATE SCHEMA` in PostgreSQL. See [create-database CLI reference](https://docs.aws.amazon.com/cli/latest/reference/glue/create-database.html). |
| `--database-input` | A JSON object describing the database to create. Must include at minimum a `Name` field. |
| `"Name": "trading"` | The database name. This is what you reference in Athena queries (e.g. `SELECT * FROM trading.orders`). Choose a name that represents the data domain. |
| `"Description": "Trading data lake"` | Optional human-readable description. Appears in the Glue Console and helps others understand what this database contains. |
| `\"...\"`| The backslash-escaped quotes (`\"`) are required because the JSON is embedded inside a CMD string. On PowerShell you would use single quotes around the JSON instead. |
| `^` | Windows CMD line continuation character. |
| `--region eu-west-2` | The AWS region where the Glue Catalog lives. Must match where your Athena workgroup and S3 bucket are. |

**`aws glue get-database --name trading --region eu-west-2`**

| Input | What it is |
|-------|-----------|
| `aws glue get-database` | Retrieves metadata about an existing Glue database. Use this to confirm the database was created successfully. |
| `--name trading` | The name of the database to look up (the same name you used in `create-database`). |
| `--region eu-west-2` | The region to query. |

The response includes the database name, description, creation time, and the catalog ID (your AWS account number). If you get a `EntityNotFoundException`, the database wasn't created — check your region and permissions.

**Expected output (success):**
```json
{
    "Database": {
        "Name": "trading",
        "Description": "Trading data lake",
        "CreateTime": "2025-01-15T10:30:00+00:00",
        "CatalogId": "123456789012"
    }
}
```

### 1.3 Create Table (via Athena DDL)

Use `aws athena start-query-execution` to run the CREATE TABLE statement. You need a results location (any S3 path where Athena can write output metadata).

```bash
aws athena start-query-execution ^
  --query-string "CREATE EXTERNAL TABLE IF NOT EXISTS trading.orders (order_id STRING, customer_id STRING, order_date DATE, amount DOUBLE, region STRING, product_category STRING) ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' LOCATION 's3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/' TBLPROPERTIES ('skip.header.line.count'='1')" ^
  --work-group "primary" ^
  --result-configuration "OutputLocation=s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/" ^
  --region eu-west-2
```

This returns a `QueryExecutionId`. Check it completed successfully:

```bash
aws athena get-query-execution ^
  --query-execution-id <QUERY_EXECUTION_ID> ^
  --region eu-west-2
```

Look for `"State": "SUCCEEDED"` in the response.

#### Command-by-command explanation

**`aws athena start-query-execution`**

This submits a SQL statement to Athena for execution. Athena queries are **asynchronous** — the command returns immediately with an execution ID, and the query runs in the background.

| Input | What it is |
|-------|-----------|
| `aws athena start-query-execution` | Submits any SQL statement (DDL or DML) to the Athena engine. Returns a `QueryExecutionId` you use to check status and fetch results. See [start-query-execution CLI reference](https://docs.aws.amazon.com/cli/latest/reference/athena/start-query-execution.html). |
| `--query-string "..."` | The SQL statement to execute. In this case it's a `CREATE EXTERNAL TABLE` DDL. The entire SQL is passed as a single string. |
| `CREATE EXTERNAL TABLE` | Tells Athena to register a table whose data lives externally (in S3). This does **not** copy or move data — it only creates metadata in the Glue Catalog describing how to read the files. |
| `IF NOT EXISTS` | Skip creation if a table with this name already exists. Prevents errors on re-runs. |
| `trading.orders` | `trading` is the Glue database name, `orders` is the table name. Dot notation: `database.table`. |
| `(order_id STRING, customer_id STRING, order_date DATE, amount DOUBLE, region STRING, product_category STRING)` | Column definitions. Each column has a name and a data type. These must match the columns in your CSV (in order). Common types: `STRING` (text), `DATE` (YYYY-MM-DD), `DOUBLE` (decimal number), `INT`/`BIGINT` (integers). |
| `ROW FORMAT DELIMITED` | Tells Athena the file uses delimited text format (as opposed to Parquet, ORC, JSON, etc.). Uses the [LazySimpleSerDe](https://docs.aws.amazon.com/athena/latest/ug/lazy-simple-serde.html) internally. |
| `FIELDS TERMINATED BY ','` | The column separator is a comma. For TSV files this would be `'\t'`. |
| `LOCATION 's3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/'` | The S3 **folder** containing data files for this table. Athena reads all files in this path (and subfolders) as rows. Points to a folder, not a specific file. Trailing `/` is required. |
| `TBLPROPERTIES ('skip.header.line.count'='1')` | Table properties. `skip.header.line.count = 1` tells Athena to skip the first line of each CSV file (the header row with column names) so it's not treated as data. |
| `--work-group "primary"` | The Athena workgroup to run the query in. Workgroups control cost limits, query result locations, and access. `primary` is the default workgroup. In production, use `chatbot-readonly`. |
| `--result-configuration "OutputLocation=s3://...query-results/"` | Where Athena writes query execution metadata (a small CSV + metadata file). Required for every query. For DDL statements like CREATE TABLE, the result file is essentially empty but must still have a location. |
| `--region eu-west-2` | The AWS region where Athena runs. Must match your Glue Catalog and S3 bucket region. |
| `^` | Windows CMD line continuation character. |

**`aws athena get-query-execution --query-execution-id <QUERY_EXECUTION_ID> --region eu-west-2`**

| Input | What it is |
|-------|-----------|
| `aws athena get-query-execution` | Retrieves the status and metadata of a previously submitted query. |
| `--query-execution-id <QUERY_EXECUTION_ID>` | The ID returned by `start-query-execution`. Replace `<QUERY_EXECUTION_ID>` with the actual value (a UUID like `a1b2c3d4-e5f6-7890-abcd-ef1234567890`). |
| `--region eu-west-2` | The region where the query was submitted. |

The response includes:
- `Status.State` — one of `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, or `CANCELLED`
- `Status.StateChangeReason` — if FAILED, this explains why (e.g. syntax error, permission issue)
- `Statistics.DataScannedInBytes` — how much data was read (for cost tracking)
- `Statistics.EngineExecutionTimeInMillis` — how long the query took

**Expected output from `start-query-execution`:**
```json
{
    "QueryExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Expected output from `get-query-execution` (success):**
```json
{
    "QueryExecution": {
        "QueryExecutionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "Query": "CREATE EXTERNAL TABLE ...",
        "Status": {
            "State": "SUCCEEDED",
            "SubmissionDateTime": "2025-01-15T10:32:00+00:00",
            "CompletionDateTime": "2025-01-15T10:32:02+00:00"
        },
        "Statistics": {
            "EngineExecutionTimeInMillis": 1200,
            "DataScannedInBytes": 0
        },
        "WorkGroup": "primary"
    }
}
```

### 1.4 Notes on CREATE TABLE DDL

**Standard CSV (comma-delimited, header row):**

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS trading.orders (
  order_id         STRING,
  customer_id      STRING,
  order_date       DATE,
  amount           DOUBLE,
  region           STRING,
  product_category STRING
)
ROW FORMAT DELIMITED
  FIELDS TERMINATED BY ','
  LINES TERMINATED BY '\n'
LOCATION 's3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/'
TBLPROPERTIES ('skip.header.line.count' = '1');
```

| DDL clause | What it does |
|------------|-------------|
| `ROW FORMAT DELIMITED` | Uses the default [LazySimpleSerDe](https://docs.aws.amazon.com/athena/latest/ug/lazy-simple-serde.html) — expects simple delimiter-separated values with no quoting or escaping. Fastest for clean CSVs. |
| `FIELDS TERMINATED BY ','` | Columns are separated by commas. |
| `LINES TERMINATED BY '\n'` | Each row is one line (newline-separated). This is the default and can be omitted. |
| `TBLPROPERTIES ('skip.header.line.count' = '1')` | Skip the first line (header). Without this, the header row becomes a data row with string values. |

**CSV with quoted fields (commas inside values):**

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS trading.clients (
  client_id   STRING,
  client_name STRING,
  address     STRING,
  tier        STRING
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde'
WITH SERDEPROPERTIES (
  'separatorChar' = ',',
  'quoteChar'     = '"',
  'escapeChar'    = '\\'
)
LOCATION 's3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/clients/'
TBLPROPERTIES ('skip.header.line.count' = '1');
```

| DDL clause | What it does |
|------------|-------------|
| `ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.OpenCSVSerde'` | Uses the [OpenCSV SerDe](https://docs.aws.amazon.com/athena/latest/ug/csv-serde.html) instead of the default LazySimpleSerDe. This SerDe handles quoted fields correctly — if a field contains a comma (e.g. an address like `"123 Main St, Suite 4"`), it won't be split into two columns. |
| `'separatorChar' = ','` | Column delimiter (same as before, but explicitly set). |
| `'quoteChar' = '"'` | Character used to quote fields containing the separator. Fields wrapped in double quotes are treated as a single value. |
| `'escapeChar' = '\\\\'` | Character used to escape special characters within a field. The double-backslash `\\\\` is SQL escaping for a single `\`. |
| **Important caveat** | OpenCSVSerde treats **all columns as STRING** regardless of what types you declare. If you need DATE or DOUBLE types, create a view that casts them: `CREATE VIEW orders_typed AS SELECT CAST(amount AS DOUBLE) ...` |

**Partitioned table (production pattern):**

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS trading.orders_partitioned (
  order_id STRING, customer_id STRING, amount DOUBLE, product_category STRING
)
PARTITIONED BY (order_date DATE, region STRING)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ','
LOCATION 's3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders_partitioned/'
TBLPROPERTIES ('skip.header.line.count'='1');
```

| DDL clause | What it does |
|------------|-------------|
| `PARTITIONED BY (order_date DATE, region STRING)` | Declares partition columns. These columns are NOT in the CSV files — their values come from the S3 folder path (Hive-style: `order_date=2025-01-15/region=EMEA/`). Partitions let Athena skip irrelevant folders when your WHERE clause filters on a partition key, dramatically reducing scan costs. See [Partitioning data in Athena](https://docs.aws.amazon.com/athena/latest/ug/partitions.html). |
| Column list (before `PARTITIONED BY`) | Only includes non-partition columns. Partition columns are defined separately in the `PARTITIONED BY` clause. |
| **S3 path requirement** | Data must be organized as: `s3://bucket/table/partition_key=value/partition_key=value/file.csv`. Athena uses the folder names to determine partition values. |

After creating a partitioned table, load partitions:

```bash
aws athena start-query-execution ^
  --query-string "MSCK REPAIR TABLE trading.orders_partitioned" ^
  --work-group "primary" ^
  --result-configuration "OutputLocation=s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/" ^
  --region eu-west-2
```

#### Command-by-command explanation (partition repair)

| Input | What it is |
|-------|-----------|
| `MSCK REPAIR TABLE trading.orders_partitioned` | Scans the S3 LOCATION for Hive-style partition paths (e.g. `order_date=2025-01-15/region=EMEA/`) and registers them in the Glue Catalog. Without this, Athena doesn't know the partitions exist. Run this after uploading new partitioned data. |
| `--work-group "primary"` | Workgroup to execute in. |
| `--result-configuration "OutputLocation=..."` | S3 path for Athena output metadata. |
| `--region eu-west-2` | AWS region. |

S3 structure for partitioned data must follow Hive-style paths:
`s3://bucket/trading/orders_partitioned/order_date=2025-01-15/region=EMEA/file.csv`

### 1.5 Verify the Table Exists

```bash
aws glue get-table --database-name trading --name orders --region eu-west-2
```

#### Command-by-command explanation

| Input | What it is |
|-------|-----------|
| `aws glue get-table` | Retrieves full metadata for a specific table from the Glue Data Catalog — column definitions, SerDe, S3 location, partition keys, and table properties. |
| `--database-name trading` | The Glue database containing the table. |
| `--name orders` | The table name to look up. |
| `--region eu-west-2` | AWS region where the Glue Catalog lives. |

The response confirms: column names/types match your CSV, the LOCATION points to the correct S3 path, and SerDe parameters (delimiter, header skip) are set correctly. If you get `EntityNotFoundException`, the CREATE TABLE DDL didn't succeed — re-check section 1.3.

---

## 2. Create Users and Groups in Cognito

The chatbot uses [Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html) as its identity layer. In production, users authenticate via corporate SAML SSO. For development and testing, you can create users and groups directly using the [cognito-idp CLI](https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/index.html).

### 2.1 Identify Your User Pool ID

If deployed via CDK, the pool ID is exported as `ChatbotUserPoolId`. Otherwise:

```bash
aws cognito-idp list-user-pools --max-results 10 --region eu-west-2
```

Set it as a variable for convenience:

```bash
set USER_POOL_ID=eu-west-2_XXXXXXXXX
```

#### Command-by-command explanation

| Input | What it is |
|-------|-----------|
| `aws cognito-idp list-user-pools` | Lists all Cognito User Pools in the account/region. Returns pool IDs and names. |
| `--max-results 10` | Limit output to 10 pools (pagination control). |
| `--region eu-west-2` | AWS region to query. |
| `set USER_POOL_ID=eu-west-2_XXXXXXXXX` | Windows CMD variable assignment. Stores the pool ID so subsequent commands can use `%USER_POOL_ID%` instead of repeating the full ID. Replace `eu-west-2_XXXXXXXXX` with the actual pool ID from the list response (format: `<region>_<alphanumeric>`). |

### 2.2 Create Groups

Groups map to Cedar policy authorization. The chatbot uses groups like `Finance-Analysts`, `Trading-Desk`, and `cross_department_access`.

```bash
# Create an analyst group
aws cognito-idp create-group ^
  --user-pool-id %USER_POOL_ID% ^
  --group-name "Finance-Analysts" ^
  --description "Finance department analysts — access to sales and finance databases" ^
  --region eu-west-2

# Create a trading group
aws cognito-idp create-group ^
  --user-pool-id %USER_POOL_ID% ^
  --group-name "Trading-Desk" ^
  --description "Trading desk — access to trading database" ^
  --region eu-west-2

# Create a cross-department manager group
aws cognito-idp create-group ^
  --user-pool-id %USER_POOL_ID% ^
  --group-name "cross_department_access" ^
  --description "Managers with cross-department query access" ^
  --region eu-west-2

# List groups to verify
aws cognito-idp list-groups --user-pool-id %USER_POOL_ID% --region eu-west-2
```

#### Command-by-command explanation

**`aws cognito-idp create-group`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp create-group` | Creates a new group in the specified Cognito User Pool. Groups appear as the `cognito:groups` claim in JWTs — Cedar policies evaluate this claim for authorization decisions. See [create-group CLI reference](https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/create-group.html). |
| `--user-pool-id %USER_POOL_ID%` | The User Pool to create the group in. `%USER_POOL_ID%` references the CMD variable set in section 2.1. |
| `--group-name "Finance-Analysts"` | The group name. This exact string appears in the JWT `cognito:groups` array and must match what your Cedar policies check (e.g. `principal.groups.contains("Finance-Analysts")`). Case-sensitive. |
| `--description "..."` | Human-readable description. Visible in the Cognito Console. Does not affect authorization logic. |
| `--region eu-west-2` | AWS region where the User Pool lives. |

**`aws cognito-idp list-groups`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp list-groups` | Lists all groups in a User Pool. Use to verify your groups were created. |
| `--user-pool-id %USER_POOL_ID%` | The User Pool to query. |
| `--region eu-west-2` | AWS region. |

The response shows each group's name, description, creation date, and last-modified date.

### 2.3 Create a User

```bash
aws cognito-idp admin-create-user ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --user-attributes "[{\"Name\":\"email\",\"Value\":\"analyst@example.com\"},{\"Name\":\"email_verified\",\"Value\":\"true\"},{\"Name\":\"custom:department\",\"Value\":\"Finance\"},{\"Name\":\"custom:role\",\"Value\":\"analyst\"},{\"Name\":\"custom:data_classification_tier\",\"Value\":\"confidential\"}]" ^
  --temporary-password "TempP@ssw0rd!" ^
  --region eu-west-2
```

Set a permanent password (skip the force-change flow for testing):

```bash
aws cognito-idp admin-set-user-password ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --password "Pr0duction$ecure!2026" ^
  --permanent ^
  --region eu-west-2
```

#### Command-by-command explanation

**`aws cognito-idp admin-create-user`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp admin-create-user` | Creates a new user in the pool as an administrator (bypasses self-signup). The user is created in `FORCE_CHANGE_PASSWORD` status by default. See [admin-create-user CLI reference](https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/admin-create-user.html). |
| `--user-pool-id %USER_POOL_ID%` | The User Pool to add the user to. |
| `--username "analyst@example.com"` | The login identifier for the user. Typically an email address. Must be unique within the pool. |
| `--user-attributes [...]` | A JSON array of `{Name, Value}` objects setting the user's profile attributes. Each attribute explained below: |
| `"Name":"email", "Value":"analyst@example.com"` | The user's email address. Used for notifications and account recovery. |
| `"Name":"email_verified", "Value":"true"` | Marks the email as pre-verified. Without this, Cognito sends a verification email and the user cannot log in until they confirm. Set to `"true"` for test users. |
| `"Name":"custom:department", "Value":"Finance"` | Custom attribute — the user's business department. Appears in the JWT as `custom:department` and is used by Cedar policies for ABAC authorization. |
| `"Name":"custom:role", "Value":"analyst"` | Custom attribute — the user's role (e.g. `analyst`, `manager`). Cedar policies check `principal.role` against this value. |
| `"Name":"custom:data_classification_tier", "Value":"confidential"` | Custom attribute — the maximum data classification tier this user can access. Valid values: `public`, `internal`, `confidential`, `restricted`. Cedar policies use this for tier-based access control. |
| `--temporary-password "TempP@ssw0rd!"` | Initial password assigned to the user. Must meet the pool's password policy (16+ chars, upper, lower, number, symbol). User is forced to change it on first login unless you set a permanent password. |
| `--region eu-west-2` | AWS region. |

**`aws cognito-idp admin-set-user-password`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp admin-set-user-password` | Directly sets a user's password without requiring them to go through the change-password flow. |
| `--user-pool-id %USER_POOL_ID%` | The User Pool containing the user. |
| `--username "analyst@example.com"` | Which user to update. |
| `--password "Pr0duction$ecure!2026"` | The new password. Must meet the pool's password policy. |
| `--permanent` | Sets the password as permanent (moves user from `FORCE_CHANGE_PASSWORD` to `CONFIRMED` status). Without this flag, the password would still be treated as temporary. |
| `--region eu-west-2` | AWS region. |

### 2.4 Add User to a Group

```bash
aws cognito-idp admin-add-user-to-group ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --group-name "Finance-Analysts" ^
  --region eu-west-2
```

#### Command-by-command explanation

| Input | What it is |
|-------|-----------|
| `aws cognito-idp admin-add-user-to-group` | Adds an existing user to an existing group. After this, the group name appears in the user's JWT `cognito:groups` claim on their next login. |
| `--user-pool-id %USER_POOL_ID%` | The User Pool that contains both the user and the group. |
| `--username "analyst@example.com"` | The user to add (must already exist in the pool). |
| `--group-name "Finance-Analysts"` | The group to add the user to (must already exist — create it first with `create-group`). Case-sensitive — must exactly match what Cedar policies expect. |
| `--region eu-west-2` | AWS region. |

A user can belong to multiple groups. Each group membership grants additional Cedar policy permissions. The user's JWT will contain all groups in the `cognito:groups` array.

### 2.5 Verify User and Group Membership

```bash
# List user details
aws cognito-idp admin-get-user ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --region eu-west-2

# List groups for a user
aws cognito-idp admin-list-groups-for-user ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --region eu-west-2
```

#### Command-by-command explanation

**`aws cognito-idp admin-get-user`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp admin-get-user` | Retrieves full profile details for a specific user — all attributes, account status, creation date, MFA settings. |
| `--user-pool-id %USER_POOL_ID%` | The User Pool to query. |
| `--username "analyst@example.com"` | The user to look up. |
| `--region eu-west-2` | AWS region. |

The response includes `UserAttributes` (email, custom:department, custom:role, etc.), `UserStatus` (`CONFIRMED`, `FORCE_CHANGE_PASSWORD`, or `DISABLED`), and `Enabled` (true/false).

**`aws cognito-idp admin-list-groups-for-user`**

| Input | What it is |
|-------|-----------|
| `aws cognito-idp admin-list-groups-for-user` | Lists all groups a specific user belongs to. Use this to verify group assignments before testing authorization. |
| `--user-pool-id %USER_POOL_ID%` | The User Pool to query. |
| `--username "analyst@example.com"` | The user whose group memberships to list. |
| `--region eu-west-2` | AWS region. |

The response is an array of group objects. Verify the user's groups match what your Cedar policies require for the access you want to test.

### 2.6 Example: Create Multiple Users (Batch)

```bash
# Manager user with cross-department access
aws cognito-idp admin-create-user ^
  --user-pool-id %USER_POOL_ID% ^
  --username "manager@example.com" ^
  --user-attributes "[{\"Name\":\"email\",\"Value\":\"manager@example.com\"},{\"Name\":\"email_verified\",\"Value\":\"true\"},{\"Name\":\"custom:department\",\"Value\":\"Finance\"},{\"Name\":\"custom:role\",\"Value\":\"manager\"},{\"Name\":\"custom:data_classification_tier\",\"Value\":\"restricted\"}]" ^
  --temporary-password "TempP@ssw0rd!" ^
  --region eu-west-2

aws cognito-idp admin-set-user-password ^
  --user-pool-id %USER_POOL_ID% ^
  --username "manager@example.com" ^
  --password "M@nager$ecure!2026" ^
  --permanent ^
  --region eu-west-2

aws cognito-idp admin-add-user-to-group ^
  --user-pool-id %USER_POOL_ID% ^
  --username "manager@example.com" ^
  --group-name "Finance-Analysts" ^
  --region eu-west-2

aws cognito-idp admin-add-user-to-group ^
  --user-pool-id %USER_POOL_ID% ^
  --username "manager@example.com" ^
  --group-name "cross_department_access" ^
  --region eu-west-2
```

#### Explanation of this sequence

This creates a **manager** user with broader access than an analyst:

| Step | What it does | Authorization effect |
|------|-------------|---------------------|
| `admin-create-user` with `custom:role = "manager"` and `custom:data_classification_tier = "restricted"` | Creates the user with manager role and highest-tier clearance. | Cedar `managers.cedar` policies match on `principal.role == "manager"`. Tier `restricted` means this user can access all data up to and including restricted. |
| `admin-set-user-password --permanent` | Sets a usable password so the user can log in immediately. | N/A — operational convenience for testing. |
| `admin-add-user-to-group "Finance-Analysts"` | Adds to the Finance-Analysts group. | User gets access to finance and sales databases via group-based permits. |
| `admin-add-user-to-group "cross_department_access"` | Adds to the cross-department group. | Cedar `managers.cedar` has additional permits for managers in this group — allows querying tables across all departments (not just their own), still bounded by classification tier. |

The resulting JWT for this user will contain `"cognito:groups": ["Finance-Analysts", "cross_department_access"]` and `"custom:role": "manager"` — both are evaluated by Cedar on every tool call.

---

## 3. Manually Verify Athena Queries

Once your table is created and CSV data is in S3, you can verify everything works by running SQL queries against Athena. There are two ways to do this: the AWS Console (interactive) and the AWS CLI (scriptable).

### 3.1 Using the AWS Console (Athena Query Editor)

This is the easiest way to interactively write and test SQL queries. The Athena Query Editor is a browser-based SQL IDE built into the [AWS Management Console](https://docs.aws.amazon.com/athena/latest/ug/getting-started.html).

1. Open the AWS Console: [https://console.aws.amazon.com/athena](https://console.aws.amazon.com/athena)
2. Make sure you are in the correct region (e.g. `eu-west-2`).
3. In the left panel, select your **Database** (e.g. `trading`) from the dropdown.
4. In the **Query Editor** (the large text area in the center of the page), type your SQL query:

```sql
SELECT * FROM trading.orders LIMIT 10;
```

5. Click **Run** (or press Ctrl+Enter).
6. Results appear in the **Results** tab below the editor.

> **Where to type the SQL:** The Athena Query Editor is the large text input area at the top of the Athena Console page. It works like a SQL IDE — you type queries directly, run them, and see results inline.

**Setting the query result location (first-time setup):**
If Athena prompts you to set a query result location, go to **Settings** (top-right of the Athena console) → **Manage** → set it to your results bucket:
```
s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/
```

**Selecting a workgroup:**
Use the **Workgroup** dropdown (top of the Athena console page) to select `chatbot-readonly` if it exists, or `primary` for general testing.

### 3.2 Using the AWS CLI

The CLI workflow is asynchronous: you submit a query, get an execution ID, poll for completion, then fetch results.

**Step 1 — Submit the query:**

```bash
aws athena start-query-execution ^
  --query-string "SELECT * FROM trading.orders LIMIT 5" ^
  --query-execution-context "Database=trading" ^
  --work-group "primary" ^
  --result-configuration "OutputLocation=s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/" ^
  --region eu-west-2
```

This returns a JSON response with `QueryExecutionId`.

| Input | What it is |
|-------|-----------|
| `aws athena start-query-execution` | Submits a SQL query to Athena. Returns immediately with a `QueryExecutionId` — the query runs asynchronously in the background. |
| `--query-string "SELECT * FROM trading.orders LIMIT 5"` | The SQL to execute. This is a read query (SELECT) that retrieves the first 5 rows from the `orders` table in the `trading` database. |
| `--query-execution-context "Database=trading"` | Sets the default database context. If your SQL uses unqualified table names (e.g. `orders` instead of `trading.orders`), Athena looks in this database. |
| `--work-group "primary"` | The Athena workgroup. Controls cost limits (bytes-scanned cap), result location defaults, and IAM access. Use `primary` for general testing or `chatbot-readonly` for production-like behavior. |
| `--result-configuration "OutputLocation=s3://..."` | S3 path where Athena writes the query result CSV. Every query produces a result file here — even if you only read results via the API. |
| `--region eu-west-2` | AWS region. |

**Step 2 — Check query status (poll until SUCCEEDED):**

```bash
aws athena get-query-execution ^
  --query-execution-id <QUERY_EXECUTION_ID> ^
  --region eu-west-2
```

Look for `"State": "SUCCEEDED"` (or `FAILED` / `CANCELLED`).

| Input | What it is |
|-------|-----------|
| `aws athena get-query-execution` | Retrieves the current status of a submitted query. |
| `--query-execution-id <QUERY_EXECUTION_ID>` | The UUID returned by step 1. Replace `<QUERY_EXECUTION_ID>` with the actual value. |
| `--region eu-west-2` | AWS region. |

Poll this command (re-run every 1–2 seconds) until `Status.State` is `SUCCEEDED`, `FAILED`, or `CANCELLED`. In-progress queries show `QUEUED` or `RUNNING`.

**Step 3 — Fetch results:**

```bash
aws athena get-query-results ^
  --query-execution-id <QUERY_EXECUTION_ID> ^
  --region eu-west-2
```

This returns the rows as JSON. The first row in `ResultSet.Rows` is the header, subsequent rows are data.

| Input | What it is |
|-------|-----------|
| `aws athena get-query-results` | Fetches the actual data rows returned by a completed query. Only works after `Status.State` is `SUCCEEDED`. |
| `--query-execution-id <QUERY_EXECUTION_ID>` | Same execution ID from step 1. |
| `--region eu-west-2` | AWS region. |

The response contains:
- `ResultSet.ResultSetMetadata.ColumnInfo` — column names and types
- `ResultSet.Rows[0]` — the header row (column names as strings)
- `ResultSet.Rows[1:]` — actual data rows, each as a list of `{VarCharValue: "..."}` cells

### 3.3 Example Verification Queries

Run these after table creation to confirm data is accessible:

```sql
-- Row count
SELECT COUNT(*) AS total_rows FROM trading.orders;

-- Sample data
SELECT * FROM trading.orders LIMIT 5;

-- Aggregation
SELECT region, COUNT(*) AS order_count, SUM(amount) AS total_amount
FROM trading.orders
GROUP BY region
ORDER BY total_amount DESC;

-- Filter
SELECT * FROM trading.orders
WHERE order_date >= DATE '2025-01-16'
  AND region = 'EMEA';
```

### 3.4 Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `HIVE_CANNOT_OPEN_SPLIT` | No files at the S3 LOCATION | Verify upload: `aws s3 ls s3://bucket/trading/orders/` |
| All columns return NULL | Header not skipped or wrong delimiter | Ensure `skip.header.line.count = '1'` in TBLPROPERTIES |
| `SYNTAX_ERROR: line X:Y` | Typo in SQL | Check column types match your CSV. DATE requires YYYY-MM-DD. |
| `AccessDeniedException` | Missing IAM permissions | Add `AmazonAthenaFullAccess` and `AWSGlueConsoleFullAccess` to your user/role |
| `TABLE_NOT_FOUND` | Wrong database selected | Prefix table with database: `trading.orders` or set `--query-execution-context` |

### 3.5 Checking Query Results in S3

Every Athena query writes its results as a CSV to the output location. You can also inspect results directly:

```bash
aws s3 ls s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/ --region eu-west-2
```

Each query produces two files: `<execution-id>.csv` (results) and `<execution-id>.csv.metadata` (schema info).

#### Command-by-command explanation

| Input | What it is |
|-------|-----------|
| `aws s3 ls` | Lists objects at the given S3 path. |
| `s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/` | The folder you configured as the Athena `OutputLocation`. Every query you run produces files here. |
| `--region eu-west-2` | AWS region (optional for `s3 ls` but good practice). |

The output shows filenames like `a1b2c3d4-e5f6-7890-abcd-ef1234567890.csv`. You can download and inspect a result file with:
```bash
aws s3 cp s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/<execution-id>.csv ./result.csv
```

---

## 4. Clean Up Resources

To avoid ongoing costs, remove resources created during testing:

```bash
# Delete the Athena table (metadata only — does not delete S3 data)
aws athena start-query-execution ^
  --query-string "DROP TABLE IF EXISTS trading.orders" ^
  --work-group "primary" ^
  --result-configuration "OutputLocation=s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/" ^
  --region eu-west-2

# Delete the Glue database (fails if tables still exist — drop tables first)
aws glue delete-database --name trading --region eu-west-2

# Delete S3 data (irreversible!)
aws s3 rm s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/trading/orders/ --recursive --region eu-west-2

# Delete the S3 bucket (must be empty first)
aws s3 rb s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2 --region eu-west-2

# Delete a Cognito user
aws cognito-idp admin-delete-user ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --region eu-west-2

# Delete a Cognito group
aws cognito-idp delete-group ^
  --user-pool-id %USER_POOL_ID% ^
  --group-name "Finance-Analysts" ^
  --region eu-west-2
```

> **Warning:** `aws s3 rm --recursive` permanently deletes files. Double-check the path before running.

---

## Quick Reference

| Task | Command |
|------|---------|
| Upload CSV to S3 | `aws s3 cp file.csv s3://bucket/db/table/` |
| Create Glue database | `aws glue create-database --database-input ...` |
| Create Athena table | `aws athena start-query-execution --query-string "CREATE EXTERNAL TABLE ..."` |
| Check query status | `aws athena get-query-execution --query-execution-id <ID>` |
| Get query results | `aws athena get-query-results --query-execution-id <ID>` |
| Create Cognito group | `aws cognito-idp create-group --user-pool-id <ID> --group-name <NAME>` |
| Create Cognito user | `aws cognito-idp admin-create-user --user-pool-id <ID> --username <EMAIL> --user-attributes [...]` |
| Add user to group | `aws cognito-idp admin-add-user-to-group --user-pool-id <ID> --username <EMAIL> --group-name <NAME>` |
| Run interactive SQL | AWS Console → Athena → Query Editor → type SQL → click Run |

---

## Further Reading

| Topic | Link |
|-------|------|
| Amazon Athena User Guide | https://docs.aws.amazon.com/athena/latest/ug/what-is.html |
| CREATE TABLE statement (Athena DDL) | https://docs.aws.amazon.com/athena/latest/ug/create-table.html |
| Supported data formats in Athena | https://docs.aws.amazon.com/athena/latest/ug/supported-serdes.html |
| LazySimpleSerDe (default CSV) | https://docs.aws.amazon.com/athena/latest/ug/lazy-simple-serde.html |
| OpenCSVSerDe (quoted CSV) | https://docs.aws.amazon.com/athena/latest/ug/csv-serde.html |
| Partitioning data in Athena | https://docs.aws.amazon.com/athena/latest/ug/partitions.html |
| Athena workgroups | https://docs.aws.amazon.com/athena/latest/ug/workgroups.html |
| AWS Glue Data Catalog | https://docs.aws.amazon.com/glue/latest/dg/catalog-and-crawler.html |
| Glue CLI reference | https://docs.aws.amazon.com/cli/latest/reference/glue/index.html |
| Amazon Cognito Developer Guide | https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html |
| Cognito User Pool groups | https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html |
| Cognito CLI reference (cognito-idp) | https://docs.aws.amazon.com/cli/latest/reference/cognito-idp/index.html |
| AWS CLI S3 commands | https://docs.aws.amazon.com/cli/latest/reference/s3/index.html |
| Athena CLI reference | https://docs.aws.amazon.com/cli/latest/reference/athena/index.html |
| IAM best practices | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html |
| Cedar policy language | https://www.cedarpolicy.com/en |
