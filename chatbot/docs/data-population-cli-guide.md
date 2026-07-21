# Data Population CLI Guide

How to populate the Athena Chatbot data layer using the AWS CLI. Covers uploading CSV data to S3, creating Athena tables via the Glue Catalog, provisioning Cognito users and groups, and manually verifying queries.

## Prerequisites

| Tool | Install | Verify |
|------|---------|--------|
| AWS CLI v2 | `msiexec /i https://awscli.amazonaws.com/AWSCLIV2.msi` | `aws --version` |
| Configured credentials | `aws configure` (Access Key, Secret Key, region `eu-west-2`) | `aws sts get-caller-identity` |
| S3 bucket for data | Created manually or via CDK | `aws s3 ls` |

Ensure your IAM user/role has permissions for S3, Glue, Athena, and Cognito.

---

## 1. Create Athena Tables from CSV Files

Athena reads data directly from S3 — you do not load data *into* Athena. Instead, you:
1. Upload CSV files to S3
2. Create a Glue database (metadata container)
3. Create an external table pointing to the S3 location

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

> **S3 path convention:** `s3://bucket-name/database-name/table-name/`. Athena reads all files under the LOCATION path — organize one folder per table.

### 1.2 Create a Glue Database

```bash
aws glue create-database ^
  --database-input "{\"Name\": \"trading\", \"Description\": \"Trading data lake\"}" ^
  --region eu-west-2

# Verify
aws glue get-database --name trading --region eu-west-2
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

After creating a partitioned table, load partitions:

```bash
aws athena start-query-execution ^
  --query-string "MSCK REPAIR TABLE trading.orders_partitioned" ^
  --work-group "primary" ^
  --result-configuration "OutputLocation=s3://chatbot-datalake-<ACCOUNT_ID>-eu-west-2/query-results/" ^
  --region eu-west-2
```

S3 structure for partitioned data must follow Hive-style paths:
`s3://bucket/trading/orders_partitioned/order_date=2025-01-15/region=EMEA/file.csv`

### 1.5 Verify the Table Exists

```bash
aws glue get-table --database-name trading --name orders --region eu-west-2
```

---

## 2. Create Users and Groups in Cognito

The chatbot uses Amazon Cognito as its identity layer. In production, users authenticate via corporate SAML SSO. For development and testing, you can create users and groups directly.

### 2.1 Identify Your User Pool ID

If deployed via CDK, the pool ID is exported as `ChatbotUserPoolId`. Otherwise:

```bash
aws cognito-idp list-user-pools --max-results 10 --region eu-west-2
```

Set it as a variable for convenience:

```bash
set USER_POOL_ID=eu-west-2_XXXXXXXXX
```

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

### 2.4 Add User to a Group

```bash
aws cognito-idp admin-add-user-to-group ^
  --user-pool-id %USER_POOL_ID% ^
  --username "analyst@example.com" ^
  --group-name "Finance-Analysts" ^
  --region eu-west-2
```

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

---

## 3. Manually Verify Athena Queries

Once your table is created and CSV data is in S3, you can verify everything works by running SQL queries against Athena. There are two ways to do this: the AWS Console (interactive) and the AWS CLI (scriptable).

### 3.1 Using the AWS Console (Athena Query Editor)

This is the easiest way to interactively write and test SQL queries.

1. Open the AWS Console: https://console.aws.amazon.com/athena
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

**Step 2 — Check query status (poll until SUCCEEDED):**

```bash
aws athena get-query-execution ^
  --query-execution-id <QUERY_EXECUTION_ID> ^
  --region eu-west-2
```

Look for `"State": "SUCCEEDED"` (or `FAILED` / `CANCELLED`).

**Step 3 — Fetch results:**

```bash
aws athena get-query-results ^
  --query-execution-id <QUERY_EXECUTION_ID> ^
  --region eu-west-2
```

This returns the rows as JSON. The first row in `ResultSet.Rows` is the header, subsequent rows are data.

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
