-- SQL Server Security Scripts
-- Last script revision - 2021-01-25
--
-- Scripts provided by MSSQLTips.com are from various contributors. Use links below to learn more about the scripts.
-- 
-- Be careful using any of these scripts. Test all scripts in Test/Dev prior to using in Production environments.
-- Please refer to the disclaimer policy: https://www.mssqltips.com/disclaimer/
-- Please refer to the copyright policy: https://www.mssqltips.com/copyright/
--
-- Note, these scripts are meant to be run individually.
--
-- Have a script to contribute or an update?  Send an email to: tips@mssqltips.com


-----------------------------------------------------------------------------------
-- Purpose: Reset the password and then disable the 'sa' login, as a recommended best practice.
-- More information: https://www.mssqltips.com/sqlservertip/2006/secure-and-disable-the-sql-server-sa-account/
-- Revision: 2021-01-25
--
-- This first requires you to create the stored procedure which can be found on the link above.
--
USE master
GO
EXEC sp_SetAutoSAPasswordAndDisable
GO

-----------------------------------------------------------------------------------
-- Purpose: Estimate when was the last time that the sa password was changed in your SQL Server instance.
-- More information: https://www.mssqltips.com/sqlservertip/1142/when-was-the-last-time-the-sql-server-sa-password-changed/
-- Revision: 2021-01-25
--
USE master
GO
SELECT sid, [name], createdate, updatedate
FROM master.dbo.syslogins
WHERE [name] = 'sa'
GO

-----------------------------------------------------------------------------------
-- Purpose: Grant/Deny/Revoke permissions to users on specific database objects.
-- More information: https://www.mssqltips.com/sqlservertip/1138/giving-and-removing-permissions-in-sql-server/
-- Revision: 2021-01-25
--
-- Here are some examples of these commands.
--
-- Allow users Joe and Mary to SELECT, INSERT and UPDATE data in table Customers
GRANT INSERT, UPDATE, SELECT ON dbo.Customers TO Joe, Mary

-- Revoke UPDATE access to table Customers for user Joe
REVOKE UPDATE ON dbo.Customers to Joe

-- Deny DELETE access to table Customers for user Joe and Mary
DENY DELETE ON dbo.Customers to Joe, Mary

-- Grant EXECUTE rights to run a stored procedure for user Joe
GRANT EXEC ON dbo.uspInsertCustomers TO Joe

-- To determine what rights have been granted in a database use the sp_helprotect stored procedure.
EXEC sp_helprotect
GO

-----------------------------------------------------------------------------------
-- Purpose: Generate script of the database roles assigned to database users in a particular database.
-- More information: https://www.mssqltips.com/sqlservertip/2296/retrieving-sql-server-fixed-database-roles-for-disaster-recovery/ 
-- Revision: 2021-01-25
--
-- This generates sp_addrolemember commands for each user that has a database role for a database
--
SET NOCOUNT ON;
CREATE TABLE #DatabaseRoleMembers (
    DbRole sysname,
    MemberName sysname,
    MemberSID VARBINARY(85)
);

INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_owner';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_securityadmin';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_accessadmin';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_backupoperator';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_ddladmin';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_datareader';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_datawriter';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_denydatareader';
INSERT INTO #DatabaseRoleMembers (DbRole, MemberName, MemberSID)
EXEC sp_helprolemember 'db_denydatawriter';

SELECT 'EXEC sp_addrolemember @rolename = ''' + DbRole + ''', @membername = ''' + MemberName + ''';'
FROM #DatabaseRoleMembers
WHERE MemberName <> 'dbo';
DROP TABLE #DatabaseRoleMembers;
GO

-----------------------------------------------------------------------------------
-- Purpose: Obtain the mapping of database users to database roles for a specific database, using a custom built user defined function.
-- More information: https://www.mssqltips.com/sqlservertip/5999/sql-server-database-users-to-roles-mapping-report/
-- Revision: 2021-01-25
--
-- Function Creation
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION dbo.dbRolesUsersMap (@dbRole SYSNAME = '%')
RETURNS TABLE
AS
RETURN (
      SELECT 
        User_Type = 
           CASE mmbrp.[type] 
           WHEN 'G' THEN 'Windows Group' 
           WHEN 'S' THEN 'SQL User' 
           WHEN 'U' THEN 'Windows User' 
           END,
         Database_User_Name = mmbrp.[name],
         Login_Name = ul.[name],
         DB_Role = rolp.[name]
      FROM sys.database_role_members mmbr, -- The Role OR members associations table
         sys.database_principals rolp,     -- The DB Roles names table
         sys.database_principals mmbrp,    -- The Role members table (database users)
         sys.server_principals ul          -- The Login accounts table
      WHERE Upper (mmbrp.[type]) IN ( 'S', 'U', 'G' )
         -- No need for these system account types
         AND Upper (mmbrp.[name]) NOT IN ('SYS','INFORMATION_SCHEMA')
         AND rolp.[principal_id] = mmbr.[role_principal_id]
         AND mmbrp.[principal_id] = mmbr.[member_principal_id]
         AND ul.[sid] = mmbrp.[sid]
         AND rolp.[name] LIKE '%' + @dbRole + '%'
      )
GO

-- Examples to retrieve database roles mapping from a user database
-- Must be in that database to run
SELECT * FROM dbo.dbRolesUsersMap (DEFAULT)
GO
SELECT * FROM dbo.dbRolesUsersMap ('db_ddlAdmin')
GO

-----------------------------------------------------------------------------------
-- Purpose: Use of SQL Server security related functions
-- More information: https://www.mssqltips.com/sqlservertip/6049/sql-server-security-functions/
-- Revision: 2021-01-25
-- 
-- Returns name of the current database user
SELECT CURRENT_USER

-- Returns ID of the database principal supplied. Note, this is the uid in sys.sysuysers corresponding to the user and not the sid that ties it to the login.
SELECT DATABASE_PRINCIPAL_ID('JoeUser')

-- Returns a 1 if the current database user has the specified permission and 0 if not
SELECT HAS_PERMS_BY_NAME(db_name(), 'DATABASE', 'ANY')

-- Returns a 1 if the current database user is a member of a specific database role, 0 if not, or NULL if role is invalid.
SELECT IS_MEMBER ('db_datareader')
SELECT IS_MEMBER ('db_datawriter')

-- Returns a 1 if the specified database user is a member of a specific database role, 0 if not, or NULL if either user or role is invalid.
SELECT IS_ROLEMEMBER ('db_datareader','JoeUser')
SELECT IS_ROLEMEMBER ('db_datawriter','JoeUser')

-- Returns a 1 if the specified login is a member of a specific server role, 0 if not, or NULL if either login or server role is invalid.
SELECT IS_SRVROLEMEMBER ('securityadmin','Joe')
SELECT IS_SRVROLEMEMBER ('sysadmin','Joe')

-- Returns the original login that first connected to the session. Even though this example is impersonating login Joe2 with the EXECUTE AS, the original login is still Joe.
EXECUTE AS LOGIN = 'Joe2'
SELECT ORIGINAL_LOGIN() AS OriginalLogin
REVERT

-- Compares plain text password to a hash for a login. Useful for checking for blank or common passwords like 'password', '12345', etc.
SELECT name 
FROM sys.sql_logins   
WHERE PWDCOMPARE('password', password_hash) = 1

-- Displays hash for plain text password passed to it. This function may not be supported in future versions of SQL Server.
SELECT PWDENCRYPT ('BadPassword')

-- Returns current database user context.
SELECT SESSION_USER

-- Returns SID of current login or specified login.
SELECT SUSER_NAME(309)

-- Returns a list of a principal's login permissions on a securable.
SELECT DISTINCT permission_name
FROM sys.fn_builtin_permissions(DEFAULT)
ORDER BY permission_name

-----------------------------------------------------------------------------------
-- Purpose: Map between SQL Server SIDs and Windows SIDs
-- More information: https://www.mssqltips.com/sqlservertip/3362/map-between-sql-server-sids-and-windows-sids/
-- Revision: 2021-01-25
--
CREATE TABLE dbo.TinyNumbers(Number TINYINT PRIMARY KEY);
GO

INSERT dbo.TinyNumbers(Number) 
  SELECT TOP (256) ROW_NUMBER() OVER (ORDER BY number)-1 
  FROM master.dbo.spt_values;
GO

CREATE FUNCTION dbo.GetWindowsSID
(
  @sid VARBINARY(85)
)
RETURNS TABLE
WITH SCHEMABINDING
AS
  RETURN 
  (
    SELECT ADsid = STUFF((SELECT '-' + part FROM 
    (
      SELECT Number = -1, part = 'S-' 
        + CONVERT(VARCHAR(30),CONVERT(TINYINT,CONVERT(VARBINARY(30),LEFT(@sid,1)))) 
        + '-' 
        + CONVERT(VARCHAR(30),CONVERT(INT,CONVERT(VARBINARY(30),SUBSTRING(@sid,3,6))))
      UNION ALL
      SELECT TOP ((LEN(@sid)-5)/4) Number, 
     part = CONVERT(VARCHAR(30),CONVERT(BIGINT,CONVERT(VARBINARY(30), 
  REVERSE(CONVERT(VARBINARY(30),SUBSTRING(@sid,9+Number*4,4)))))) 
      FROM dbo.TinyNumbers ORDER BY Number
    ) AS x ORDER BY Number
    FOR XML PATH(''), TYPE).value(N'.[1]','nvarchar(max)'),1,1,'')
  );
GO

CREATE VIEW dbo.server_principal_sids
AS
  SELECT sp.name, sp.[sid], ad.ADsid, sp.type_desc
    FROM sys.server_principals AS sp
    CROSS APPLY dbo.GetWindowsSID(sp.[sid]) AS ad
    WHERE [type] IN ('U','G') 
    AND LEN([sid]) % 4 = 0;
GO

SELECT name, [sid], ADSid, type_desc FROM dbo.server_principal_sids;

-----------------------------------------------------------------------------------
-- Purpose: Clone a SQL Server login and password to a new server
-- More information: https://www.mssqltips.com/sqlservertip/4679/clone-a-sql-server-login-and-password-to-a-new-server/
-- Revision: 2021-01-25
-- 
-- Step 1: Get the SID of the login you want to migrate
USE [master]
SELECT SUSER_SID('testlogin')
GO

-- Step 2: Get the password hash of the login you want to migrate
USE [master]
SELECT LOGINPROPERTY('testlogin','PASSWORDHASH')
GO

-- Step 3: Create the login in the target server, using the SID and Password hash obtained from the previous steps (the values provided in the PASSWORD and SID properties are for reference only)
CREATE LOGIN [testlogin] WITH PASSWORD = 0x020019814E12C5DCBE7D55C803E46D9CD7E349C9F9000BC392759E0CFD0CF98AA5A3D88B1A725F660A82FE7CAEAECA34E49AC5F08C188F5EF5DB99B06EC1E290EBFF4DF10EF1 HASHED, 
SID = 0xE7F3C36B478F5A4A96F179210CFF39C5, 
DEFAULT_DATABASE = [master],
DEFAULT_LANGUAGE=[us_english], 
CHECK_EXPIRATION = ON, 
CHECK_POLICY = ON

-----------------------------------------------------------------------------------
-- Purpose: Find all failed SQL Server logins
-- More information: https://www.mssqltips.com/sqlservertip/4941/find-all-failed-sql-server-logins/
-- Revision: 2021-01-25
--
-- SQL Server setting to capture failed logins
USE [master]
GO
EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', 
     N'Software\Microsoft\MSSQLServer\MSSQLServer', 
     N'AuditLevel',
     REG_DWORD, 2
GO

-- This custom SP loops over each Error Log file to find any failed login attempt. As it is, it will display only those that have occured within the last 7 days, but you can change it to suit your particular case.
CREATE PROC usp_GetFailedLoginsListFromLastWeek
AS
BEGIN
   SET NOCOUNT ON

   DECLARE @ErrorLogCount INT 
   DECLARE @LastLogDate DATETIME

   DECLARE @ErrorLogInfo TABLE (
       LogDate DATETIME
      ,ProcessInfo NVARCHAR (50)
      ,[Text] NVARCHAR (MAX)
      )
   
   DECLARE @EnumErrorLogs TABLE (
       [Archive#] INT
      ,[Date] DATETIME
      ,LogFileSizeMB INT
      )

   INSERT INTO @EnumErrorLogs
   EXEC sp_enumerrorlogs

   SELECT @ErrorLogCount = MIN([Archive#]), @LastLogDate = MAX([Date])
   FROM @EnumErrorLogs

   WHILE @ErrorLogCount IS NOT NULL
   BEGIN

      INSERT INTO @ErrorLogInfo
      EXEC sp_readerrorlog @ErrorLogCount

      SELECT @ErrorLogCount = MIN([Archive#]), @LastLogDate = MAX([Date])
      FROM @EnumErrorLogs
      WHERE [Archive#] > @ErrorLogCount
      AND @LastLogDate > getdate() - 7 
  
   END

   -- List all last week failed logins count of attempts and the Login failure message
   SELECT COUNT (TEXT) AS NumberOfAttempts, TEXT AS Details, MIN(LogDate) as MinLogDate, MAX(LogDate) as MaxLogDate
   FROM @ErrorLogInfo
   WHERE ProcessInfo = 'Logon'
      AND TEXT LIKE '%fail%'
      AND LogDate > getdate() - 7
   GROUP BY TEXT
   ORDER BY NumberOfAttempts DESC

   SET NOCOUNT OFF
END     

-- Execute the SP to obtain the results, if any
EXEC usp_GetFailedLoginsListFromLastWeek     

-----------------------------------------------------------------------------------
-- Purpose: Find orpaned users in a database
-- More information: https://www.mssqltips.com/sqlservertip/1590/understanding-and-dealing-with-orphaned-users-in-a-sql-server-database/
-- Revision: 2021-01-25
--
-- run this in each user database to find orphaned users
sp_change_users_login @Action='Report'
GO

-----------------------------------------------------------------------------------
-- Purpose: Match logins to database users
-- More information: https://www.mssqltips.com/sqlservertip/2705/identifying-the-tie-between-logins-and-users/
-- Revision: 2021-01-25
--
-- run this in each user database 
SELECT d.[name] AS 'DB User', d.sid AS 'DB SID', s.[name] AS 'Login', s.sid AS 'Server SID'
FROM sys.database_principals d
JOIN sys.server_principals s ON d.sid = s.sid
