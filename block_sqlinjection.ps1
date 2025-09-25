Import-Module WebAdministration

function createFilterRule {
	param (
		[string]$ruleName,
		[string]$denyString
	)
	
	Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules" `
		-Name "." ` -Value @{ 
			name = $ruleName
			scanUrl = $true 
			scanQueryString = $true
		}

	Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
		-Name "." `
		-Value @{string=$denyString} `
		-Force	
	
}

# sql injection string cast(
createFilterRule -ruleName "SQL-BLOCK-seq-cast" -denyString "cast("
createFilterRule -ruleName "SQL-BLOCK-at-version" -denyString "@@version"
createFilterRule -ruleName "SQL-BLOCK-connect" -denyString "Connect()"
createFilterRule -ruleName "SQL-BLOCK-cast" -denyString "cast()"
createFilterRule -ruleName "SQL-BLOCK-char" -denyString "char()"
createFilterRule -ruleName "SQL-BLOCK-bchar" -denyString "bchar()"
createFilterRule -ruleName "SQL-BLOCK-sysdatabases" -denyString "sysdatabases"
createFilterRule -ruleName "SQL-BLOCK-Select" -denyString "(select"
createFilterRule -ruleName "SQL-BLOCK-convert" -denyString "convert("
createFilterRule -ruleName "SQL-BLOCK-DBNETLIB" -denyString "DBNETLIB"
createFilterRule -ruleName "SQL-BLOCK-connect2" -denyString "Connect("
createFilterRule -ruleName "SQL-BLOCK-int" -denyString "int%2c("
createFilterRule -ruleName "SQL-BLOCK-sysobject" -denyString "sysobject"
createFilterRule -ruleName "SQL-BLOCK-count" -denyString "count("

createFilterRule -ruleName "SQL-BLOCK-xp_cmdshell" -denyString "xp_cmdshell"
createFilterRule -ruleName "SQL-BLOCK-sp_executesql" -denyString "sp_executesql"
createFilterRule -ruleName "SQL-BLOCK-exec" -denyString "exec("
createFilterRule -ruleName "SQL-BLOCK-union-select" -denyString "union+select"
createFilterRule -ruleName "SQL-BLOCK-info-schema" -denyString "information_schema"
createFilterRule -ruleName "SQL-BLOCK-syscolumns" -denyString "syscolumns"
createFilterRule -ruleName "SQL-BLOCK-master-dbo" -denyString "master.dbo"
createFilterRule -ruleName "SQL-BLOCK-drop-table" -denyString "drop+table"
createFilterRule -ruleName "SQL-BLOCK-truncate-table" -denyString "truncate+table"
createFilterRule -ruleName "SQL-BLOCK-nvarchar" -denyString "nvarchar"

createFilterRule -ruleName "SQL-BLOCK-one-equals-one" -denyString "1=1"
createFilterRule -ruleName "SQL-BLOCK-encoded-one-equals-one" -denyString "1%3d1"