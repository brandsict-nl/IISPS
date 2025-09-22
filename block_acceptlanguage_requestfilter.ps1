# https://github.com/brandsict-nl/IISPS
Import-Module WebAdministration

$ruleName = "block list with acceptlanguage"

# Add a request filtering rule to deny specific User-Agent strings server-wide
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules" `
    -Name "." `
    -Value @{
        name = $ruleName
    }

# Configure the rule to apply to the User-Agent header
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/scanHeaders" `
    -Name "." `
    -Value "Accept-Language"


	
# Add denyStrings to the  filtering rule

# Russia
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="ru"} `
    -Force
	
# North Korea
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="ko-KP"} `
    -Force

# Iran
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="fa"} `
    -Force

# Belarus
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="be"} `
    -Force	

# Venezuela
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="es-VE"} `
    -Force	

# Syria
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="ar"} `
    -Force	

# Ukraine
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="uk"} `
    -Force

# China
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="zh-CN"} `
    -Force
	
# Nigeria
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="en-NG"} `
    -Force

# Romania - Moldova
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="ro"} `
    -Force
	
# Ghana
Add-WebConfigurationProperty -PSPath "IIS:\" ` -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="en-GH"} `
    -Force