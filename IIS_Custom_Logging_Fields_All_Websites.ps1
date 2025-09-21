# https://github.com/brandsict-nl/IISPS
Import-Module WebAdministration
Get-WebSite | Select-Object Name | ForEach-Object {
   Write-Output $($_.Name);
   $siteName = $_.Name;
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='XForwardedFor';sourceName='X-Forwarded-For';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='XRealIp';sourceName='X-Real-IP';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='XForwardHost';sourceName='X-Forwarded-Host';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='XForwardProto';sourceName='X-Forwarded-Proto';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='Via';sourceName='Via';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='Forwarded';sourceName='Forwarded';sourceType='RequestHeader'} -Force
   Add-WebConfigurationProperty -pspath "IIS:\"  -filter "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields" -name "." -value @{logFieldName='AcceptLanguage';sourceName='Accept-Language';sourceType='RequestHeader'} -Force
}