define("MsPortalImpl/Services/BrowseCuration/default",["require","exports","f","MsPortalImpl/Services/Services.BrowseCuration"],(function(n,t,i,r){"use strict";var u;return (function(n){function v(){return Q({favorites:t([f,"BrowseAllResources"],[f,"ResourceGroups"],i.isFeatureEnabled("quickstart")&&[a,"Quickstart"],[u,"Website"],[u,"AppService"],["SqlAzureExtension","Database"],["Microsoft_Azure_DocumentDB","DocumentDBDatabaseAccount"],["Microsoft_Azure_Compute","VirtualMachine"],["Microsoft_Azure_Network","LoadBalancer"],["Microsoft_Azure_Storage","StorageAccount"],["Microsoft_Azure_Network","VirtualNetwork"],["Microsoft_AAD_IAM","AzureActiveDirectory"],["Microsoft_Azure_Monitoring","AzureMonitoring"],["Microsoft_Azure_Expert","AzureAdvisor"],["Microsoft_Azure_Security","SecurityDashboard"],["Microsoft_Azure_Billing","Billing"],["Microsoft_Azure_Support","HelpAndSupport"]),categories:[{id:"General",items:t([f,o.BrowseAllResources],[f,o.BrowseRecentResources],["Microsoft_Azure_ManagementGroups","ManagementGroups"],["Microsoft_Azure_Billing","SubscriptionDetail"],[f,o.ResourceGroups],["Microsoft_Azure_Billing","Billing"],["Microsoft_Azure_Reservations","ReservationsBrowse"],[l,"Gallery"],["Microsoft_Azure_Support","HelpAndSupport"],["Microsoft_Azure_Health","AzureHealth"],[l,"GalleryRpItem"],[f,"Tag"],[f,"WhatsNew"],[a,"Quickstart"],[f,"Dashboards"],[f,"Settings",!1])},{id:"Compute",items:t(["Microsoft_Azure_Compute","VirtualMachine"],["Microsoft_Azure_Classic_Compute","VirtualMachine"],["Microsoft_Azure_Compute","VirtualMachineScaleSet"],["Microsoft_Azure_Compute","AzureContainerService"],[u,"AppService"],[u,"Website"],["Microsoft_Azure_Compute","ContainerGroup"],["Microsoft_Azure_Batch","BatchAccount"],["Microsoft_Azure_ServiceFabric","ServiceFabricCluster"],["Microsoft_Azure_ServiceFabric","MeshApplications"],["Microsoft_Azure_CloudServices","CloudService"],["Microsoft_Azure_Compute","ManagedClusters"],["Microsoft_Azure_Compute","AvailabilitySet"],["Microsoft_Azure_Compute","Disk"],["Microsoft_Azure_Classic_Compute","Disks"],["Microsoft_Azure_Compute","Snapshot"],["Microsoft_Azure_Compute","Image"],["Microsoft_Azure_Classic_Compute","UserImages"],["Microsoft_Azure_Classic_Compute","OsUserImages"],["Microsoft_Azure_Classic_Compute","VmUserImages"],["Citrix_XenDesktop_Essentials","XenDesktopEssentials"],["Citrix_XenApp_Essentials","XenAppEssentials"],["CloudSimpleExtension","CloudSimple_PrivateCloudIAAS"])},{id:"Networking",items:t(["Microsoft_Azure_Network","VirtualNetwork"],["Microsoft_Azure_Classic_Network","VirtualNetwork"],["Microsoft_Azure_Network","LoadBalancer"],["Microsoft_Azure_Network","ApplicationGateway"],["Microsoft_Azure_Network","VirtualNetworkGateway"],["Microsoft_Azure_Network","LocalNetworkGateway"],["Microsoft_Azure_Network","DnsZone"],["Microsoft_Azure_Cdn","CdnProfile"],["Microsoft_Azure_Network","TrafficManager"],["Microsoft_Azure_Network","ExpressRoute"],["Microsoft_Azure_Network","NetworkWatcher"],["Microsoft_Azure_Network","NetworkSecurityGroup"],["Microsoft_Azure_Classic_Network","NetworkSecurityGroup"],["Microsoft_Azure_Network","NetworkInterface"],["Microsoft_Azure_Network","PublicIpAddress"],["Microsoft_Azure_Network","PublicIpPrefix"],["Microsoft_Azure_Classic_Network","ReservedIPAddress"],["Microsoft_Azure_Network","Connection"],["Microsoft_Azure_ODG","ConnectionGateway"],["Microsoft_Azure_Network","RouteTable"],["Microsoft_Azure_Network","RouteFilter"],["Microsoft_Azure_Network","ApplicationSecurityGroup"],["Microsoft_Azure_Network","DdosProtectionPlan"],["Microsoft_Azure_Network","CloudNativeFirewall"],["Microsoft_Azure_Network","Frontdoor"],["Microsoft_Azure_Network","ServiceEndpointPolicy"],["Microsoft_Azure_Network","VirtualWan"])},{id:"Storage",items:t(["Microsoft_Azure_Storage","StorageAccount"],["Microsoft_Azure_Storage","ClassicStorageAccount"],["Microsoft_Azure_RecoveryServices","RecoveryServicesResource"],["Microsoft_Azure_StorSimple","StorSimpleManager"],["Microsoft_Azure_DataLakeStore","CaboAccount"],["Microsoft_Azure_Storage","StorageExplorer"],["Microsoft_Azure_HybridData","HybridData"],["Microsoft_Azure_Kailani","SyncServiceAsset"],["Microsoft_Azure_Storage","ImportExportJob"],["Microsoft_Azure_EdgeGateway","EdgeGateway"])},{id:"Web",items:t([u,"Website"],["Microsoft_Azure_ApiManagement","Service"],["Microsoft_Azure_Cdn","CdnProfile"],["Microsoft_Azure_Search","SearchService"],["Microsoft_Azure_NotificationHubs","NotificationHub"],["Microsoft_Azure_NotificationHubs","Namespace"],[u,"WebHostingPlan"],[u,"AppServiceEnvironment"],[u,"ApiHubConnection"],[u,"SslCertificate"],[u,"AppServiceDomain"],["Microsoft_Azure_Media","MediaServiceAccount"],["Microsoft_Azure_SignalR","SignalR"])},{id:"Mobile",items:t([u,"Website"],["Microsoft_Azure_NotificationHubs","NotificationHub"],["Microsoft_Azure_LocationServices","LocationBasedServices"])},{id:"Containers",items:t(["Microsoft_Azure_Compute","AzureContainerService"],["Microsoft_Azure_Compute","ContainerGroup"],["Microsoft_Azure_Compute","ManagedClusters"],["Microsoft_Azure_ContainerRegistries","RegistryResource"],["Microsoft_Azure_Batch","BatchAccount"],["Microsoft_Azure_ServiceFabric","ServiceFabricCluster"],[u,"Website"])},{id:"Databases",items:t(["Microsoft_Azure_DocumentDB","DocumentDBDatabaseAccount"],["SqlAzureExtension","Database"],["SqlAzureExtension","MySqlServer"],["SqlAzureExtension","PostgreSqlServer"],["SqlAzureExtension","MariaDBServer"],["SqlAzureExtension","Server"],["SqlAzureExtension","Database","v12.0,user,datawarehouse"],["Microsoft_Azure_DMS","Dms"],["AzureCacheExtension","CacheAsset"],["SqlAzureExtension","Database","v12.0,user,stretch"],["Microsoft_Azure_DataFactory","DataFactory"],["SqlAzureExtension","ElasticPool"],["SqlAzureExtension","VirtualCluster"],["SqlAzureExtension","ManagedDatabase"],["SqlAzureExtension","JobAgent"],["SqlAzureExtension","ManagedInstance"],["SqlAzureExtension","TargetGroup"],["SqlAzureExtension","Credential"],["SqlAzureExtension","Job"])},{id:"Analytics",items:t(["SqlAzureExtension","Database","v12.0,user,datawarehouse"],["Microsoft_Azure_Databricks","Workspace"],["Microsoft_Azure_HDInsight","HDInsightCluster"],["Microsoft_Azure_DataFactory","DataFactory"],["Microsoft_Azure_PowerBIDedicated","PowerBIDedicated"],["Microsoft_PowerBI_Embedded","WorkspaceCollection"],["Microsoft_Azure_StreamAnalytics","StreamAnalyticsJob"],["Microsoft_Azure_DataLakeAnalytics","KonaAccount"],["Microsoft_Azure_AnalysisServices","AnalysisServices"],["Microsoft_Azure_EventHub","EventHub"],["Microsoft_Azure_EventHub","EventHubCluster"],["Microsoft_OperationsManagementSuite_Workspace","Workspace"],["Microsoft_Azure_DataLakeStore","CaboAccount"],["Microsoft_Azure_Kusto","KustoCluster"])},{id:"AI + Machine Learning",items:t(["Microsoft_Azure_BatchAI","BatchAI"],["Microsoft_Azure_BotService","BotService"],["Microsoft_Azure_ProjectOxford","CognitiveServicesAccount"],["Microsoft_Azure_MLTeamAccounts","MachineLearningServices"],["Microsoft_Azure_MLWebservices","MachineLearningWebService"],["Microsoft_Azure_MLWorkspaces","MachineLearningWorkspace"],["Microsoft_Research_Genomics","GenomicsAccountAsset"],["Microsoft_Azure_MLCommitmentPlans","MachineLearningCommitmentPlan"],["Microsoft_Azure_MLTeamAccounts","MachineLearningExperimentationAccount"],["Microsoft_Azure_MLHostingAccounts","MachineLearningModelManagementAccount"])},{id:"Internet of things",items:t(["Microsoft_Azure_IotHub","IotHubs"],["Microsoft_Azure_IotHub","DeviceProvisioning"],["Microsoft_Azure_IoTCentral","IoTApps"],["Microsoft_Azure_LocationServices","LocationBasedServices"],[u,"AppService"],["Microsoft_Azure_EventGrid","EventGrid"],["Microsoft_Azure_TimeSeriesInsights","TimeSeriesInsightsEnvironment"],["Microsoft_Azure_TimeSeriesInsights","TimeSeriesInsightsEventSource"],["Microsoft_Azure_TimeSeriesInsights","TimeSeriesInsightsReferenceDataSet"],["Microsoft_Azure_StreamAnalytics","StreamAnalyticsJob"],["Microsoft_Azure_DocumentDB","DocumentDBDatabaseAccount"],["Microsoft_Azure_EMA","Workflow"],["Microsoft_Azure_MLWorkspaces","MachineLearningWorkspace"],["Microsoft_Azure_MLWebservices","MachineLearningWebService"],["Microsoft_Azure_MLCommitmentPlans","MachineLearningCommitmentPlan"],["Microsoft_Azure_MLTeamAccounts","MachineLearningExperimentationAccount"],["Microsoft_Azure_MLHostingAccounts","MachineLearningModelManagementAccount"],["Microsoft_Azure_EventHub","EventHub"],["Microsoft_Azure_EventHub","EventHubCluster"],["Microsoft_Azure_NotificationHubs","NotificationHub"],["Microsoft_Azure_NotificationHubs","Namespace"],["Microsoft_Azure_LocationServices","Maps"],["Microsoft_WindowsIoT_DeviceServices","DeviceService"],["Microsoft_Azure_EdgeGateway","EdgeGateway"])},{id:"Integration",items:t(["Microsoft_Azure_EMA","Workflow"],["Microsoft_Azure_ServiceBus","ServiceBus"],["Microsoft_Azure_ApiManagement","Service"],["Microsoft_Azure_EventGrid","EventGrid"],["Microsoft_Azure_EventGrid","Topic"],["Microsoft_Azure_DataFactory","DataFactory"],["Microsoft_Azure_DataCatalog","CatalogResource"],["SqlAzureExtension","Database","v12.0,user,stretch"],["Microsoft_Azure_StorSimple","StorSimpleManager"],["Microsoft_Azure_Relay","Relay"],["Microsoft_Azure_EMA","IntegrationAccount"],["Microsoft_Azure_EMA","CustomConnector"],["Microsoft_Azure_Appliance","ArmAppliance"],["Microsoft_Azure_Appliance","ApplianceDefinition"],["Microsoft_Azure_EdgeGateway","EdgeGateway"])},{id:"Identity",items:t(["Microsoft_AAD_IAM","AzureActiveDirectory"],["Microsoft_AAD_B2CAdmin","RootAsset"],["Microsoft_AAD_DomainServices","AADDomainService"],["Microsoft_Azure_InformationProtection","PrimaryDataClassGroup"],["Microsoft_AAD_IAM","GroupsManagement"],["Microsoft_AAD_IAM","UserManagement"],["Microsoft_Azure_ADHybridHealth","RootAsset"],["Microsoft_Azure_PIM","RootAsset"],["Microsoft_AAD_ProtectionCenter","RootAsset"],["Microsoft_AAD_IAM","Application"],["Microsoft_AAD_IAM","RegisteredApplication"],["Microsoft_AAD_ERM","RootAsset"],["Microsoft_AAD_IAM","PolicyRootAsset"],["Microsoft_Azure_ManagedServiceIdentity","UserAssignedIdentity"])},{id:"Security",items:t(["Microsoft_Azure_Security","SecurityDashboard"],["Microsoft_Azure_KeyVault","KeyVault"],["Microsoft_Azure_Network","ApplicationGateway"],["Microsoft_Azure_InformationProtection","PrimaryDataClassGroup"],["Microsoft_Azure_Network","VirtualNetworkGateway"],["Microsoft_AAD_IAM","AzureActiveDirectory"],["Microsoft_Azure_Network","ApplicationSecurityGroup"])},{id:"DevOps",items:t(["AzureTfsExtension","Account"],["AzureTfsExtension","TeamProject"],["AzureTfsExtension","DevOpsProject"],["AppInsightsExtension","ApplicationInsights"],["Microsoft_Azure_DevTestLab","DevTestLab"],["Microsoft_Azure_ApiManagement","Service"],["Microsoft_Azure_ManagedLab","LabAccount"])},{id:"Migrate",items:t(["Microsoft_Azure_Migrate","MigrationProject"],["Microsoft_Azure_RecoveryServices","RecoveryServicesResource"],["Microsoft_Azure_DMS","Dms"],["Microsoft_Azure_Billing","Billing"],["Microsoft_Azure_ExpressPod","DataBox"],["Microsoft_Azure_EdgeGateway","EdgeGateway"])},{id:"Management + governance",items:t(["Microsoft_Azure_Expert","AzureAdvisor"],["Microsoft_Azure_RecoveryServices","RecoveryServicesResource"],["Microsoft_Azure_Billing","Billing"],["Microsoft_Azure_Policy","PolicyHub"],["Microsoft_Azure_Policy","UserPrivacyHub"],["Microsoft_Azure_Monitoring","AzureMonitoring"],["Microsoft_Azure_Policy","ArmBlueprintHub"],["Microsoft_Azure_Policy","ResourceGraphHub"],["Microsoft_Azure_ActivityLog","ActivityLogAsset"],["Microsoft_Azure_Monitoring","AzureMonitoringMetrics"],["Microsoft_Azure_Monitoring","AzureMonitoringMetricsV3"],["Microsoft_Azure_Monitoring","AzureMonitoringDiagnostics"],["Microsoft_Azure_Monitoring","AzureMonitoringAlerts"],["Microsoft_OperationsManagementSuite_Workspace","Workspace"],["Microsoft_OperationsManagementSuite_Workspace","Solution"],["Microsoft_Azure_Scheduler","JobCollection"],["Microsoft_Azure_Automation","Account"],["Microsoft_Azure_Network","NetworkWatcher"],["AppInsightsExtension","ApplicationInsights"],["Microsoft_Azure_Migrate","MigrationProject"],["Microsoft_Azure_RSMT","ComputerConnection"],["Microsoft_Azure_RSMT","Gateway"],["Microsoft_Azure_Billing","FreeServices"],["Microsoft_Azure_Resources","OperationLog"],["Microsoft_EMM_ModernWorkplace","MWaaS"])},{id:"Intune",items:t(["Microsoft_Intune_DeviceSettings","Intune"],["Microsoft_Intune_Apps","IntuneAppProtectionLanding"],["Microsoft_Intune","Intune"],["Microsoft_Intune_Apps","BookMainMenuAsset"],["Microsoft_Intune_Apps","AppsMainMenu"],["Microsoft_Intune_Enrollment","OverviewBladeMenuAsset"],["Microsoft_Intune_Devices","DeviceEntryBladeAsset"],["Microsoft_Intune_DeviceSettings","ExtensionMenu"],["Microsoft_Intune_DeviceSettings","DeviceConfigMainMenuViewModelAsset"],["Microsoft_Intune_DeviceSettings","DeviceComplianceMainMenuViewModelAsset"],["Microsoft_Intune_DeviceSettings","ConnectorMenuAsset"],["Microsoft_Intune_DeviceSettings","ManageOnPremisesAccessAsset"],["Microsoft_Intune_DeviceSettings","RolesLandingMenuAsset"],["Microsoft_Intune_DeviceSettings","SoftwareUpdatesMenuAsset"],["Microsoft_Intune_DeviceSettings","TroubleshootBladeAsset"],["Microsoft_Intune_Workflows","SecurityBaselineAsset"])},],search:[{id:"AccountPortal",icon:c.BillingHub(),link:"{accountPortal}subscriptions"},{id:"TemplateDeployment",icon:c.Module(),link:"#create/Microsoft.Template"},],resourceTypesExcludedFromBrowse:[{types:["microsoft.compute/virtualmachines/extensions","microsoft.insights/alertrules","microsoft.insights/autoscalesettings","microsoft.web/certificates",{resourceType:"microsoft.sql/servers/databases",kinds:{system:!0,"v2.0,system":!0,"v12.0,system":!0}},]},],mergedAssetTypes:[s(["Microsoft_Azure_Compute","VirtualMachine"],["Microsoft_Azure_Classic_Compute","VirtualMachine"]),s(["Microsoft_Azure_Storage","StorageAccount"],["Microsoft_Azure_Storage","ClassicStorageAccount"]),s(["Microsoft_Azure_DataFactory","DataFactory"],["Microsoft_Azure_DataFactory","DataFactoryv2"]),].filter((function(n){return!!n}))})}var h=i.Base.Constants,o=h.AssetNames,e=h.ExtensionNames,c=i.Base.Images.Polychromatic,t=r.getAssetTypes,s=r.getMergedAssetType,f=e.Hubs,l=e.Marketplace,u=e.Websites,a=e.Resources;n.getCuration=v})(u||(u={})),u}))