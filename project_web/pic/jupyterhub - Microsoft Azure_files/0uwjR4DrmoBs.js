define("MsPortalImpl/UI/Compositions/UI.Composition.BladeOpener.Provisioning",["require","exports","f","i","o","FxInternal/Di","FxHubs/HubsSettingsSchema","FxHubs/MarketplaceRpc","MsPortalImpl/Services/Services.Settings"],(function(n,t,i,r,u,f,e,o,s){"use strict";function c(n){var t=h(n);return t&&t.type===19792}function l(n){var t=n.marketplaceOptions,s=n.marketplaceResults,f=n.inputs,h=Q.promise((function(n){var i=f&&f._marketplaceContext;return i?(delete f._marketplaceContext,n(Q({createFlow:null,marketplaceContext:i}))):(!t||!t.marketplaceGalleryItemId)&&!s?n(Q(null)):(s||o.getCreateFlow(t)).then((function(t){var e=t.bladeSelection.detailBladeInputs,f,o;return(i=e._marketplaceContext,delete e._marketplaceContext,i)?n(Q({createFlow:null,marketplaceContext:i})):(f=e.internal_bladeCallerParams,!f)?n(Q(null)):(o=u.keys(f).reduce((function(n,t){return n[t]=r.fromSerializableObject(f[t]),n}),{}),n(Q({createFlow:o,marketplaceContext:null})))}))})),c=a.querySettings({store:6,keys:[e.Keys.deploymentsLastUsedLocations,e.Keys.createLauncherLastUsedSubscriptionId,]}).then((function(n){var t=n[e.Keys.createLauncherLastUsedSubscriptionId];return{subscriptionIds:t?[t]:[],locationNames:u.keys(n[e.Keys.deploymentsLastUsedLocations]||{}).sort((function(t,r){return i.compare(n[t],n[r])})),resourceGroupNames:null}}));return Q.spread([c,h],(function(n,t){var u={initialValues:n},c=t||{},f=c.marketplaceContext,e=c.createFlow,l,o,s,h,r,a;return f?(u=i.extend2(u,f),n.resourceGroupNames=f.resourceGroupName&&[f.resourceGroupName]):e&&(o=e.providerConfig,s=o.provisioningConfig,delete o.provisioningConfig,delete e.providerConfig,h=s.startboardProvisioningInfo,r=s.galleryCreateOptions,l=i.extend(e,o),u=i.extend(u,{telemetryId:r.launchingContext.telemetryId,marketplaceItem:i.extend2(r.galleryItem,{deploymentFragmentFileUris:r.deploymentFragmentFileUris,deploymentName:r.deploymentName,deploymentTemplateFileUris:r.deploymentTemplateFileUris,launchingContext:r.launchingContext,uiMetadata:l}),provisioningConfig:{dontDiscardJourney:s.dontDiscardJourney,dashboardPartReference:{dashboardPartKeyId:h.startboardPartKeyId,partName:h.startboardPart.name,options:{extensionName:h.startboardPart.extension},parameters:null}}}),n.resourceGroupNames=[r.resourceGroupName]),a=u.telemetryId,a||i.extend(u,{telemetryId:i.getUniqueId()}),{_provisioningContext:u}}))}function v(){var n=[],t;return n[2]=function(n,r){var u=r.bladeRequest.bladeReference,f,e;if(c(u))return f=h(u,null).marketplaceId,e=(u.parameters||{}).internal_bladeCallerParams,t=l({marketplaceOptions:{marketplaceGalleryItemId:f,launchingContext:{telemetryId:i.newGuid(),source:[]}},marketplaceResults:e,inputs:u.parameters})},n[4]=function(n,r){if(c(r.bladeRequest.bladeReference))return t.then((function(n){return r.selection.detailBladeInputs=i.extend2(n,r.selection.detailBladeInputs)}))},n}u.defineProperty(t,"__esModule",{value:!0});var h=r.shellInterface,a=f.container.get(s.SettingsManager);t.getMarketplaceItemAndInitialValues=l;t.openBladeHandler=v}))