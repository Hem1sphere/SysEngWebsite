"use strict";

var queryMap = (function () {
  var query = window.location.search.substring(1);
  var parameterList = query.split("&");
  var map = {};
  for (var i = 0; i < parameterList.length; i++) {
    var pair = parameterList[i].split("=");
    map[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
  }
  return map;
})();

function format (fmtstr) {
  var args = Array.prototype.slice.call(arguments, 1);
  return fmtstr.replace(/\{(\d+)\}/g, function (match, index) {
    return args[index];
  });
}

function isEmptyOrSpaces(str){
  return str === null || str.match(/^ *$/) !== null;
}

function getQueryParameter(name) {
  return queryMap[name] || "";
}

function getQueryParametersPrefix(prefix) {
  return Object.keys(queryMap).filter(function (queryKey) {
    return queryKey.indexOf(prefix) === 0;
  }).map(function (queryKey) {
    return { name: queryKey, value: queryMap[queryKey] }
  })
}

var term,
  consoleUri,
  termId,
  userRootDirectory,
  codeEditorDirectory,
  accessToken,
  tenantId,
  getTokenInterval,
  userSettings,
  embed = getQueryParameter('embed') === 'true',
  popout = getQueryParameter('popout') === 'true',
  language = getQueryParameter('l').split('.')[0],
  cloudshellVersion = getQueryParameter('version');

if (embed) {
  document.documentElement.classList.add('embed');
}

var trustedParentOrigin = getQueryParameter("trustedAuthority");
var cloudShellStorageString = "cloud-shell-storage";
var appInsights;

var fontSizes = {
  "small": "13",
  "medium": "16",
  "large": "21"
};
var fontStyles = {
  "monospace": "monospace",
  "courier": "Courier New, courier, monospace"
}
var backgroundColors = {
  "bash": "#000000",
  "pwsh": "#012456",
  "drag": "#4c4c4c",
}

var tokenAudiences = {
  "https://management.core.windows.net/": "arm",
  "https://management.azure.com/": "arm",
  "https://graph.windows.net/": "graph",
  "https://vault.azure.net": "keyvault",
  "https://datalake.azure.net/": "datalake",
  "https://outlook.office365.com/": "office365",
  "https://graph.microsoft.com/": "microsoft.graph",
  "https://batch.core.windows.net/": "azurebatch",
  "https://analysis.windows.net/powerbi/api": "powerbi",
  "https://storage.azure.com/": "storage"
};

var currentFontSize;
var currentFontStyle;

var linksToOpen = {};
var defaultHeight = true;

const OsType = {
  Linux : "linux",
  Windows : "windows",

  IsLinux : function (osType) {
    return (typeof osType !== "undefined" && osType !== null && osType.toLowerCase() === OsType.Linux);
  },
  IsWindows : function (osType) {
    return (typeof osType !== "undefined" && osType !== null && osType.toLowerCase() === OsType.Windows);
  }
}

const ShellType = {
  Bash : "bash",
  PowerShellCore : "pwsh",

  IsPowerShell : function (shellType) {
    return (typeof shellType !== "undefined"
            && shellType !== null
            && shellType.toLowerCase() === ShellType.PowerShellCore);
  },
  MappingFromOsType : function (osType) {
    if(osType) {
      return (OsType.IsWindows(osType) ? ShellType.PowerShellCore : ShellType.Bash);
    } 
    else {
      return null;
    }
  }
}

// The prefererence of osType and shellType.
var osTypeSelection = OsType.Linux;
var shellTypeSelection = ShellType.Bash;

var screenReaderMode;

// used for handling delayed resizing
var rtime;
var timeout = false;
var delta = 200;
// Initialize terminal idle timeout to 20 mins.
var terminalIdleTimeout = 20;

var terminalContainer;

var ConnectionState = {
  NotConnected: 0,
  Connecting: 1,
  Connected: 2
};

var consoleApiVersion = '2018-10-01';

var storage = {};

var logger;
var fileManager;

(function () {
  if (typeof window.CustomEvent === "function") {
    return false;
  }

  function CustomEvent(event, params) {
    params = params || { bubbles: false, cancelable: false, detail: undefined };
    var evt = document.createEvent('CustomEvent');
    evt.initCustomEvent(event, params.bubbles, params.cancelable, params.detail);
    return evt;
  }

  CustomEvent.prototype = window.Event.prototype;
  window.CustomEvent = CustomEvent;
})();

function userBrowserIE() {
  return (navigator.userAgent.indexOf("MSIE") > 0 || navigator.userAgent.indexOf("Trident/") > 0);
}

function userBrowserFirefox() {
  return navigator.userAgent.indexOf("Firefox") > 0;
}

function setupParentMessage() {
  // --------------------------------------- Security Code ---------------------------------------
  var allowedParentFrameAuthorities = ["localhost:3000", "localhost:55555", "azconsole-df.azurewebsites.net", "cloudshell-df.azurewebsites.net", "portal.azure.com", "rc.portal.azure.com", "ms.portal.azure.com", "docs.microsoft.com", "shell.azure.com", "ms.shell.azure.com", "rc.shell.azure.com"];

  function handleToken(evt) {

    var authToken = evt.data.message;

    if (!authToken) {
      console.error("No auth token in event, event: " + JSON.stringify(evt));
      $(terminalContainer).html("Sorry, something went wrong.");
      return;
    }

    switch (evt.data.audience) {
      case '':
      case 'arm':
        accessToken = authToken;
        tenantId = jwt_decode(accessToken).tid;
        if(popout) {
          populateDirectoryInfo(jwt_decode(accessToken));
        }

        createOrUpdateTerminal();
        postToken(authToken);
        break;
      case 'graph':
      case 'keyvault':
      case 'datalake':
      case 'office365':
      case 'azurebatch':
      case 'microsoft.graph':
      case 'powerbi':
      case 'storage':
        postToken(authToken);
        break;
      default:
        console.error("Audience '" + evt.data.audience + "' cannot be handled.");
    }
  }

  function postToken(token) {
    if (consoleUri) {
      var method = 'POST';

      var targetUri = consoleUri + '/accessToken';
      var start = Date.now();
      var newToken = { token: token };

      $.ajax(targetUri,
        {
          method: method,
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': accessToken,
            'Accept-Language': language
          },
          data: JSON.stringify(newToken)
        })
        .fail(function (jqXHR, textStatus, errorThrown) {
          logger.clientRequest('ACC.POST.TOKEN', {}, Date.now() - start, method, "", null, null, null, null, jqXHR.status);
        })
        .done(function (data, textStatus, jqXHR) {
          logger.clientRequest('ACC.POST.TOKEN', {}, Date.now() - start, method, "", null, null, null, null, jqXHR.status);
        });
    }
  }

  var isTrustedOrigin = (function () {
    var trustedAuthority = (trustedParentOrigin.split("//")[1] || "").toLowerCase();

    return allowedParentFrameAuthorities.some(function (origin) {
      // Verify that the requested trusted authority is either an allowed origin or is a
      // subdomain of an allowed origin.
      return origin === trustedAuthority
        || trustedAuthority.substr(-origin.length) === origin;
    });
  })();

  if (!isTrustedOrigin) {
    var errorMessage = "The origin '" + trustedParentOrigin + "' is not trusted.";
    console.error(errorMessage);
    throw new Error(errorMessage);
  }

  function postMessageHandler(evt) {
    if (evt.origin !== trustedParentOrigin) {
      return;
    }

    var data = evt.data || {};
    if (data.signature === "portalConsole") {
      switch (data.type) {
        case "postToken":
          handleToken(evt);
          break;
        case "restart":
          restartTerminal();
          break;
      }
    }
  }

  window.addEventListener("message", postMessageHandler, false);

  getTokens();
}

function createOrUpdateTerminal() {
  if (!term) {
    createTerminal();
  }
  else if (term.connectionState === ConnectionState.Connecting) {
    window.setTimeout(createOrUpdateTerminal, 500);
  }
  else if (term.connectionState === ConnectionState.Connected) {
    window.setTimeout(keepAlive, 500);
  }
  else {
    provisionConsole();
  }
}

function getARMEndpoint() {
  if (getQueryParameter('arm')) {
    return getQueryParameter('arm');
  }
  else {
    return "https://management.azure.com"
  }
}

function getConsoleUri() {
  var resourceId = '/consoles/default';
  return getARMEndpoint() + '/providers/Microsoft.Portal' + getAzureConsoleProviderLocation() + resourceId + '?api-version=' + consoleApiVersion;
}

function getAzureConsoleProviderLocation() {
  var providerLocation = '';
  if (getQueryParameter('feature.azureconsole.providerlocation')) {
    providerLocation = '/locations/' + getQueryParameter('feature.azureconsole.providerlocation');
  }
  return providerLocation;
}

function showTerminal() {
  if (!embed) {
    $('#terminal-header').show();
  }
  $('#terminal-container').show();
  $('#terminal-dialog-back').hide();
}

function hideTerminal() {
  $('#terminal-dialog-back').show();
  $('#terminal-header').hide();
  $('#terminal-container').hide();
}

function saveSessionConsoleShellType(shellType) {
  window.sessionStorage.setItem('consoleShellType', shellType);
}

function getAndRemoveSessionConsoleShellType() {
  var shellType = window.sessionStorage.getItem('consoleShellType');
  window.sessionStorage.removeItem('consoleShellType');
  return shellType;
}

function showSwitchShellTypeConfirmation(shellType) {
  if(ShellType.IsPowerShell(shellType)) {
    $("#switch-shell-ps-head").show();
    $("#switch-shell-ps-text").show();
    $("#switch-shell-bash-head").hide();
    $("#switch-shell-bash-text").hide();
  } else {
    $("#switch-shell-ps-head").hide();
    $("#switch-shell-ps-text").hide();
    $("#switch-shell-bash-head").show();
    $("#switch-shell-bash-text").show();
  }

  $('#confirm-switch-shell').off('keypress click keydown');
  $('#cancel-switch-shell').off('keydown');
  enterClickHandler($("#confirm-switch-shell"), function () {
    saveSessionConsoleShellType(shellType);
    $("#terminal-restart-confirmation").hide();
    $("#terminal-switch-shell-confirmation").hide();
    showTerminal();
    switchTerminal();
  });

  arrowKeyHandler($("#confirm-switch-shell"), "right", function () {
    $("#cancel-switch-shell").focus();
  });

  arrowKeyHandler($("#cancel-switch-shell"), "left", function () {
    $("#confirm-switch-shell").focus();
  });
  
  hideTerminal();
  $("#terminal-storage-creation").hide();
  $("#terminal-switch-shell-confirmation").show();
  $("#confirm-switch-shell").focus();
}

function updateFileServiceLink() {
  var storageAccountResourceId = userSettings.storageProfile.storageAccountResourceId;
  var fileShareName = userSettings.storageProfile.fileShareName;
  var cloudShellLink = "https://portal.azure.com/#@" + tenantId + "/resource/" + storageAccountResourceId + "/fileList";
  enterClickHandler($("#file-upload-blade"), function() {
    if(popout) {
      window.open(cloudShellLink, '_blank');
    }
    else {
      postMessageHelper("openFileShare", { resourceId: storageAccountResourceId, fileShare: fileShareName });
    }
  });
}

function checkUserSettings(callback) {
  var userLocation, assignedLocation, subscriptions, userLocationCode, locationName, storageAccountResourceId, resourceGroups, storageAccounts;
  var retryLimit = 3, retryLimitForGetStorageAccount = 20;
  var showAdvancedSettings = false;
  var inputError = false;

  $(".advanced-link-text").off("click");
  $("#terminal-storage-creation-subscriptions").off("change");
  $("#resource-group-select-entry").off("change");

  $(".advanced-link-text").on("click", toggleAdvancedSettings);
  $('#terminal-storage-creation-subscriptions').change(function () {
    validateStorageSupport();
    getResourceGroups(0, $('#terminal-storage-creation-subscriptions').val());
  });

  $("#resource-group-select-entry").change(function () {
    if (!$("#create-new-rg").prop('checked')) {
      getStorageAccounts(0, $('#terminal-storage-creation-subscriptions').val(), $("#resource-group-select-entry").val());
    }
  });

  hideTerminal();
  getUserSettings(0);

  function showUnknownFailure(messageText) {
    if (messageText) {
      $("#terminal-dialog-unknown-failure .terminal-dialog-text").html(messageText);
    }
    $("#terminal-dialog-unknown-failure").show();
    $("#unknown-failure-close").focus();
  }


  function handleShellType(shellType, callback) {
    if (!shellType || shellType.toLowerCase() === "notspecified") {
      hideTerminal();
      $("#terminal-ostype-selection").show()
      $("#os-bash-option").focus();
      $('.os-option').off('keypress click');
      $('.os-option').on('keypress click', function (e) {
        shellType = $(this).attr('shell-type');

        $("#terminal-ostype-selection").hide();
        setupShellType(shellType);
        callback();
      });
    }
    else {
      setupShellType(shellType);
      callback();
    }
  }

  function setupShellType(userSettingShellType) {
    var featureOsType = getQueryParameter("feature.azureconsole.ostype");
    var featureShellType = ShellType.MappingFromOsType(featureOsType);

    shellTypeSelection = getAndRemoveSessionConsoleShellType() || featureShellType || userSettingShellType;

    var showList = [];
    var hideList = [];
    var otherShellType = '';
    var selectOtherShellType = '';

    if (ShellType.IsPowerShell(shellTypeSelection)) {
      $('#powershellstyle').prop('disabled', false);
      updateTerminalBackgroundColor(ShellType.PowerShellCore);
      $('#environment-selection').html("PowerShell");
      showList = ['#bash-terminal-selector', '#terminal-psdoc'];
      hideList = ['#powershell-terminal-selector', '#terminal-clidoc'];
      otherShellType = ShellType.Bash;
      selectOtherShellType = '#bash-terminal-selector';
    }
    else {
      $('#powershellstyle').prop('disabled',true);
      updateTerminalBackgroundColor(ShellType.Bash);
      $('#environment-selection').html("Bash");
      showList = ['#powershell-terminal-selector', '#terminal-clidoc'];
      hideList = ['#bash-terminal-selector', '#terminal-psdoc'];
      otherShellType = ShellType.PowerShellCore;
      selectOtherShellType = '#powershell-terminal-selector';
    }

    for (var i = 0; i < showList.length; i++) {
      $(showList[i]).show();
    }

    for (var i = 0; i < hideList.length; i++) {
      $(hideList[i]).hide();
    }

    $(selectOtherShellType).off('keypress click');
    enterClickHandler($(selectOtherShellType), function (e) {
      showSwitchShellTypeConfirmation(otherShellType);
    });

    // Add OS and shellType data to logger.
    logger.addBaseEventData({ osType: osTypeSelection, shellType: shellTypeSelection });
  }

  function getUserSettings(retryCount) {
    loadUserSettings(
      function (jqXHR, textStatus, errorThrown, start, targetUri) {
        if (jqXHR.status === 404) {
          locationName = jqXHR.getResponseHeader("x-ms-console-required-location");
          storage.location = userLocation = assignedLocation = locationName.replace(/ /g, "").toLowerCase();
          userLocationCode = jqXHR.getResponseHeader("x-ms-console-required-location-code");
          handleShellType(null, function () { getSubscriptions(0); });
        }
        else if (jqXHR.responseJSON.error.code === 'UserNotEnabledForPreview') {
          window.location.replace("rollingout.html" + window.location.search);
        }
        else if (jqXHR.status > 399 && jqXHR.status < 500) {
          var message = (!!jqXHR.responseJSON && !!jqXHR.responseJSON.error && !!jqXHR.responseJSON.error.message) ? jqXHR.responseJSON.error.message : null;
          hideTerminal();
          showUnknownFailure(message);
        }
        else {
          logger.clientRequest('ACC.USERSETTINGS.GET', {}, Date.now() - start, 'GET', targetUri, null, null, null, null, jqXHR.status);
          if (++retryCount < retryLimit) {
            getUserSettings(retryCount);
          }
          else {
            hideTerminal();
            showUnknownFailure();
          }
        }
      },
      function (data, textStatus, jqXHR) {
        userSettings = data.properties;

        if(popout) {
          displayUserSettings();
        }
        showTerminal();
        updateFontSize(userSettings.terminalSettings.fontSize.toLowerCase());
        updateFontStyle(userSettings.terminalSettings.fontStyle.toLowerCase());
        locationName = userSettings.preferredLocation;
        storage.location = userLocation = assignedLocation = locationName.replace(/ /g, "").toLowerCase();
        userLocationCode = jqXHR.getResponseHeader("x-ms-console-required-location-code");
        storageAccountResourceId = userSettings.storageProfile.storageAccountResourceId;
        updateFileServiceLink();
        handleShellType(userSettings.preferredShellType, function () {
          if (data.properties.storageProfile != null) {
            callback();
          }
          else {
            getSubscriptions(0);
          }
        });
      },
      function () {}
    );
  }

  function getSubscriptions(retryCount) {
    var method = 'GET';
    var targetUri = getARMEndpoint() + '/subscriptions?api-version=2016-06-01';
    var start = Date.now();

    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.SUBSCRIPTIONS.LIST', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        if (++retryCount < retryLimit) {
          getSubscriptions(retryCount);
        }
        else {
          showUnknownFailure();
        }

      })
      .done(function (data, textStatus, jqXHR) {
        subscriptions = data.value || [];
        subscriptions = subscriptions.filter(function (s) { return s.state === "Enabled"; });
        if (subscriptions.length === 0) {
          $("#terminal-dialog-nosubscription").show();
          $("#nosubscription-close").focus();
        }
        else {
          populateSubscriptions();
          $('#terminal-storage-creation-text').show();
          $('#terminal-dialog-rg_storage-creation-failure').hide();
          $('#terminal-storage-creation-footer').show();
          $('.message-storage-subscriptions-choice').show();
          $("#terminal-storage-creation").show();
          $("#terminal-storage-creation-subscriptions").focus();
        }
      });
  }

  function validateStorageSupport() {
    var index = $('#terminal-storage-creation-subscriptions')[0].selectedIndex;
    if(index < 0 ) { 
      return;
    }

    var quotaId = subscriptions[index].subscriptionPolicies.quotaId;
    if(quotaId == 'DreamSpark_2015-02-01')
    {
      $("#terminal-storage-creation-create").prop("disabled", true);
      $("#terminal-storage-creation-disabled-note").show();
      $("#show-advanced").hide();
      $("#hide-advanced").hide();
    }
    else
    {
      $("#terminal-storage-creation-create").prop("disabled", false);
      $("#terminal-storage-creation-disabled-note").hide();
      $("#show-advanced").show();
      $("#hide-advanced").hide();
    }
  }

  function getResourceGroups(retryCount, sid) {
    var method = 'GET';
    var targetUri = getARMEndpoint() + '/subscriptions/' + sid + '/resourceGroups?api-version=2017-05-10';
    var start = Date.now();

    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.RESOURCEGROUPS.LIST', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        if (++retryCount < retryLimit) {
          getResourceGroups(retryCount, sid);
        }
        else {
          showUnknownFailure();
        }
      })
      .done(function (data, textStatus, jqXHR) {
        populateResourceGroups(data);
      });
  }

  function getStorageAccounts(retryCount, sid, rg) {
    var method = 'GET';
    var targetUri = getARMEndpoint() + '/subscriptions/' + sid + '/resourceGroups/' + rg + '/providers/Microsoft.Storage/storageAccounts?api-version=2017-06-01';
    var start = Date.now();
    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.STORAGEACCOUNTS.LIST', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        if (++retryCount < retryLimit) {
          getStorageAccounts(retryCount, sid, rg);
        }
        else {
          showUnknownFailure();
        }
      })
      .done(function (data, textStatus, jqXHR) {
        populateStorageAccounts(data);
      });
  }

  function disableExisting(existing, options, message) {
    existing.attr("disabled", true);
    existing.prop("checked", false);
    options.attr("data-toggle", "tooltip");
    options.attr("title", message);
  }

  function enableExisting(existing, options) {
    existing.attr("disabled", false);
    options.removeAttr("data-toggle");
    options.removeAttr("title");
  }

  function populateDropdown(options, selection) {
    options.sort(function (a, b) {
      return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
    });
    $(selection).find('option').remove();
    $.each(options, function (i, item) {
      $(selection).append($('<option>', {
        value: item.name,
        text: item.name
      }));
    });
  }

  function updateStorageAccountButtons() {
    var tooltipMessage = $("#file-share-buttons").attr("tooltip");
    if ($("#create-new-sa").prop('checked')) {
      $("#storage-account-text-entry").show();
      $("#storage-account-select").hide();
      $("#create-new-fs").prop("checked", true);
      disableExisting($("#use-existing-fs"), $('#file-share-buttons'), tooltipMessage);
    }
    else {
      $("#storage-account-text-entry").hide();
      $("#storage-account-select").show();
      enableExisting($("#use-existing-fs"), $('#file-share-buttons'));
    }
  }

  function updateResourceGroupButtons() {
    var tooltipMessage = $("#storage-account-buttons").attr("tooltip1");
    if ($("#create-new-rg").prop('checked')) {
      disableExisting($("#use-existing-sa"), $("#storage-account-buttons"), tooltipMessage);
      $("#create-new-sa").prop("checked", true);
      updateStorageAccountButtons();
      $("#resource-group-text-entry").show();
      $("#resource-group-select").hide();
    }
    else {
      $("#resource-group-text-entry").hide();
      $("#resource-group-select").show();
      enableExisting($("#use-existing-sa"), $("#storage-account-buttons"));
      $("#resource-group-select-entry").change();
    }
  }

  function populateLocationDropdown(options, selection) {
    var locations = Object.keys(options).sort();
    $(selection).find('option').remove();
    locations.forEach(function (location) {
      $(selection).append($('<option>', {
        value: location,
        text: options[location]
      }));
    });
  }

  function toggleAdvancedSettings() {
    showAdvancedSettings = !showAdvancedSettings;
    if (showAdvancedSettings) {
      $('#terminal-storage-creation-intro').hide(1000);
      $("#show-advanced").hide();
      $("#hide-advanced").show();
      $(".message-storage-subscriptions-choice.row").animate({ 'padding-top': '0px' }, 1000);
      $('#advanced-options').show(1000);
      $("#subscription-selection-prompt").animate({ 'margin-left': '0px' }, 1000);
      populateLocationDropdown(locationDisplayNames, $("#terminal-storage-select-location"));
      $("#terminal-storage-select-location").val(userLocation);      
      $("#location-selection-prompt").show(1000);
      $("#terminal-storage-creation-content").stop().animate({
        scrollTop: $("#terminal-storage-creation-content")[0].scrollHeight
      }, 1000);
      if ($("#location-note").attr("localized") === "false") {
        $("#location-note").html(format($("#location-note").text(), $("#location-note").attr("redundancy-link")));
        $("#location-note").attr("localized", "true");
      }
      $('.option-buttons').change(function () {
        var updatedButtonLabel;
        if ($("#use-existing-fs").prop('checked') && $("#use-existing-sa").prop('checked') && $("#use-existing-rg").prop('checked')) {
          updatedButtonLabel = $("#terminal-storage-creation-create").attr("attach-storage");
        }
        else {
          updatedButtonLabel = $("#terminal-storage-creation-create").attr("create-storage");
        }
        $("#terminal-storage-creation-create").text(updatedButtonLabel);
      });
      $("#terminal-storage-select-location").change(function() {
        userLocation =  $("#terminal-storage-select-location").val();
        getStorageAccounts(0, $('#terminal-storage-creation-subscriptions').val(), $("#resource-group-select-entry").val());
      });
      $("#storage-account-buttons").change(function () {
        updateStorageAccountButtons();
        updateCreateButton();
      });
      $("#resource-group-buttons").change(function () {
        updateResourceGroupButtons();
        updateCreateButton();
      });
      getResourceGroups(0, $('#terminal-storage-creation-subscriptions').val());
      updateCreateButton();
    }
    else {
      if (!inputError) {
        $('#terminal-storage-creation-intro').show(1000);
        $(".message-storage-subscriptions-choice.row").animate({ 'padding-top': '10px' }, 1000);
      }
      userLocation = assignedLocation;
      $("#show-advanced").show();
      $("#hide-advanced").hide();
      $("#location-selection-prompt").hide(1000);
      $("#subscription-selection-prompt").animate({ 'margin-left': '238px' }, 1000);
      $('#advanced-options').hide(1000);
      $('.option-buttons').off('change');
      $("#storage-account-buttons").off('change');
      $("#resource-group-buttons").off('change');
      $("#terminal-storage-creation-create").prop("disabled", false);
    }
    $("#terminal-storage-creation-create").text($("#terminal-storage-creation-create").attr("create-storage"));
  }

  function populateSubscriptions() {
    var selection = $('#terminal-storage-creation-subscriptions');
    subscriptions.sort(function (a, b) {
      var nameA = a.displayName.toUpperCase();
      var nameB = b.displayName.toUpperCase();

      return nameA < nameB ? -1 : (nameA > nameB ? 1 : 0);
    });

    var options = subscriptions;
    for (var i = 0; i < options.length; i++) {
      if ((i + 1 < options.length && options[i].displayName === options[i + 1].displayName)
        || (i > 0 && options[i].displayName === options[i - 1].displayName)) {
        options[i].optionName = options[i].displayName + ' (' + options[i].subscriptionId + ')';
      }
      else {
        options[i].optionName = options[i].displayName;
      }
    }

    $(selection).find('option').remove();
    $.each(options, function (i, item) {
      $(selection).append($('<option>', {
        value: item.subscriptionId,
        text: item.optionName
      }));
    });
    selection.change();
  }

  function populateResourceGroups(resourceGroups) {
    var selection = $("#resource-group-select-entry");
    var options = resourceGroups.value;
    var tooltipMessage = $("#resource-group-buttons").attr("tooltip");
    if (options.length === 0) {
      disableExisting($("#use-existing-rg"), $("#resource-group-buttons"), tooltipMessage);
      $("#create-new-rg").prop("checked", true);
      updateResourceGroupButtons();
    }
    else {
      enableExisting($("#use-existing-rg"), $("#resource-group-buttons"));
      populateDropdown(options, selection);
      selection.change();
    }
  }

  function populateStorageAccounts(storageAccounts) {
    var selection = $("#storage-account-select-entry");
    var options = storageAccounts.value;
    var tooltipMessage = $("#storage-account-buttons").attr("tooltip2");
    options = options.filter(function (s) {
      return s.location === userLocation && (s.sku.name === "Standard_LRS" || s.sku.name === "Standard_GRS" || s.sku.name === "Standard_ZRS") && s.sku.tier === "Standard";
    });
    if (options.length === 0) {
      disableExisting($("#use-existing-sa"), $("#storage-account-buttons"), tooltipMessage);
      $("#create-new-sa").prop("checked", true);
      updateStorageAccountButtons();
    }
    else {
      enableExisting($("#use-existing-sa"), $("#storage-account-buttons"));
      populateDropdown(options, selection);
    }
  }

  function handleQuit(evt) {
    $(evt.target).closest(".terminal-dialog").hide();
    postMessageHelper("close");
  }

  function resetCreateStorageDialog() {
    $('#terminal-storage-creation-subscriptions').prop("disabled", false);

    $("#terminal-storage-creation-create").prop("disabled", false);
    $("#terminal-storage-creation-create").text($("#terminal-storage-creation-create").attr("create-storage"));
  }

  function handleCreateStorage(evt) {
    $("#terminal-storage-creation-create").prop("disabled", true);
    $("#terminal-storage-creation-create").text($("#terminal-storage-creation-create").attr("creating"));
    $('#terminal-storage-creation-subscriptions').prop("disabled", true);

    var sid = $('#terminal-storage-creation-subscriptions').val();
    storage.subscriptionId = sid;
    createResourceGroup(sid);
  }

  $("#terminal-storage-creation-create").off("keypress click keydown");
  $(".terminal-dialog-quit").off('keypress click keydown');

  enterClickHandler($("#terminal-storage-creation-create"), function () {
    showAdvancedSettings = !($("#advanced-options").css("display") === "none");
    handleCreateStorage();
  });

  arrowKeyHandler($("#terminal-storage-creation-create"), "right", function () {
    $("#terminal-storage-creation-close").focus();
  });

  arrowKeyHandler($("#terminal-storage-creation-close"), "left", function () {
    $("#terminal-storage-creation-create").focus();
  });

  enterClickHandler($(".terminal-dialog-quit"), function (e) {
    handleQuit(e);
  });

  resetCreateStorageDialog();

  function storageCreationFailed(status, error) {
    resetCreateStorageDialog();
    inputError = true;
    $('#terminal-storage-creation-intro').hide();
    $('#terminal-storage-creation').hide();
    $('#standard-header').hide();
    $("#time-out-body").html(format($("#time-out-body").html(), terminalIdleTimeout));
    $("#creation-failure-error-code").html(format($("#creation-failure-error-code").html(), status));
    $("#creation-failure-error-message").html(error);
    $('.message-storage-subscriptions-choice').show();
    $('#error-header').show();
    $('#terminal-storage-creation').show();
    $('#terminal-storage-creation-subscriptions').focus();
    $(".message-storage-subscriptions-choice.row").css({ 'padding-top': '0px' });
    $('#terminal-dialog-rg_storage-creation-failure').show();
    $('#terminal-storage-creation-footer').hide();
    $("#terminal-storage-creation").show();
    $("#terminal-storage-creation-content")[0].scrollTop = 0;
  }

  function getProviderRegistrationState(retries, sid, fnCreateStorageAccount, resourceProviderNamespace) {
    var method = 'GET';
    var targetUri = getARMEndpoint() + '/subscriptions/' + sid + '/providers/' + resourceProviderNamespace + '?api-version=2016-06-01';
    var start = Date.now();
    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.RESOURCEPROVIDER.GET', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        if (retries === 8) {
          storageCreationFailed(jqXHR.status, jqXHR.responseText);
        }
        else {
          window.setTimeout(function () { getProviderRegistrationState(retries + 1, sid, fnCreateStorageAccount, resourceProviderNamespace) }, 3000);
        }
      })
      .done(function (data, textStatus, jqXHR) {
        if (data.registrationState === "Registered" || retries === 8) {
          fnCreateStorageAccount();
        }
        else {
          window.setTimeout(function () { getProviderRegistrationState(retries + 1, sid, fnCreateStorageAccount, resourceProviderNamespace) }, 3000);
        }
      });
  }

  function registerStorageResourceProvider(sid, fnCreateStorageAccount) {
    var method = 'POST';
    var resourceProviderNamespace = 'Microsoft.Storage'
    var targetUri = getARMEndpoint() + '/subscriptions/' + sid + '/providers/' + resourceProviderNamespace + '/register?api-version=2016-06-01';
    var start = Date.now();
    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.RESOURCEPROVIDER.REGISTER', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        storageCreationFailed(jqXHR.status, jqXHR.responseText);
      })
      .done(function (data, textStatus, jqXHR) {
        window.setTimeout(function () { getProviderRegistrationState(0, sid, fnCreateStorageAccount, resourceProviderNamespace) }, 3000);
      });
  }

  function createResourceGroup(sid) {
    var method = 'PUT';
    var resourceGroupName;
    if (!showAdvancedSettings) {
      resourceGroupName = cloudShellStorageString + '-' + userLocation;
    }
    else {
      if ($("#create-new-rg").prop('checked')) {
        resourceGroupName = $("#resource-group-text-entry").val();
      }
      else {
        resourceGroupName = $("#resource-group-select-entry").val();
      }
    }
    storage.resourceGroupName = resourceGroupName;
    var targetUri = getARMEndpoint() + '/subscriptions/' + sid + '/resourcegroups/' + resourceGroupName + '?api-version=2016-06-01';
    var start = Date.now();
    var locationObject = { location: userLocation };
    $.ajax(targetUri,
    {
      method: "GET",
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': accessToken,
        'Accept-Language': language
      }
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
      if (jqXHR.status === 404 && jqXHR.responseJSON && jqXHR.responseJSON.error && jqXHR.responseJSON.error.code === 'ResourceGroupNotFound') {
        $.ajax(targetUri,
          {
            method: method,
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json',
              'Authorization': accessToken,
              'Accept-Language': language
            },
            data: JSON.stringify(locationObject)
          })
          .fail(function (jqXHR, textStatus, errorThrown) {
            logger.clientRequest('ACC.RESOURCEGROUP.CREATE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
            storageCreationFailed(jqXHR.status, jqXHR.responseText);
          })
          .done(function (data, textStatus, jqXHR) {
            createStorageAccount(sid, resourceGroupName);
          });
      }
      else {
        logger.clientRequest('ACC.RESOURCEGROUP.GET', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
        storageCreationFailed(jqXHR.status, jqXHR.responseText);
      }
    })
    .done(function (data, textStatus, jqXHR) {
      createStorageAccount(sid, resourceGroupName);
    });
  }

  function createStorageAccount(sid, resourceGroupName) {
    var method = 'PUT';
    //storage account name restriction: 3-24 characters and must be lowercase alphanumeric
    var accountName;
    if (!showAdvancedSettings) {
      accountName = "cs" + userLocationCode;
      var len = 24 - accountName.length;
      accountName += sid.replace('-', '').substring(0, len);
      accountName = accountName.toLowerCase().replace(/[^a-z|0-9]/g, 'x');
    }
    else {
      if ($("#create-new-sa").prop('checked')) {
        accountName = $("#storage-account-text-entry").val();
      }
      else {
        accountName = $("#storage-account-select-entry").val();
      }
    }

    storage.storageAccountName = accountName;
    storageAccountResourceId = '/subscriptions/' + sid + '/resourcegroups/' + resourceGroupName + '/providers/Microsoft.Storage/storageAccounts/' + accountName;
    var targetUri = getARMEndpoint() + storageAccountResourceId + '?api-version=2017-10-01';
    var start = Date.now();
    var data = {
      location: userLocation,
      sku: { name: 'Standard_LRS' },
      kind: 'Storage',
      tags: { 'ms-resource-usage': 'azure-cloud-shell' },
      properties: {
        encryption: {
          services: {
            blob: { 'enabled': true },
            file: { 'enabled': true }
          },
          keySource: 'Microsoft.Storage'
        },
        supportsHttpsTrafficOnly: true
      }
    };
    var headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': accessToken,
      'Accept-Language': language
    };

    $.ajax(targetUri,
      {
        method: "GET",
        headers: headers
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        if (jqXHR.status === 404 && jqXHR.responseJSON && jqXHR.responseJSON.error && jqXHR.responseJSON.error.code === 'ResourceNotFound') {
        $.ajax(targetUri,
          {
            method: method,
            headers: headers,
            data: JSON.stringify(data)
          })
          .fail(function (jqXHR, textStatus, errorThrown) {
            logger.clientRequest('ACC.STORAGEACCOUNT.CREATE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
    
            if (jqXHR.status === 202) {
              window.setTimeout(function () { getStorageAccount(0); }, 3000);
            }
            else if (jqXHR.status === 409 && jqXHR.responseJSON && jqXHR.responseJSON.error && jqXHR.responseJSON.error.code === 'MissingSubscriptionRegistration') {
              registerStorageResourceProvider(sid, function () {
                createStorageAccount(sid, resourceGroupName);
              });
            }
            else {
              storageCreationFailed(jqXHR.status, jqXHR.responseText);
            }
          })
          .done(function (data, textStatus, jqXHR) {
            if (jqXHR.status === 202) {
              window.setTimeout(function () { getStorageAccount(0); }, 3000);
            }
            else {
              createUserSettings();
            }
          });
        }
        else {
          logger.clientRequest('ACC.STORAGEACCOUNT.GET', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
          storageCreationFailed(jqXHR.status, jqXHR.responseText);
        }
      })
      .done(function (data, textStatus, jqXHR) {
        if (data.kind === 'BlobStorage') {
          storageCreationFailed($("#terminal-dialog-rg_storage-creation-failure-reason").attr("failed"), $("#creation-failure-error-message").attr("blob-error"));
        }
        else if (data.sku === 'Standard_RAGRS' || data.sku === 'Premium_LRS') {
          storageCreationFailed($("#terminal-dialog-rg_storage-creation-failure-reason").attr("failed"), format($("#creation-failure-error-message").attr("sku-error"), data.sku));
        }
        else {
          if(data.tags["ms-resource-usage"] !== 'azure-cloud-shell') {
            data.tags["ms-resource-usage"] = 'azure-cloud-shell';
            data = {
              tags: data.tags
            }
            $.ajax(targetUri,
              {
                method: 'PATCH',
                headers: headers,
                data: JSON.stringify(data)
              })
              .fail(function (jqXHR, textStatus, errorThrown) {
                console.error('Error updating storage account tags: ' + errorThrown);
              })
              .always(function () {
                createUserSettings();
              });
          }
          else {
            createUserSettings();
          }
        }
      });
  }

  function getStorageAccount(retriesForGetStorageAccount, startTime) {
    var targetUri = getARMEndpoint() + storageAccountResourceId + '?api-version=2016-12-01';
    var method = 'GET';

    startTime = startTime || Date.now();

    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        },
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        window.setTimeout(function () { getStorageAccount(retriesForGetStorageAccount + 1, startTime) }, 3000);
      })
      .done(function (data, textStatus, jqXHR) {
        if (data.properties.provisioningState === "Succeeded") {
          createUserSettings();
        }
        else if (data.properties.provisioningState === "Failed") {
          logger.clientTelemetry('ACC.STORAGEACCOUNT.PUT.FAILURE', { storageAccount: storageAccountResourceId, provisioningState: data.properties.provisioningState }, { retryCount: retriesForGetStorageAccount }, Date.now() - startTime);
          storageCreationFailed($("#terminal-dialog-rg_storage-creation-failure-reason").attr("failed"), format($("#creation-failure-error-message").attr("failed"), storageAccountResourceId));
        }
        else {
          if (retriesForGetStorageAccount >= retryLimitForGetStorageAccount) {
            $("#terminal-storage-creation").hide();
            showUnknownFailure();

            logger.clientTelemetry('ACC.STORAGEACCOUNT.PUT.TIMEOUT', { storageAccount: storageAccountResourceId, provisioningState: data.properties.provisioningState }, { retryCount: retriesForGetStorageAccount }, Date.now() - startTime);
            resetCreateStorageDialog();
          }
          else {
            window.setTimeout(function () { getStorageAccount(retriesForGetStorageAccount + 1, startTime) }, 3000);
          }
        }
      });
  }

  function buildStorageFileShareName() {
    var claims = jwt_decode(accessToken);
    var userName = getUserNameFromClaims(claims);
    var prefix = ('cs-' + userName + '-').toLowerCase().replace(/[^a-z|0-9|-]/g, '-').replace(/-+/g, '-');
    var puid = (claims.puid || claims.altsecid.split(",")[0].split(":")[2]).toLowerCase();
    var fileShareName = prefix + puid;
    //note if fileShareName is too long, we trucate one extra char from prefix and then add back the dash to preserve the dash
    return fileShareName.length <= 63 ? fileShareName : (prefix.substring(0, 62 - puid.length) + '-' + puid).replace(/-+/g, '-');
  }

  function createUserSettings() {
    var fileShareName = !showAdvancedSettings ? buildStorageFileShareName() : $("#file-share-entry").val();
    storage.fileShareName = fileShareName;
    var data = {
      properties: {
        preferredOsType: osTypeSelection,
        preferredShellType: shellTypeSelection,
        preferredLocation: userLocation,
        storageProfile: {
          storageAccountResourceId: storageAccountResourceId,
          fileShareName: fileShareName,
          diskSizeInGB: 5
        }
      }
    };

    userSettings = data.properties;
    if(popout) {
      displayUserSettings();
    }
    updateFileServiceLink();
    putUserSettings(data, function (jqXHR, textStatus, errorThrown) {
      $("#terminal-storage-creation").hide();
      storageCreationFailed(jqXHR.status, jqXHR.responseText);
      resetCreateStorageDialog();
    }, function (data, textStatus, jqXHR) {
      $("#terminal-storage-creation").hide();
      resetCreateStorageDialog();
      if (data.properties.storageProfile) {
        callback(shellTypeSelection);
      }
    });
  }
}

function displayUserSettings() {
  var storageAccountIds = userSettings.storageProfile.storageAccountResourceId.split("/");
  var subscriptionId = storageAccountIds[storageAccountIds.indexOf("subscriptions")+1];
  var storageAccountId = storageAccountIds[storageAccountIds.indexOf("storageAccounts")+1];
  var armUri = getARMEndpoint() +  '/subscriptions/' + subscriptionId + '?api-version=2017-08-01';
  $("#cloudshell-header").show();
  $.ajax(armUri,
    {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': accessToken
      },
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
      $("#subscription-name").text(subscriptionId);
    })
    .done(function (data, textStatus, jqXHR) {
      $("#subscription-name").text(data.displayName);
    });
  
  $("#storage-account-name").text(storageAccountId);
}

function putUserSettings(data, callbackFail, callbackDone) {
  var method = 'PUT';
  var targetUri = getARMEndpoint() + '/providers/Microsoft.Portal' + getAzureConsoleProviderLocation() + '/userSettings/cloudconsole?api-version=' + consoleApiVersion;
  var start = Date.now();
  $.ajax(targetUri,
    {
      method: method,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': accessToken,
        'Accept-Language': language
      },
      data: JSON.stringify(data)
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
      callbackFail(jqXHR, textStatus, errorThrown);
    })
    .done(function (data, textStatus, jqXHR) {
      callbackDone(data, textStatus, jqXHR);
    });
}

function loadUserSettings(callbackFail, callbackDone, callbackAlways) {
  var method = 'GET';
  var targetUri = getARMEndpoint() + '/providers/Microsoft.Portal' + getAzureConsoleProviderLocation() + '/userSettings/cloudconsole?api-version=' + consoleApiVersion;
  var start = Date.now();
  $.ajax(targetUri,
    {
      method: method,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': accessToken,
        'Accept-Language': language
      },
    })
    .fail(function (jqXHR, textStatus, errorThrown, start, targetUri) {
      callbackFail(jqXHR, textStatus, errorThrown, start, targetUri);
    })
    .done(function (data, textStatus, jqXHR) {
      callbackDone(data, textStatus, jqXHR);
    })
    .always(function () {
      callbackAlways();
    });
}

function createTerminal() {
  while (terminalContainer.children.length) {
    terminalContainer.removeChild(terminalContainer.children[0]);
  }

  Terminal.applyAddon(webLinks);
  Terminal.applyAddon(winptyCompat);
  Terminal.applyAddon(attach);
  Terminal.applyAddon(fullscreen);
  Terminal.applyAddon(fit);

  term = new Terminal({
    cursorBlink: true
  });

  term.on('resize', function (size) {
    if (!termId) {
      return;
    }

    var method = 'POST';
    var targetUri = consoleUri + '/terminals/' + termId + '/size?cols=' + size.cols + '&rows=' + size.rows + '&version=2018-06-01';
    var start = Date.now();

    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.TERMINAL.RESIZE', {}, Date.now() - start, method, "", null, null, null, null, jqXHR.status);
      })
      .done(function (data, textStatus, jqXHR) {
        logger.clientRequest('ACC.TERMINAL.RESIZE', {}, Date.now() - start, method, "", null, null, null, null, jqXHR.status);
      });
  });
  screenReaderMode = window.localStorage.getItem('screenReaderMode') || "off";
  term.open(terminalContainer);
  term.focus();
  term.toggleFullScreen(true);
  term.fit();
  term.setOption('screenReaderMode', false);
  term.webLinksInit();
  term.connectionState = ConnectionState.NotConnected;

  if (screenReaderMode === "on") {
    term.setOption('screenReaderMode', true);
    $("#terminal-container").attr('aria-label', $("#terminal-container").attr('screen-reader-on-message'));
  }

  term.attachCustomKeyEventHandler(function (e) {
    // On Shift+Tab set focus to parent so keyboard-only users can navigate in and out of terminal
    var keyCode = e.keyCode || e.which;
    if (keyCode == 9) {
      if (e.shiftKey) {
        $("#terminal-container").focus();
        return false;
      }
    }
    if (e.ctrlKey || e.metaKey) {
      // On CTRL+C copy if there is an active selection, otherwise let xterm handle the command
      if (keyCode == 67) {
        if(term.hasSelection()) {
          document.execCommand('copy');
          setTimeout(function () { term.clearSelection() }, 20);
          return false;
        }
        return true;
      }
      // TODO (rosturm): support CTRL+V for pasting
    }
  // On CTRL+ALT+R toggle screen reader mode
    if ((e.ctrlKey || e.metaKey) && e.altKey && keyCode == 82) {
      screenReaderMode = screenReaderMode === "off" ? "on" : "off";
      window.localStorage.setItem('screenReaderMode', screenReaderMode);
      term.setOption('screenReaderMode', screenReaderMode === "on");
      $("#terminal-container").attr('aria-label', $("#terminal-container").attr('screen-reader-' + screenReaderMode + '-message'));
      return false;
    }
  });
  // Workaround to fix autocomplete on mobile device.
  $('.xterm-helper-textarea').attr('autocomplete', 'off');

  provisionConsole();
}

function keepAlive() {
  var start = Date.now();
  var method = 'POST';
  var targetUri = consoleUri + '/keepAlive';

  $.ajax(targetUri,
    {
      method: method,
      contentType: 'application/json',
      headers: {
        'Accept': 'application/json',
        'Authorization': accessToken,
        'Accept-Language': language
      }
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
      logger.clientRequest('ACC.KEEPALIVE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
    })
    .done(function (data, textStatus, jqXHR) {
      logger.clientRequest('ACC.KEEPALIVE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
    });

  logger.clientTelemetry('ACC.HEARTBEAT', {}, {}, Date.now() - term.connectTime.getTime());
}

function authorizeSession() {
  var start = Date.now();
  var targetUri = consoleUri + "/authorize";
  var method = "POST";
  $.ajax(targetUri,
    {
      method: method,
      contentType: 'application/json',
      headers: {
        'Accept': 'application/json',
        'Authorization': accessToken,
        'Accept-Language': language
      }
    })
    .fail(function (jqXHR, textStatus, errorThrown) {
      logger.clientRequest('ACC.AUTHORIZE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
    })
    .done(function (data, textStatus, jqXHR) {
      var cookieToken = data.token;
      var a = document.createElement("img");
      a.src = targetUri + "?token="+encodeURIComponent(cookieToken);
      logger.clientRequest('ACC.AUTHORIZE', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
    });
}

function provisionConsole() {
  var accFeatures = getQueryParametersPrefix('feature.azureconsole.').reduce(function (acc, val) {
    return acc + '&' + val.name + '=' + val.value;
  }, "");

  var targetUri = getConsoleUri() + accFeatures;
  var start = Date.now();

  function provisionConsoleInternal(pollingTimeout) {
    start = pollingTimeout ? start : Date.now();
    term.write(pollingTimeout ? "." : "Requesting a Cloud Shell.");
    var method = pollingTimeout ? 'GET' : 'PUT';
    var data = {
      properties: {
        osType: osTypeSelection
      }
    };

    var startInternal = Date.now();

    $.ajax(targetUri,
      {
        method: method,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'Authorization': accessToken,
          'x-ms-console-preferred-location': storage.location,
          'Accept-Language': language
        },
        data: (pollingTimeout ? undefined : JSON.stringify(data))
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.CONSOLE.' + method, {}, Date.now() - startInternal, method, targetUri, consoleApiVersion, null, jqXHR.getResponseHeader('x-ms-request-id'), null, jqXHR.status);

        if (method === 'PUT' && jqXHR.status === 409 && jqXHR.responseJSON && jqXHR.responseJSON.error && jqXHR.responseJSON.error.code === 'DeploymentOsTypeConflict') {
          // If the requesting Shell type is different from existing console Shell type, need to switch over.
          showSwitchShellTypeConfirmation(userSettings.preferredShellType);
          return;
        }

        if (jqXHR.responseJSON && jqXHR.responseJSON.error) {
          term.writeln("\x1B[1;31mFailed to provision a Cloud Shell: " + JSON.stringify(jqXHR.responseJSON.error) + "\x1B[0m ");
        }
        else {
          term.writeln("\x1B[1;31mFailed to provision a Cloud Shell.\x1B[0m ");
        }
        logger.clientTelemetry('ACC.CONSOLE.' + method + '.FAILURE', {}, {}, Date.now() - start);
      })
      .done(function (consoleResource, textStatus, jqXHR) {
        if (consoleResource.properties.provisioningState === "Succeeded") {
          logger.clientTelemetry('ACC.CONSOLE.PUT.SUCCESS', {}, {}, Date.now() - start);

          term.writeln("\x1B[1;32mSucceeded.\x1B[0m ");
          term.writeln('Connecting terminal...\n\r');

          connectTerminal(consoleResource, shellTypeSelection);
          authorizeSession();
        }
        else if (consoleResource.properties.provisioningState === "Failed") {
          term.connectionState = ConnectionState.NotConnected;
          logger.clientTelemetry('ACC.CONSOLE.PUT.FAILURE', {}, {}, Date.now() - start);
          term.writeln("\x1B[1;31mSorry, your Cloud Shell failed to provision. Please retry later. Request correlation id: " + jqXHR.getResponseHeader('x-ms-routing-request-id') + "\x1B[0m ");
        }
        else {
          pollingTimeout = pollingTimeout || new Date(Date.now() + 5 * 60 * 1000);
          if (pollingTimeout > new Date()) {
            setTimeout(function () { provisionConsoleInternal(pollingTimeout) }, 1000);
          }
          else {
            term.connectionState = ConnectionState.NotConnected;
            logger.clientTelemetry('ACC.CONSOLE.PUT.TIMEOUT', {}, {}, Date.now() - start);
            term.writeln("\n\r\x1B[1;31mSorry, your Cloud Shell failed to provision. Please retry later. Request correlation id: " + jqXHR.getResponseHeader('x-ms-routing-request-id') + "\x1B[0m ");
          }
        }
      });
  }

  term.connectionState = ConnectionState.Connecting;

  checkUserSettings(function () {
    showTerminal();

    if (storage.fileShareName) {
      term.writeln("Your cloud drive has been created in:")
      term.writeln("");
      term.writeln("Subscription Id: " + storage.subscriptionId);
      term.writeln("Resource group:  " + storage.resourceGroupName);
      term.writeln("Storage account: " + storage.storageAccountName);
      term.writeln("File share:      " + storage.fileShareName);
      term.writeln("");
      term.write("Initializing your account for Cloud Shell... ");

      waitingCursor(
        function (setTimeout) { setTimeout(1000 * 10); },
        function () { term.writeln(""); provisionConsoleInternal(); });
    }
    else {
      provisionConsoleInternal();
    }
  });
}

function connectTerminal(consoleResource, shellType, retryCount) {
  var start = Date.now();

  function connectTerminalInternal(consoleResource, retryCount) {
    consoleUri = consoleResource.properties.uri;

    var method = 'POST';
    var targetUri = consoleUri + '/terminals?cols=' + term.cols + '&rows=' + term.rows + '&version=2018-06-01' + '&shell=' + shellType;
    var startInternal = Date.now();
    var requestId = guid();

    retryCount = retryCount || 0;

    $.ajax(targetUri,
      {
        method: method,
        contentType: 'application/json',
        headers: {
          'Accept': 'application/json',
          'Authorization': accessToken,
          'x-ms-client-request-id': requestId,
          'Accept-Language': language
        }
      })
      .then(function (res, textStatus, jqXHR) {
        logger.clientRequest('ACC.TERMINAL.POST', { retryCount: retryCount }, Date.now() - startInternal, method, targetUri, null, requestId, null, null, jqXHR.status);
        logger.clientTelemetry('ACC.TERMINAL.CONNECT.SUCCESS', {}, { retryCount: retryCount }, Date.now() - start);

        termId = res.id;
        userRootDirectory = res.rootDirectory;
        terminalIdleTimeout = res.idleTimeout || terminalIdleTimeout;

        connectSocket(res.socketUri, null, handleSocketOpen, null, handleConnectionTimeout);
        connectSocket(res.socketUri + "/control", null, handleControlSocketOpen, handleControlSocketMessage, function() {});
        document.dispatchEvent(new CustomEvent('layoutUpdate'));

        window.onresize = function () {
          rtime = Date.now();
          if (timeout === false) {
            timeout = true;
            setTimeout(resizeTerminal, delta);
          }
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.TERMINAL.POST', { retryCount: retryCount }, Date.now() - startInternal, method, targetUri, null, requestId, null, null, jqXHR.status);

        if (jqXHR.status === 400 && jqXHR.responseJSON && jqXHR.responseJSON.error) {
          if (jqXHR.responseJSON.error.code === 'TooManyTerminals') {
            term.connectionState = ConnectionState.NotConnected;
            term.writeln("\x1B[1;31mFailed to request a terminal: " + jqXHR.responseJSON.error.message);
            term.setOption('cursorBlink', false);
            return;
          }
          else if (jqXHR.responseJSON.error.code === 'UserSettingsInvalid') {
            restartTerminal(jqXHR.responseJSON.error.message);
            return;
          }
        }

        if (retryCount > 50) {
          term.connectionState = ConnectionState.NotConnected;
          logger.clientTelemetry('ACC.TERMINAL.CONNECT.TIMEOUT', { status: jqXHR.status }, { retryCount: retryCount }, Date.now() - start);

          if (jqXHR.responseJSON && jqXHR.responseJSON.error) {
            term.writeln("\x1B[1;31mFailed to request a terminal: " + JSON.stringify(jqXHR.responseJSON.error) + "\x1B[0m ");
          }
          else {
            term.writeln("\x1B[1;31mFailed to request a terminal.\x1B[0m ");
          }
        }
        else {
          setTimeout(function () { connectTerminalInternal(consoleResource, retryCount + 1) }, 1000)
        }
      });
  }

  connectTerminalInternal(consoleResource);
}

function postMessageHelper(type, message) {
  if (window.parent !== window) {
    message = $.extend(message, {
      signature: "portalConsole",
      type: type
    });
    window.parent.postMessage(message, trustedParentOrigin);
  }
}

function getTokens() {
  postMessageHelper("getToken", { audience: "" });
}

// Requests ARM endpoint.
//postMessageHelper("getArmEndpoint");

function reconnectOnEnterKeydown(evt) {
  if (evt.keyCode === 13) {
    term.attachCustomKeyEventHandler(null);
    getTokens();
    return false;
  }
}

function resizeTerminal() {
  if (Date.now() - rtime < delta) {
    setTimeout(resizeTerminal, delta);
  }
  else {
    timeout = false;
    document.dispatchEvent(new CustomEvent('layoutUpdate'));
  }
}

document.addEventListener('layoutUpdate', function () {
  if ($("#terminal-open-editor").attr("editor-open") === "true") {
    if (defaultHeight) {
      $("#terminal-container").height($("#terminal-and-editor").height() * .2);
      $("#editor-wrapper").height($("#terminal-and-editor").height() * .8);
      $("#editor-bench").height($("#editor-wrapper").height() - 25);
      $("#editor-dialog-back").height($("#editor-wrapper").height());
    }
    $("#editor-terminal-separator").attr("aria-valuenow", $("#terminal-container").height());
    $("#editor-terminal-separator").attr("aria-valuemax", $("#terminal-and-editor").height() - $("#editor-terminal-separator").height());
    $("#editor-terminal-separator").attr("aria-valuemin", 0);

    $("#editor-explorer-separator").attr("aria-valuenow", $("#explorer-wrapper").width());
    $("#editor-explorer-separator").attr("aria-valuemax", $("#editor-bench").width() - $("#editor-explorer-separator").width());
    $("#editor-explorer-separator").attr("aria-valuemin", 0);
  }
  else {
    $("#terminal-container").height($("#terminal-and-editor").height());
  }
  term.toggleFullScreen(true);
  term.fit();
});

function waitingCursor(initialize, done) {
  var printCursor = function () {
    var index = 0;
    var chars = ['-', '\\', '|', '/'];
    return window.setInterval(function () {
      term.write("\x1B[1D" + chars[index++ % chars.length]);
    }, 200);
  }();

  initialize(function (timeout) {
    window.setTimeout(
      function () { window.clearInterval(printCursor); if (done) done(); },
      timeout || 500);
  });
}

function restartTerminal(msg) {
  var initialization = function (setTimeout) {
    var method = 'DELETE';
    var targetUri = getConsoleUri();
    var start = Date.now();

    $.ajax(targetUri,
      {
        method: method,
        contentType: 'application/json',
        headers: {
          'Accept': 'application/json',
          'Authorization': accessToken,
          'Accept-Language': language
        }
      })
      .fail(function (jqXHR, textStatus, errorThrown) {
        logger.clientRequest('ACC.TERMINAL.RESTART', {}, Date.now() - start, method, targetUri, null, null, null, null, jqXHR.status);
      })
      .done(function (res, textStatus, jqXHR) {
        setTimeout(5000);
      });
  };

  restartTerminalInternal(msg, 'Restarting your Cloud Shell...', initialization);
}

function restartTerminalInternal(msg, consolemsg, initialize)
{
  term.attachCustomKeyEventHandler(null);
  if (!accessToken) {
    window.location.reload();
  }

  closeTerminal();

  term.clear();

  if (msg) {
    term.writeln('\r' + msg + '\r\n');
    term.fit();
  }

  term.write('\r' + consolemsg);

  waitingCursor(
    initialize,
    function () {
      window.location.reload();
    });
}

function switchTerminal(msg) {
  restartTerminalInternal(
    msg,
    'Switching your Cloud Shell...', 
    function (setTimeout) 
    { 
      setTimeout(500); 
    }
  );
}

function closeTerminal() {
  if (term.connectTime) {
    logger.clientTelemetry('ACC.TERMINAL.CLOSE', {}, {}, Date.now() - term.connectTime.getTime());
  }

  disableFileUploads();
  disableEditorOpen();
  termId = null;
  userSettings = null;
  storage = {};
  term.connectionState = ConnectionState.NotConnected;
  term.connectTime = null;
  term.detach();
}

function handleSocketOpen() {
  this.onerror = handleSocketError;
  this.onclose = handleSocketClose;
    term.detach();
    term.attach(this);
    term.focus();
    getTokenInterval = getTokenInterval || window.setInterval(getTokens, 1000 * 60 * 10);
    term.connectionState = ConnectionState.Connected;
    term.connectTime = new Date();
    logger.clientTelemetry('ACC.TERMINAL.OPEN', {}, {}, Date.now() - term.connectTime.getTime());
    enableFileUploads();
    enableEditorOpen();
    if(cloudshellVersion >= "2018-03-01") {
      postMessageHelper("connected");
    }
}

function handleControlSocketOpen() {
  this.onerror = handleSocketError;
  this.onclose = handleControlSocketClose;
}

function handleControlSocketClose() {
  if (term.connectionState === ConnectionState.Connected || term.connectionState === ConnectionState.Connecting) {
    var that = this;
    window.setTimeout(function () {
      connectSocket(that.url, 0, that.onopen, that.onmessage, that.ontimeout);
    }, 500);
  }
}

function handleSocketClose() {
  if (term.connectionState === ConnectionState.Connected) {
    if(cloudshellVersion >= "2018-03-01") {
      postMessageHelper("disconnected");
    }
    closeTerminal();
    window.clearInterval(getTokenInterval);
    getTokenInterval = null;
    accessToken = null;
    hideTerminal();
    $(".terminal-dialog").hide();
    $("#terminal-time-out-dialog").show();
    $("#time-out-reconnect").focus();
    $("#time-out-body").html(format($("#time-out-body").html(), terminalIdleTimeout));
    if (userBrowserFirefox()){
      $("#time-out-body-firefox").html($("#time-out-body-firefox").text());
    }
    else{
      $("#time-out-body-firefox").css('display', 'none');
    }
    $('#time-out-reconnect').off('keypress click keydown');
    $('#time-out-quit').off('keypress click keydown');

    enterClickHandler($("#time-out-reconnect"), function () {
      $("#terminal-time-out-dialog").hide();
      term.focus();
      term.reset();
      showTerminal();
      getTokens();
    });

    arrowKeyHandler($("#time-out-reconnect"), "right", function() {
      $("#time-out-quit").focus();
    });

    arrowKeyHandler($("time-out-quit"), "left", function() {
      $("#time-out-reconnect").focus();
    });

    enterClickHandler($("#time-out-quit"), function () {
      postMessageHelper("close");
    });
  }
}

function handleSocketError(event) {
  console.error("Socket Error: " + JSON.stringify(event));
}

function handleSocketConnectionError(event) {
  console.error("Socket Connection Error: " + JSON.stringify(event));

  var that = this;

  window.setTimeout(function () {
    connectSocket(that.url, that.retryCount, that.onopen, that.onmessage, that.ontimeout);
  }, 500);
}

function handleConnectionTimeout() {
  closeTerminal();

  accessToken = null;
  term.writeln("\n\r\x1B[1;31mFailed to connect terminal: websocket cannot be established. Press \"Enter\" to reconnect.\x1B[0m ");
  term.attachCustomKeyEventHandler(reconnectOnEnterKeydown);
}

function connectSocket(url, retryCount, handleSocketOpen, handleSocketMessage, handleConnectionTimeout) {
  retryCount = retryCount || 0;

  if (retryCount < 10) {
    var socket = new WebSocket(url);
    socket.retryCount = retryCount + 1;
    socket.onopen = handleSocketOpen;
    socket.onerror = handleSocketConnectionError;
    socket.onmessage = handleSocketMessage;
    socket.ontimeout = handleConnectionTimeout;
  }
  else {
    handleConnectionTimeout();
  }
}

function enterClickHandler(htmlElement, enterFunction) {
  htmlElement.on('keypress click', function (e) {
    if (e.which === 13 || e.type === 'click') {
      enterFunction(e);
    }
  });
}

function arrowKeyHandler(htmlElement, direction, arrowKeyFunction) {
  htmlElement.on('keypress keydown', function (e) {
    if (e.which === 37 && direction === "left") {
      arrowKeyFunction();
    }
    if (e.which === 39 && direction === "right") {
      arrowKeyFunction();
    }
  });
}

function updateFontSize(size) {
  if (!(size in fontSizes)) {
    size = fontSizes.small;
  }
  if (currentFontSize !== size) {
    var previousFontSize = currentFontSize;
    currentFontSize = size;
    $('.font-size-option').removeClass("selected-font-setting");
    $("#font-size-option-" + size).addClass("selected-font-setting");
    term.setOption('fontSize', fontSizes[size]);
    if (previousFontSize != undefined) {
      saveFontToUserSettings();
    }
    term.fit();
    term.refresh();
  }
}

function updateFontStyle(style) {
  if (!(style in fontStyles)) {
    style = fontStyles.monospace;
  }
  if (currentFontStyle !== style) {
    var previousFontStyle = currentFontStyle;
    currentFontStyle = style;
    $('.font-style-option').removeClass("selected-font-setting");
    $("#font-style-option-" + style).addClass("selected-font-setting");
    term.setOption('fontFamily', fontStyles[style]);
    if (previousFontStyle != undefined) {
      saveFontToUserSettings();
    }
    term.fit();
    term.refresh();
  }
}

//TODO (rosturm): enable PATCH for font and perform PATCH insted of GET+POST
function saveFontToUserSettings() {
  var updateData;
  loadUserSettings(
    function (jqXHR, textStatus, errorThrown, start, targetUri) {
      updateData = userSettings;
      console.error('Error getting current user settings');
    },
    function (data, textStatus, jqXHR) {
      updateData = data.properties;
    },
    function () {
      updateData.terminalSettings = updateData.terminalSettings || {};
      updateData.terminalSettings.fontSize = currentFontSize || "medium";
      updateData.terminalSettings.fontStyle = currentFontStyle || "monospace";
      var data = {
        properties: updateData
      };

      putUserSettings(data,
        function (jqXHR, textStatus, errorThrown) {
          console.error('Error saving font selection to user settings: ' + errorThrown);
        }, function (data, textStatus, jqXHR) { });
    }
  );
}

function populateDirectoryInfo(claims) {
  var unique_name = getUserNameFromClaims(claims);
  $("#current-email").text(unique_name);
  var tenantName = getQueryParameter("tenant") || claims.tid;
  $("#current-tenant").text(tenantName);
  $("#directory-name").text(tenantName);
  var greeting = $("#directory-popout-greeting");
  greeting.text(claims.given_name ? format(greeting.attr('greeting-text-name'), claims.given_name) : greeting.attr('greeting-text-noname'));
}

function getUserNameFromClaims(claims) {
  var userName;
  if (claims.upn && claims.upn.match(/\S/)) {
    userName = claims.upn;
  }
  else {
    userName = claims.unique_name;
    if (userName && userName.indexOf('#') != -1 && userName.indexOf('#') != userName.length - 1) {
      userName = userName.substring(userName.indexOf('#') + 1);
    }
  }
  return userName;
}

// Generate a semi GUID.
function guid() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }

  return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
}

function updateCreateButton() {
  var hasRGInput = $("#use-existing-rg").prop("checked") || $("#resource-group-text-entry").val() !== "";
  var hasSAInput = $("#use-existing-sa").prop("checked") || $("#storage-account-text-entry").val() !== "";
  var hasFSInput = $("#file-share-entry").val() !== "";

  if (hasRGInput && hasSAInput && hasFSInput) {
    $("#terminal-storage-creation-create").prop("disabled", false);
  }
  else {
    $("#terminal-storage-creation-create").prop("disabled", true);
  }
}

function updateTerminalBackgroundColor(state) {
  term.setOption('theme', {
    background: backgroundColors[state]
  });
}

function setupFileDragDrop() {
  var dragCount = 0;  
  $("#terminal-container").on("dragenter", function (e) {
    dragCount++;
    $("#terminal-container").addClass("dragging-file");
    updateTerminalBackgroundColor("drag");
  });

  $("#terminal-container").on("dragleave", function (e) {
    dragCount--;
    if (dragCount === 0) {
      $("#terminal-container").removeClass("dragging-file");
      updateTerminalBackgroundColor(shellTypeSelection.toLowerCase());
    }
  });

  $("#terminal-container").on("dragover", function (e) {
    e.preventDefault();
  });

  $("#terminal-container").on("drop", function (e) {
    dragCount = 0;
    e.preventDefault();
    $("#terminal-container").removeClass("dragging-file");
    updateTerminalBackgroundColor(shellTypeSelection.toLowerCase());
    var files = e.originalEvent.dataTransfer.files;
    fileManager.startUpload(files, consoleUri + "/terminals/" + termId + "/upload");
  });
}

function enableFileUploads() {
  setupFileDragDrop();
  $("#terminal-file-selector").removeClass("disabled");
  $("#terminal-file-selector").attr("tabindex", "0");
  $("#terminal-file-selector").attr("role", "button");
  enterClickHandler($("#terminal-file-selector"), function (e) {
    if ($('#terminal-file-selector div.dropdown-content').css('display') === 'none') {
      hideAllDropdowns();
      $('#terminal-file-selector div.dropdown-content').css('display', 'inline-block');
      $('#terminal-file-selector').attr('aria-expanded', "true");
      $('#terminal-file-selector').focus();
    }
    else {
      $('#terminal-file-selector div.dropdown-content').css('display', 'none');
      $('#terminal-file-selector').attr('aria-expanded', "false");
      $('#terminal-file-selector').focus();
    }
    stopClickEventPropagation(e);
  });
  enterClickHandler($("#terminal-upload"), function() {
    $("#file-uploader").click();
  });
}

function enableEditorOpen() {
  $("#terminal-open-editor").removeClass("disabled");
  enterClickHandler($('#terminal-open-editor'), function(e) {
    if($('#terminal-open-editor').attr("editor-open") === "false") {
      defaultHeight = true;
      document.dispatchEvent(new CustomEvent('show', {
        detail: {
          component: 'editor',
          arguments: {
            audience: 'editor',
            folderUri: "/files" + userRootDirectory
          }
        }
      }));
    }
    else {
      $("#hide-editor").click();
    }
  });
  $("#terminal-open-editor").attr("tabindex", "0");
  $("#terminal-open-editor").attr("role", "button");
}

function disableEditorOpen() {
  $("#terminal-open-editor").addClass("disabled");
  $("#terminal-open-editor").removeAttr("role");
  $("#terminal-open-editor").removeAttr("tabindex");
  $("#terminal-open-editor").off();
}

function disableFileUploads() {
  $("#terminal-container").off("dragenter dragleave dragover drop");
  $("#terminal-file-selector").addClass("disabled");
  $("#terminal-file-selector").removeAttr("role");
  $("#terminal-file-selector").removeAttr("tabindex");
  $("#terminal-upload").off();
  $("#terminal-file-selector").off();
}

function hideAllDropdowns() {
  $('#terminal-header div.dropdown-content').css('display', 'none');
  $('#terminal-header div.second-dropdown-content').css('display', 'none');
  $('.terminal-button .terminal-header-button').attr('aria-expanded', "false");
  $('.terminal-button').removeClass('active-selector');
  $('#directory-popout').css('display', 'none');
  $('#tenant-button').attr('aria-expanded', "false");
}

function stopClickEventPropagation(event) {
  if (event.stopPropagation) {
    event.stopPropagation();
  }
  else if (window.event) {
    window.event.cancelBubble = true;
  }
};

function handleControlSocketMessage(e) {
  var msg = JSON.parse(e.data);
  var audience = msg.audience;
  if (audience === "download") {
    var downloadUrl = consoleUri + msg.fileUri;
    var id = downloadUrl.indexOf("downloads/") >= 0 ? downloadUrl.split("downloads/")[1] : "";
    triggerLinkClick(downloadUrl, id, false);
  }
  if (audience === "editor") {
    defaultHeight = true;
    if (!msg.fileUri && !msg.folderUri) {
      document.dispatchEvent(new CustomEvent('show', { detail: 'editor' }));
      return;
    }
    if (msg.directory) {
       codeEditorDirectory = msg.directory;
    }
    document.dispatchEvent(new CustomEvent('show', {
      detail: {
        component: 'editor',
        arguments: msg
      }
    }));
  }
  if (audience === "token") {
    var endpoint = msg.tokenAudience;
    if (endpoint in tokenAudiences) {
      postMessageHelper("getToken", { audience: tokenAudiences[endpoint] });
    }
    else {
      console.error("Audience '" + endpoint + "' cannot be handled.");
    }
  }
  if (audience === "url") {
    var url = msg.url;
    triggerLinkClick(url, "openLink", true);
  }
}

function triggerLinkClick(url, id, launchPage) {
  var a = document.createElement("a");
  a.href = url;
  if (launchPage) {
    a.target = "_blank";
    $("#click-link-firefox-link").text($("#click-link-firefox-link").attr('open-link-text'));
  }
  else {
    $("#click-link-firefox-link").text($("#click-link-firefox-link").attr('download-text'));
  }
  if (id) {
    linksToOpen[id] = a;
    if (userBrowserFirefox() || userBrowserIE()) {
      $("#click-link-firefox-dialog").show();
      $("#terminal-upload-status-dialog").hide();
      $("#click-link-firefox-link").focus();
    }
    else {
      window.setTimeout(function () {
        linksToOpen[id].click();
        delete linksToOpen[id]
      }, 1000 * Object.keys(linksToOpen).length);
    }
  }
}

function resizeEditorAndTerminal(terminalContainerHeight) {
  $("#terminal-container").height(terminalContainerHeight);
  $("#editor-wrapper").height(terminalContainerHeight === maxHeight ? 0 : $("#terminal-and-editor").height() - terminalContainerHeight);
  $("#editor-bench").height($("#editor-wrapper").height() - 25);
  $("#editor-dialog-back").height($("#editor-wrapper").height());
  $("#editor-terminal-separator").attr("aria-valuenow", $("#terminal-container").height());
  rtime = Date.now();
  if (timeout === false) {
    timeout = true;
    setTimeout(resizeTerminal, delta);
  }
}

function resizeExplorerAndEditor(explorerWrapperWidth) {
  var editorContainerWidth = $("#editor-wrapper").width() - explorerWrapperWidth;
  $("#editor-container").css("flex", "initial");
  $("#explorer-wrapper").width(explorerWrapperWidth);
  $("#editor-container").width(editorContainerWidth);
  document.dispatchEvent(new CustomEvent('layoutUpdate'));
}

function dragResizeHandler(e) {
  defaultHeight = false;
  e.preventDefault();
  if (canResizeY) {
    canResizeY = false;
    window.requestAnimationFrame(function() {
      var terminalContainerHeight = Math.min(terminalResizeOriginalHeight + startY - e.clientY, maxHeight);
      resizeEditorAndTerminal(terminalContainerHeight);
      canResizeY = true;
    });
  }
  if (canResizeX) {
    canResizeX = false;
    window.requestAnimationFrame(function() {
      var explorerWrapperWidth = Math.max(Math.min(e.clientX, maxWidth), 0);
      resizeExplorerAndEditor(explorerWrapperWidth);
      canResizeX = true;
    });
  }
}

function hideEditorMenu() {
  $('#editor-titlebar-menu-dropdown').css('display', 'none');
  $('#editor-titlebar-menu').attr('aria-expanded', "false");
  $('#editor-titlebar-menu').focus();
}

var canResizeY = false;
var canResizeX = false;
var startY;
var startX;
var explorerResizeOriginalWidth;
var terminalResizeOriginalHeight;
var maxWidth = $("#terminal-and-editor").width() - $("#editor-explorer-separator").width();
var maxHeight = $("#terminal-and-editor").height() - $("#editor-terminal-separator").height();

$(document).ready(function () {
  enterClickHandler($(".close-download-dialog"), function() {
    $("#download-file-input-entry").val("");
    $("#terminal-download-dialog").hide();
    term.focus();
  });

  $("#terminal-container").height($("#terminal-and-editor").height());

  $("#download-enter").on('click', function() {
    var filename = $("#download-file-input-entry").val();
    $("#download-file-input-entry").val("");
    $("#download-enter").prop("disabled", true);
    fileManager.startDownload(filename, consoleUri + "/terminals/" + termId + "/download");
  });

  $("#download-file-input-entry").on('keypress', function (e) {
    if (e.which === 13) {
      var filename = $("#download-file-input-entry").val();
      $("#download-file-input-entry").val("");
      $("#download-enter").prop("disabled", true);
      fileManager.startDownload(filename, consoleUri + "/terminals/" + termId + "/download");
    }
  });

  enterClickHandler($("#terminal-download"), function () {
    $("#terminal-download-dialog").show();
    $("#download-file-input-directory").text(userRootDirectory);
    $("#download-errors").hide();
    $("#download-file-input-entry").focus();
    $("#download-file-input-entry").on('input', function () {
      if($("#download-file-input-entry").val() !== "") {
        $("#download-enter").prop("disabled", false);
      }
      else {
        $("#download-enter").prop("disabled", true);
      }
    });
  });
  appInsights = window.appInsights || function (config) {
    function i(config) { t[config] = function () { var i = arguments; t.queue.push(function () { t[config].apply(t, i) }) } } var t = { config: config }, u = document, e = window, o = "script", s = "AuthenticatedUserContext", h = "start", c = "stop", l = "Track", a = l + "Event", v = l + "Page", y = u.createElement(o), r, f; y.src = config.url || "https://az416426.vo.msecnd.net/scripts/a/ai.0.js"; u.getElementsByTagName(o)[0].parentNode.appendChild(y); try { t.cookie = u.cookie } catch (p) { } for (t.queue = [], t.version = "1.0", r = ["Event", "Exception", "Metric", "PageView", "Trace", "Dependency"]; r.length;)i("track" + r.pop()); return i("set" + s), i("clear" + s), i(h + a), i(c + a), i(h + v), i(c + v), i("flush"), config.disableExceptionTracking || (r = "onerror", i("_" + r), f = e[r], e[r] = function (config, i, u, e, o) { var s = f && f(config, i, u, e, o); return s !== !0 && t["_" + r](config, i, u, e, o), s }), t
  }({
    instrumentationKey: $("#app-insights-key").attr("value"),
    disableAjaxTracking: true
  });

  window.appInsights = appInsights;
  appInsights.trackPageView();

  logger = new Logger(getARMEndpoint(), appInsights);
  fileManager = new FileManager();

  if (embed) {
    $('#terminal-header').hide();
  }

  $("#editor-terminal-separator").on("mousedown", function(e) {
    startY = e.clientY;
    maxHeight = $("#terminal-and-editor").height() - $("#editor-terminal-separator").height();
    terminalResizeOriginalHeight = $("#terminal-container").height();
    canResizeY = true;
    $(document).on("mousemove", dragResizeHandler);
    $(document).on("mouseup", function(e) {
      canResizeY = false;
      $(document).off("mousemove", dragResizeHandler);
    });
  });

  $("#editor-explorer-separator").on("mousedown", function(e) {
    maxWidth = $("#terminal-and-editor").width() - $("#editor-explorer-separator").width();
    startX = e.clientX;
    explorerResizeOriginalWidth = $("#explorer-wrapper").width();
    canResizeX = true;
    $(document).on("mousemove", dragResizeHandler);
    $(document).on("mouseup", function(e) {
      canResizeX = false;
      $(document).off("mousemove", dragResizeHandler);
    });
  });

  $("#editor-terminal-separator").on("keydown", function(e) {
    var hasMoved = false;
    maxHeight = $("#terminal-and-editor").height() - $("#editor-terminal-separator").height();
    terminalResizeOriginalHeight = $("#terminal-container").height();
    var terminalContainerHeight;
    switch (e.keyCode) {
      case 38: {
        hasMoved = true;
        terminalContainerHeight = Math.min(terminalResizeOriginalHeight + 10, maxHeight);
        break;
      }
      case 40: {
        hasMoved = true;
        terminalContainerHeight = Math.max(terminalResizeOriginalHeight - 10, 0);
        break;
      }
    }
    if (hasMoved) {
      defaultHeight = false;
      e.stopPropagation();
      resizeEditorAndTerminal(terminalContainerHeight);
      rtime = Date.now();
      if (timeout === false) {
        timeout = true;
        setTimeout(resizeTerminal, delta);
      }
    }
  });

  $("#editor-explorer-separator").on("keydown", function(e) {
    maxWidth = $("#terminal-and-editor").width() - $("#editor-explorer-separator").width();
    var hasMoved = false;
    explorerResizeOriginalWidth = $("#explorer-wrapper").width();
    var explorerWrapperWidth;
    switch (e.keyCode) {
      case 39: {
        hasMoved = true;
        explorerWrapperWidth = Math.min(explorerResizeOriginalWidth + 10, maxWidth);
        break;
      }
      case 37: {
        hasMoved = true;
        explorerWrapperWidth = Math.max(explorerResizeOriginalWidth - 10, 0);
        break;
      }
    }
    if (hasMoved) {
      defaultHeight = false;
      e.stopPropagation();
      resizeExplorerAndEditor(explorerWrapperWidth);
    }
  });

  if (popout) {
    $("#terminal-minimize").hide();
    $("#terminal-maximize").hide();
    $("#terminal-close").hide();
    $("#terminal-restore").hide();
    $("#editor-titlebar-menu-dropdown").addClass("with-popout");
  }

  $("#click-link-firefox-link").on("click", function() {
    for (var fileId in linksToOpen) {
      window.open($(linksToOpen[fileId]).attr("href"), "_blank");
    }
    linksToOpen = {};

    $("#click-link-firefox-dialog").hide();
    term.focus();
  });

  enterClickHandler($("#click-link-firefox-dialog-close"), function() {
    $("#click-link-firefox-dialog").hide();
    term.focus();
  });

  $(".advanced-option-input").on('input', function () {
    updateCreateButton();
  });

  $("#file-uploader").on('change', function() {
    fileManager.startUpload($("#file-uploader")[0].files, consoleUri + "/terminals/" + termId + "/upload");
    $("#file-uploader").val("");
  });

  enterClickHandler($("#terminal-close"), function() {
    postMessageHelper("close");
  });

  enterClickHandler($("#directory-popout-signout"), function() {
    postMessageHelper("close");
  });

  enterClickHandler($("#terminal-minimize"), function() {
    postMessageHelper("minimize");
  });

  enterClickHandler($("#terminal-maximize"), function() {
    $("#terminal-minimize").show();
    $('#terminal-restore').show();
    $("#terminal-maximize").hide();
    postMessageHelper("maximize");
  });

  enterClickHandler($("#terminal-restore"), function() {
    $("#terminal-minimize").show();
    $("#terminal-restore").hide();
    $('#terminal-maximize').show();
    postMessageHelper("restore");
  });

  enterClickHandler($("#confirm-restart"), function () {
    $("#terminal-restart-confirmation").hide();
    showTerminal();
    restartTerminal();
  });

  arrowKeyHandler($("#cancel-restart"), "left", function () {
    $("#confirm-restart").focus();
  });

  arrowKeyHandler($("#confirm-restart"), "right", function() {
    $("#cancel-restart").focus();
  });

  enterClickHandler($(".cancel-terminal-restart"), function () {
    $("#terminal-restart-confirmation").hide();
    $("#terminal-switch-shell-confirmation").hide();
    showTerminal();
    term.focus();
  });

  enterClickHandler($("#upload-dialog-close"), function() {
    $("#terminal-upload-status-dialog").stop();
    $("#terminal-upload-status-dialog").hide();
    $("#terminal-upload-status-dialog").css('opacity', '1');
    term.focus();
  });

  $("#upload-dialog-close").focusin(function() {
    $("#terminal-upload-status-dialog").stop();
    $("#terminal-upload-status-dialog").css('opacity', '1');
  });

  $("#upload-dialog-close").focusout(function() {
    hideUploadDialogue();
  });

  $("#terminal-upload-status-dialog").mouseenter(function() {
    $("#terminal-upload-status-dialog").stop();
    $("#terminal-upload-status-dialog").css('opacity', '1');
  });

  $("#terminal-upload-status-dialog").mouseleave(function() {
    hideUploadDialogue();
  });

  function hideUploadDialogue() {
    setTimeout(function() {
      $("#terminal-upload-status-dialog").fadeOut(6000);
    }, 10000);
  }

  enterClickHandler($("#cancel-switch-shell"), function () {
    if (embed) {
      postMessageHelper("close");
    }
  });

  enterClickHandler($('#terminal-restart'), function(e) {
    hideTerminal();
    $("#terminal-storage-creation").hide();
    $("#terminal-restart-confirmation").show();
    $("#confirm-restart").focus();
  });

  enterClickHandler($('#terminal-popout'), function(e) {
    var cloudShellLink = 'https://shell.azure.com/' + (tenantId ? '?tid=' + tenantId : '');
    window.open(cloudShellLink, '_blank');
  });

  enterClickHandler($("#terminal-shell-selector"), function (e) {
    if ($('#terminal-shell-selector div.dropdown-content').css('display') === 'none') {
      hideAllDropdowns();
      $('#terminal-shell-selector div.dropdown-content').css('display', 'inline-block');
      $('#terminal-shell-selector').attr('aria-expanded', "true");
      $('#terminal-shell-selector').focus();
    }
    else {
      $('#terminal-shell-selector div.dropdown-content').css('display', 'none');
      $('#terminal-shell-selector').attr('aria-expanded', "false");
      $('#terminal-shell-selector').focus();
    }
    stopClickEventPropagation(e);
  });

  $('.terminal-button').on('focusin', function (e) {
    $(this).addClass('active-selector');
  });

  $('.terminal-button').on('focusout', function () {
    if (!($(this).attr('aria-expanded') === "true")) {
      $(this).removeClass('active-selector');
    }
  });

  $("#terminal-shell-selector").on('focusout mouseleave', function (e) {
    if($("#terminal-shell-selector").children('.dropdown-content').css('display') === "none" && !$(this).is(":focus")) {
      $(this).removeClass('active-selector');
    }
  });

  $("#terminal-help-selector").on('focusin', function (e) {
    $(this).addClass('active-selector');
  });

  $("#terminal-tool-selector").on('focusin', function (e) {
    $(this).addClass('active-selector');
  });

  $("#terminal-help-selector").on('focusout mouseleave', function (e) {
    if($("#terminal-help-selector").children('.dropdown-content').css('display') === "none" && !$(this).is(":focus")) {
      $(this).removeClass('active-selector');
    }
  });

  $("#terminal-tool-selector").on('focusout mouseleave', function (e) {
    if($("#terminal-tool-selector").children('.dropdown-content').css('display') === "none" && !$(this).is(":focus")) {
      $(this).removeClass('active-selector');
    }
  });

  $("#terminal-file-selector").on('focusout mouseleave', function (e) {
    if($("#terminal-file-selector").children('.dropdown-content').css('display') === "none" && !$(this).is(":focus")) {
      $(this).removeClass('active-selector');
    }
  });

  enterClickHandler($("#terminal-help-selector"), function (e) {
    if ($('#terminal-help-selector div.dropdown-content').css('display') === 'none') {
      hideAllDropdowns();
      $('#terminal-help-selector div.dropdown-content').css('display', 'inline-block');
      $('#terminal-help-selector').attr('aria-expanded', "true");
      $('#terminal-help-selector').focus();
    }
    else {
      $('#terminal-help-selector div.dropdown-content').css('display', 'none');
      $('#terminal-help-selector').attr('aria-expanded', "false");
      $('#terminal-help-selector').focus();
    }
    stopClickEventPropagation(e);
  });

  enterClickHandler($("#terminal-tool-selector"), function (e) {
    if ($('#terminal-tool-selector div.dropdown-content').css('display') === 'none') {
      hideAllDropdowns();
      $('#terminal-tool-selector div.dropdown-content').css('display', 'inline-block');
      $('#terminal-tool-selector').attr('aria-expanded', "true");
      $('#terminal-tool-selector').focus();
    }
    else {
      $('#terminal-tool-selector div.dropdown-content').css('display', 'none');
      $('#terminal-tool-selector').attr('aria-expanded', "false");
      $('#terminal-tool-selector').focus();
    }
    stopClickEventPropagation(e);
  });

  enterClickHandler($("#tenant-button"), function (e) {
    if ($('#directory-popout').css('display') === 'none') {
      hideAllDropdowns();
      $('#directory-popout').css('display', 'inline-block');
      $('#tenant-button').attr('aria-expanded', "true");
      $('#tenant-button').focus();
    }
    else {
      $('#directory-popout').css('display', 'none');
      $('#tenant-button').attr('aria-expanded', "false");
      $('#tenant-button').focus();
    }
    stopClickEventPropagation(e);
  });

  enterClickHandler($("#editor-titlebar-menu"), function(e) {
    if ($('#editor-titlebar-menu-dropdown').css('display') === 'none') {
      hideAllDropdowns();
      $('#editor-titlebar-menu-dropdown').css('display', 'inline-block');
      $('#editor-titlebar-menu').attr('aria-expanded', "true");
      $('#save-file-editor').focus();
    }
    else {
      $('#editor-titlebar-menu-dropdown').css('display', 'none');
      $('#editor-titlebar-menu').attr('aria-expanded', "false");
      $('#editor-titlebar-menu').focus();
    }
    stopClickEventPropagation(e);
  });

  enterClickHandler($("#editor-wrapper"), function(e) {
    if ($("#editor-titlebar-menu-dropdown").has($(e.target)).length == 0 && $('#editor-titlebar-menu-dropdown').css('display') !== "none") {
      hideEditorMenu();
    }
  });

  enterClickHandler($("#directory-popout"), function (e) {
    stopClickEventPropagation(e);
  });

  $('.size-settings').on('focusin mouseenter click', function (e) {
    $("#font-size-dropdown").css("left", $("#tools-dropdown").width());
    $('#terminal-size-selector div.second-dropdown-content').css('display', 'inline-block');
    $('#terminal-size-selector').attr('aria-expanded', "true");
    $('#terminal-style-selector div.second-dropdown-content').css('display', 'none');
    $('#terminal-style-selector').attr('aria-expanded', "false");
    stopClickEventPropagation(e);
  });

  $('.style-settings').on('focusin mouseenter click', function (e) {
    $("#font-style-dropdown").css("left", $("#tools-dropdown").width());
    $('#terminal-style-selector div.second-dropdown-content').css('display', 'inline-block');
    $('#terminal-style-selector').attr('aria-expanded', "true");
    $('#terminal-size-selector div.second-dropdown-content').css('display', 'none');
    $('#terminal-size-selector').attr('aria-expanded', "false");
    stopClickEventPropagation(e);
  });

  $('#tools-feedback-element').on('focusin mouseenter click', function (e) {
    $('#terminal-size-selector div.second-dropdown-content').css('display', 'none');
    $('#terminal-size-selector').attr('aria-expanded', "false");
    $('#terminal-style-selector div.second-dropdown-content').css('display', 'none');
    $('#terminal-style-selector').attr('aria-expanded', "false");
    stopClickEventPropagation(e);
  });

  $('#focusguard-restart-confirm-end').on('focus', function () {
    $('#restart-close').focus();
  });

  $('#focusguard-restart-confirm-begin').on('focus', function () {
    $('#cancel-restart').focus();
  });

  $('#focusguard-download-dialog-end').on('focus', function () {
    $('#download-close').focus();
  });

  $('#focusguard-download-dialog-begin').on('focus', function () {
    $('#cancel-download').focus();
  });

  $('#focusguard-editor-save-end').on('focus', function () {
    $('#editor-save-close').focus();
  });

  $('#focusguard-editor-save-begin').on('focus', function () {
    $('#editor-save-cancel').focus();
  });

  $('#focusguard-switch-shell-end').on('focus', function () {
    $('#switch-shell-close').focus();
  });

  $('#focusguard-switch-shell-begin').on('focus', function () {
    $('#cancel-switch-shell').focus();
  });

  $('#focusguard-ostype-selection-end').on('focus', function () {
    $('#terminal-ostype-close').focus();
  });

  $('#focusguard-ostype-selection-begin').on('focus', function () {
    $('#os-ps-option').focus();
  });

  $('#focusguard-storage-creation-end').on('focus', function () {
    $('#storage-creation-close').focus();
  });

  $('#focusguard-storage-creation-begin').on('focus', function () {
    $('#terminal-storage-creation-close').focus();
  });

  $('#focusguard-time-out-end').on('focus', function () {
    $('#time-out-reconnect').focus();
  });

  $('#focusguard-time-out-begin').on('focus', function () {
    $('#time-out-quit').focus();
  });

  $(document).click(function () {
    hideAllDropdowns();
  });

  $('.font-size-option').on('keypress click', function (e) {
    if (e.which === 13 || e.type === 'click') {
      var size = $(this).attr("value");
      updateFontSize(size, this);
      stopClickEventPropagation(e);
      hideAllDropdowns();
    }
  });

  $('.font-style-option').on('keypress click', function (e) {
    if (e.which === 13 || e.type === 'click') {
      var font = $(this).attr("value");
      updateFontStyle(font, this);
      stopClickEventPropagation(e);
      hideAllDropdowns();
    }
  });

  terminalContainer = document.getElementById('terminal-container');
  if (window.parent !== window) {
    setupParentMessage();
  }
  else {
    $(terminalContainer).html("Sorry, something went wrong.");
  }
});