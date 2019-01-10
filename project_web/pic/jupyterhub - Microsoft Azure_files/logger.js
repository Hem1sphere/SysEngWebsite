var Logger = (function()
{
  function Logger(armEndpoint, appInsights, baseEventData) {
    var sessionId = guid();
    this.sessionId = sessionId;
    this.armEndpoint = armEndpoint;
    this.appInsights = appInsights;
    this.baseEventData = baseEventData || {};

    // Enable consistent sessionId in AppInsights via callback
    if(this.appInsights.queue) {
      this.appInsights.queue.push(function() {
        // the callback is made in AppInsights context so "this" pointer is "window"
        if (this.appInsights) {
          this.appInsights.context.session.id = sessionId;
        }
      });
    }
  }

  function guid() {
    function s4() {
      return Math.floor((1 + Math.random()) * 0x10000)
        .toString(16)
        .substring(1);
    }
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
      s4() + '-' + s4() + s4() + s4();
  }

  function collectTelemetry(armEndpoint, data)
  {
    $.ajax(armEndpoint + '/providers/Internal.Telemetry/collect?api-version=2015-09-30-preview',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': accessToken
        },
        data: JSON.stringify({ events: data } )
      });
  }

  Logger.prototype.addBaseEventData = function(baseEventData) {
    this.baseEventData = $.extend(this.baseEventData, baseEventData || {});
  };
  
  Logger.prototype.clientError = function(eventName, eventData, code, message, exception) {
    collectTelemetry(
      this.armEndpoint, 
      [{
        eventType: 'error',
        eventId: this.sessionId,
        eventTimestamp: new Date().toISOString(),
        eventName: eventName,
        eventData: $.extend(eventData, this.baseEventData),
        code: code,
        message: message,
        exception: exception ? JSON.stringify(exception) : null
      }]);
  };

  Logger.prototype.clientTrace = function(eventName, eventData, code, message, exception) {
    collectTelemetry(
      this.armEndpoint,
      [{
        eventType: 'trace',
        eventId: this.sessionId,
        eventTimestamp: new Date().toISOString(),
        eventName: eventName,
        eventData: $.extend(eventData, this.baseEventData),
        code: code,
        message: message,
        exception: exception ? JSON.stringify(exception) : null
      }]);
  };

  Logger.prototype.clientTelemetry = function(eventName, eventProperties, eventMeasurements, durationInMs) {
    eventProperties = $.extend(eventProperties, this.baseEventData);
    var eventData = $.extend(eventProperties, eventMeasurements);
    collectTelemetry(
      this.armEndpoint,
      [{
        eventType: 'telemetry',
        eventId: this.sessionId,
        eventTimestamp: new Date().toISOString(),
        eventName: eventName,
        eventData: eventData,
        durationInMilliseconds: durationInMs
      }]);

      var durationLabel = eventName + ".DURATION";
      if (durationLabel.indexOf("ACC.") === 0) {
        durationLabel = durationLabel.substring("ACC.".length);
      }

      eventMeasurements[durationLabel] = durationInMs;
      this.appInsights.trackEvent(eventName, eventProperties, eventMeasurements);
      this.appInsights.trackMetric(
        durationLabel, // name
        durationInMs, // value
        null, // count
        null, // min
        null, // max
        null, // stdDev
        eventProperties // properties
      );
  };

  Logger.prototype.clientRequest = function(eventName, eventData, durationInMs, httpMethod, targetUri, apiVersion, clientRequestId, serviceRequestId, contentLength, httpStatusCode) {
    eventData = $.extend(eventData, this.baseEventData);
    collectTelemetry(
      this.armEndpoint,
      [{
        eventType: 'request',
        eventId: this.sessionId,
        eventTimestamp: new Date().toISOString(),
        eventName: eventName,
        eventData: eventData,
        durationInMilliseconds: durationInMs,
        httpMethod: httpMethod,
        targetUri: targetUri,
        apiVersion: apiVersion,
        clientRequestId: clientRequestId,
        serviceRequestId: serviceRequestId,
        contentLength: contentLength,
        httpStatusCode: httpStatusCode
      }]);

    var properties = $.extend({
      eventType: 'request',
      httpMethod: httpMethod,
      targetUri: targetUri,
      apiVersion: apiVersion,
      clientRequestId: clientRequestId,
      serviceRequestId: serviceRequestId,
      httpStatusCode: httpStatusCode
    }, eventData);

    var durationLabel = eventName + ".DURATION";
    if (durationLabel.indexOf("ACC.") === 0) {
      durationLabel = durationLabel.substring("ACC.".length);
    }

    var measurements = {
      contentLength: contentLength || 0
    };
    measurements[durationLabel] = durationInMs;

    this.appInsights.trackEvent(eventName, properties, measurements);
    this.appInsights.trackMetric(
      durationLabel, // name
      durationInMs, // value
      null, // count
      null, // min
      null, // max
      null, // stdDev
      properties // properties
    );
  };

  return Logger;
})();