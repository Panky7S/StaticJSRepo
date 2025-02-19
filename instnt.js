/* eslint-disable no-undef */
// Starting point
if (!window?.instnt) {
  window.instnt = {};
}

/*  Compare Version Strings */
instnt.compareVersionStrings = (version1, version2 = '4.9.3') => {
  const v1 = version1.split('.');
  const v2 = version2.split('.');
  const maxLength = Math.max(v1.length, v2.length);
  for (let i = 0; i < maxLength; i++) {
    const num1 = parseInt(v1[i] || 0);
    const num2 = parseInt(v2[i] || 0);
    if (num1 > num2) {
      return 'GREATER';
    } else if (num1 < num2) {
      return 'SMALLER';
    }
  }
  return 'EQUAL'; // versions are equal
};

/* Get Environment Variable */
instnt.getEnvironmentVariable = (sdkAssetRoot) => {
  const parts = sdkAssetRoot?.split('/');
  const environment = parts && parts[parts.length - 1];
  return environment;
};

/* Console Message to backend logger */

instnt.logRequestToServer = (messagePayload) => {
  const url = serviceURL + '/public/sdklogs/';
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      transactionId: instnt.instnttxnid
    },
    mode: 'cors',
    cache: 'default',
    body: JSON.stringify(messagePayload)
  });
};

/** Remote Logging With Buffer Size And Interval **/
// Custom logger with buffer and flush interval
function InstntRemoteLogger() {
  this.logBuffer = [];
  this.bufferSize = 10;
  this.flushInterval = 5000; // Adjust as needed (in milliseconds)

  // Function to log messages
  this.addLog = function (message) {
    this.logBuffer.push(message);
    // Check if the buffer size has reached a certain threshold
    if (this.logBuffer.length >= this.bufferSize) {
      this.flush();
    }
  };

  this.log = function (message, data) {
    if (sdkLogsLevel === 'DEBUG') {
      const logPayload = {
        logLevel: 'DEBUG',
        message: message,
        data: JSON.stringify(data)
      };
      this.addLog(JSON.stringify(logPayload));
    }
    if (data) {
      console.log(message, data);
    } else {
      console.log(message);
    }
  };

  this.info = function (message, data) {
    if (['INFO', 'DEBUG'].includes(sdkLogsLevel)) {
      const infoPayload = {
        logLevel: 'INFO',
        message: message,
        data: JSON.stringify(data)
      };
      this.addLog(JSON.stringify(infoPayload));
    }
    if (data) {
      console.info(message, data);
    } else {
      console.info(message);
    }
  };

  this.warn = function (message, data) {
    if (['WARN', 'INFO', 'DEBUG'].includes(sdkLogsLevel)) {
      const warnPayload = {
        logLevel: 'WARN',
        message: message,
        data: JSON.stringify(data)
      };
      this.addLog(JSON.stringify(warnPayload));
    }
    if (data) {
      console.warn(message, data);
    } else {
      console.warn(message);
    }
  };

  this.error = function (message, data) {
    if (['ERROR', 'WARN', 'INFO', 'DEBUG'].includes(sdkLogsLevel)) {
      const errorPayload = {
        logLevel: 'ERROR',
        message: message,
        data: JSON.stringify(data)
      };
      this.addLog(JSON.stringify(errorPayload));
    }
    if (data) {
      console.error(message, data);
    } else {
      console.error(message);
    }
  };

  // Function to flush the buffer
  this.flush = function () {
    if (this.logBuffer.length > 0) {
      // Send the log entries to the remote server (replace with your implementation)
      instnt.logRequestToServer(this.logBuffer.join(''));

      // Clear the buffer after flushing
      this.logBuffer = [];
    }
  };

  // Function to periodically flush the buffer
  this.startFlushInterval = function () {
    setInterval(this.flush.bind(this), this.flushInterval);
  };

  // Initialize flush interval
  this.startFlushInterval();
}

/** Initializing Instnt Remote Logger */

instnt.remoteLogger = new InstntRemoteLogger();

/* Binding Function at instnt scope level */

/* instnt.getDeviceType --- to get device type on which SDK is running */
instnt.getDeviceType = (userAgent) => {
  const ua = userAgent;
  if (/(tablet|ipad|playbook|silk)|(android(?!.*mobi))/i.test(ua)) {
    return TABLET;
  }
  if (
    /Mobile|iP(hone|od)|Android|BlackBerry|IEMobile|Kindle|Silk-Accelerated|(hpw|web)OS|Opera M(obi|ini)/.test(
      ua
    )
  ) {
    return MOBILE;
  }
  return DESKTOP;
};

/* instnt.emit --- receive event at SDK level ex: react, angular */

instnt.getSkipVendorLoadingFlag = () => {
  if (['sandbox.acmebank.org'].includes(window?.location?.hostname)) {
    return true;
  }
  return false;
};

instnt.skipVendorLoading = instnt.getSkipVendorLoadingFlag();

instnt.compareAIDVersionWithLatestAID = (idmetrics_version) =>
  instnt.compareVersionStrings(idmetrics_version);

instnt.environmentName = (SdkAssetRoot) =>
  instnt.getEnvironmentVariable(SdkAssetRoot);

instnt.onEvent = window.instntSettings?.onEvent || window.onInstntEvent;

instnt.emit = async (event) => {
  instnt.remoteLogger.info(`Instnt Event: ${JSON.stringify(event)}`);
  if (instnt.onEvent) {
    const eventType = event?.type ? event.type : event.event_type;
    const eventData = event?.data ? event.data : event.event_data;
    const updatedEvent = { ...event, type: eventType, data: eventData };
    instnt.onEvent(updatedEvent);
  }
};

/* instnt.load_scripts --- using load script function to run multiple script simultaneously */
instnt.load_scripts = async (script_urls) => {
  function load(script_url) {
    return new Promise(function (resolve, reject) {
      if (instnt.load_scripts.loaded.has(script_url)) {
        resolve();
      } else {
        var script = document.createElement('script');
        script.onload = resolve;
        script.src = script_url;
        document.head.appendChild(script);
      }
    });
  }
  var promises = [];
  for (const script_url of script_urls) {
    promises.push(load(script_url));
  }
  await Promise.all(promises);
  for (const script_url of script_urls) {
    instnt.load_scripts.loaded.add(script_url);
  }
};

instnt.load_scripts.loaded = new Set();

/* instnt.initVendorCall  */
instnt.initVendorCall = async () => {
  instnt.remoteLogger.log('inside init()', Date());
  instnt.remoteLogger.log('loading premodule  init()', Date());
  const deviceType = instnt.getDeviceType(instnt.userAgent);
  if (!instnt.skipVendorLoading) {
    //await instnt.initImageProcessor();
    await instnt.load_scripts([
      'https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js'
    ]);
    // await instnt.load_scripts([
    //   SdkAssetRoot +
    //     '/assets/scripts/authenticid/sdk/IDMetricsCaptureFramework-' +
    //     idmetrics_version +
    //     '.js',
    //   SdkAssetRoot + '/assets/scripts/collector.js'
    // ]);
    // await instnt.initFingerprintJS();
    //await instnt.initBehaviosecSDK();
    //instnt.getInstntBase64String();
  }
  instnt.remoteLogger.log('premodule loading finished', Date());
  let event;
  if (instnt.isAsync) {
    instnt.pollEventsInterval = setInterval(instnt.pollEvents, 3000);
  } else {
    event = {
      event_type: 'transaction.initiated',
      event_data: { instnt }
    };
    instnt.emit(event);
    instnt.remoteLogger.log('Instnt initialized');
  }
  instnt.remoteLogger.log(' init finished', Date());
};

/** instnt.init-- Call public API to get JSON response */
instnt.init = async (formKey, serviceURL, idmetrics_version, instnttxnid) => {
    let url = serviceURL + '/public/transactions?sdk=react&format=json';
    if (idmetrics_version && idmetrics_version.length > 0) {
        url += '&idmetrics_version=' + idmetrics_version;
    }
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          form_key: formKey,
          hide_form_fields: true,
          redirect: false,
          instnttxnid: instnttxnid
        }),
      });
      const data = await response.json();
      if (response.ok) {
        let event = {
          event_type: 'transaction.initiated',
          event_data: { data },
        }
        instnt.emit(event);
        } else {
          instnt.remoteLogger.log(' init finished', Date())  
          instnt.remoteLogger.error('error', 'Error processing :', `${url}, ${data}`);
        }
    } catch (error) {
      instnt.remoteLogger.error('error', 'Error while initiating signup transaction process');
      instnt.remoteLogger.error('error', 'Error while connecting to :', `${url}, ${error}`);
    }
}
