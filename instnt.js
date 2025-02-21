/* eslint-disable no-undef */
// Starting point
if (!window?.instnt) {
  window.instnt = {};
}

/** Initialize variable from JSON */

instnt.documentVerification = false; 
instnt.fingerprint_txt = null;
instnt.formKey = null;
instnt.instnttxnid = null;
/** aidWhitelistedDomain configure for workflow */
instnt.aidWhitelistedDomain = "";
/** defaultDevAidLicenseKey getting from parameter store */
instnt.defaultDevAidLicenseKey = ""
/* Checks needed because we are getting "true" and false as value from DB */
instnt.isAsync = false;
/* Checks needed because we are getting "true" and false as value from DB */
instnt.otpVerification = false;
instnt.userAgent = window.navigator.userAgent;
instnt.sdkAssetRoot = null;
instnt.serviceURL = "";
instnt.invitation_url = "";
instnt.idmetrics_version = "";
instnt.fingerprintjsBrowserToken = "";
instnt.getDefaultInstntBase64String = "";
instnt.documentSettingsOverride = {};
instnt.selfieSettingsOverride = {};


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
  const url = instnt.serviceURL + '/public/sdklogs/';
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
function InstntRemoteLogger(sdkLogsLevel) {
  this.logBuffer = [];
  this.bufferSize = 10;
  this.flushInterval = 5000; // Adjust as needed (in milliseconds)
  this.sdkLogsLevel = sdkLogsLevel;

  // Function to log messages
  this.addLog = function (message) {
    this.logBuffer.push(message);
    // Check if the buffer size has reached a certain threshold
    if (this.logBuffer.length >= this.bufferSize) {
      this.flush();
    }
  };

  this.log = function (message, data) {
    if (this.sdkLogsLevel === 'DEBUG') {
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
    if (['INFO', 'DEBUG'].includes(this.sdkLogsLevel)) {
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
    if (['WARN', 'INFO', 'DEBUG'].includes(this.sdkLogsLevel)) {
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
    if (['ERROR', 'WARN', 'INFO', 'DEBUG'].includes(this.sdkLogsLevel)) {
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

instnt.initializeLogger = (sdkLogsLevel) => {
  instnt.remoteLogger = new InstntRemoteLogger(sdkLogsLevel);
}


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

/* instnt.getToken --- to get token for API calling which include fingerprint and behaviosec data */
instnt.getToken = () => {
  const data = {};
  data['form_key'] = instnt.formKey; 
  data['client_referer_url'] = window.location.href; 
  data['client_referer_host'] = window.location.hostname;
  if(!instnt.skipVendorLoading){
    if(document.getElementById("fingerprint_txt")){
      data['fingerprint'] = document.getElementById("fingerprint_txt").value;
    }else{
      data['fingerprint'] = instnt.fingerprint_txt;
    }
    instnt.remoteLogger.info(`fingerprint data: ${data.fingerprint}`)
    data['bdata'] = window.bw?.getData();
  }
  data['client_ip'] = '{{ client_ip }}'; 
  data['expires_on'] = '{{ expires_on }}';   
  if(window.instnt && window.instnt.debug) {
    data['debug'] = window.instnt.debug;
  }
  const token = btoa(JSON.stringify(data));
  return token;
}

/* instnt.submitSignupData --- to submit form data to complete transaction */
instnt.submitSignupData = (data = {}, redirect) => {
  data['instnt_token'] = instnt.getToken();
  data['instnttxnid'] = instnt.instnttxnid;
  const updatedData = {...data, js_sdk_submit_function: 'submitSignupData' };
  instnt.remoteLogger.info(`submitSignupData ${JSON.stringify(updatedData)}`);
  const url = instnt.serviceURL + '/public/transactions/' + instnt.instnttxnid;
  const submitRequest = new Request(url, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    method: 'PUT',
    mode: 'cors',
    cache: 'default',
    body: JSON.stringify(updatedData),
  });
  this.submitTransaction(submitRequest, redirect);
}

/* instnt.submitVerifyData* --- to verify transactions */
instnt.submitVerifyData = (data = {}, redirect) => {
  data['instnt_token'] = instnt.getToken();
  data['instnttxnid'] = instnt.instnttxnid;
  const url = instnt.serviceURL + '/public/transactions/verify/' + instnt.instnttxnid;
  const submitRequest = new Request(url, {
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    method: 'PUT',
    mode: 'cors',
    cache: 'default',
    body: JSON.stringify(data),
  });
  this.submitTransaction(submitRequest, redirect);
}

/* instnt.callingTransactionStatus --- recursive call with number of retries and specified timeout */
instnt.callingTransactionStatus = async (retries,timeout) => {
  const url = instnt.serviceURL + '/public/transactions/' + instnt.instnttxnid;
  instnt.remoteLogger.log('Instnt : Retries attempt', retries);
  return await fetch(url, { method: 'GET', headers: {'Accept': 'application/json'}})
  .then(async(response) => {
    if (response.status === 200) {
      const response_data = await response.json();
      let responsePromise = new Promise((resolve, reject) => {
        try {
          resolve(response_data);
        } catch (error) {
          reject(error);
        }
      });
      if(response_data.status === 'processed') {
        return responsePromise;
      } else if(response_data.status === 'error') {
        instnt.remoteLogger.error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
        throw Error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
      } else {
        if (retries > 0) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          return instnt.callingTransactionStatus(retries - 1);
        } else {
          instnt.remoteLogger.error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
          throw Error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
        }
      }
    } else {
      if (retries > 0) {
        await new Promise(resolve => setTimeout(resolve, 5000));
        return instnt.callingTransactionStatus(retries - 1);
      } else {
        instnt.remoteLogger.error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
        throw Error("Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org");
      }
    }
  })
}

/* instnt.getResponseStatusBased --- get response based on status code or go into recursive call instnt.callingTransactionStatus */
instnt.getResponseStatusBased = response =>{
  const statusCode = response.status;
  instnt.remoteLogger.log('Instnt : getResponseStatusBased',statusCode);
  switch(statusCode){
    case 200:
      return response.json();
    case 529:
    case 504:
      return instnt.callingTransactionStatus(retries = 10,timeout = 5000)
    default:
      return response.json();
  }
}

/* submitTransaction --- calling submit transaction API end point and calling instnt.getResponseStatusBased on successs */
function submitTransaction(submitRequest, redirect) {
  let data;
  let status;
  let errorMessage;
  fetch(submitRequest).then(response => instnt.getResponseStatusBased(response)).then((response) => {
    instnt.remoteLogger.log('Instnt : response from submitRequest', response);
    if (response) {
      if (response.data) {
        data = response.data;
      } else {
        if(response.detail && response.message){/** To Handle Error handling response from backend*/
          errorMessage = response.message;
        }else if(!response.errorMessage){/** To Handle the response we are getting from retry mechanism*/
          data = { decision: response.decision, form_key: response.form_key, status: '1' };
        }else{
          data = {}
        }
        if(response.errorMessage){
          errorMessage = response.errorMessage;
        }
      }
    }
    //Check for error (this check is from the old function, may be able to be removed or changed)
    if (data && data.status && data.status == '1') {
      instnt.remoteLogger.log({ console_log: 'data.status is 1', status: data.status });
      if (redirect && data.url) {
        instnt.remoteLogger.log({ console_log: 'data.url is good', url: data.url });
        if (isIframe)
          window.top.location.href = data.url;
        else
          window.location.href = data.url;
      }
      if (!instnt.isAsync) {
        if (instnt.onResponse) {
          instnt.onResponse(null, data)
        };
        instnt.remoteLogger.info('Instnt : emiting transaction.processed');
        instnt.emit({
          type: 'transaction.processed',
          data,
          status: response.status,
        })
      }
          // ERRORS
    } else {
      instnt.remoteLogger.error('Instnt : There was an Error in the response');
      instnt.emit({
        type: 'transaction.error',
        data: { 'message': errorMessage ? errorMessage : response.errorMessage, 'type': 'error' }
      });
    }
  }).catch ((err) => {
    instnt.remoteLogger.error('Instnt : Error processing signup request. Please retry and if the issue persist, contact support@instnt.org');
    instnt.remoteLogger.error('Instnt : error calling submitFormURL, URL: ', submitFormURL);
    if ((instnt.isAsync)) {
            // Ignore timeout for asynchronous invocation
        instnt.stopEventPolling();
    }
    if (instnt.onResponse) {
      instnt.onResponse(err, null)
    };
    instnt.emit({
      type: 'transaction.error',
      data: { 'message': 'Error processing signup request. Please retry and if the issue persist, contact support@instnt.org', 'type': 'error' }
    });      
  });
}

/* instnt.verifyDocuments --- verify upload document */
instnt.verifyDocuments = async (documentType) => {
  instnt.remoteLogger.log('Instnt : Verifying documents')
  const context = "verifying documents";
  const url = instnt.serviceURL + '/public/transactions/' + instnt.instnttxnid + '/attachments/verify/';
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        formKey: instnt.formKey,
        documentType: documentType,
        documentSettingsOverride: instnt.documentSettingsOverride,
        selfieSettingsOverride: instnt.selfieSettingsOverride
      })
    });
    if(response.ok) {
      instnt.emit({
        type: 'document.verification-initiated',
        data: instnt.instnttxnid, // this endpoint returns jwt which is nothing but encoded instnttxnid 
      });
    } else {
      const data = await response.json();
      instnt.remoteLogger.error("Instnt : Error processing " + url, data);
      instnt.emit({
        type: 'document.error',
        data: { 'message': 'Received error: ' + data.errorMessage + ' while ' + context, 'status': data.status, 'type': 'error' }
      });
    }
  } catch (error) {
    instnt.remoteLogger.error("Instnt : Error while calling verifyDocument end point");
    instnt.remoteLogger.error("Instnt : Error while connecting to " + url, error);
    instnt.emit({
      type: 'document.error',
      data: { 'message': 'Received error: ' + error.message + ' while ' + context, 'type': 'error' }
    });
  }
}

/* instnt.getInvitationURLForVC --- get invitation url for VC (At the end of the successful signup we allow the user to download the VC)*/
instnt.getInvitationURLForVC = async (transactionId = instnt?.instnttxnid) => {
  let invitation_url;
  try {
    if (!transactionId) {
      instnt.remoteLogger.error("Instnt : Not Able to found transactionId to get invitation_url");
      return invitation_url;
    }
    const response = await fetch(`${instnt.serviceURL}/ssi/issuer/invitation/${transactionId}/`,{
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    const invitation = await response.json();
    instnt.remoteLogger.log("Instnt : getInvitation: ", invitation);
    invitation_url = invitation?.invitation_url;
    return invitation_url;
  } catch (e) {
    instnt.remoteLogger.error("Instnt : Error while calling getInvitationURLForVC");
    instnt.remoteLogger.error(e);
    return invitation_url;
  }
}

/* instnt.getInvitationURLForSignup --- get invitation url for signup (When users attempt to signup, we provide option to signup using VC)*/
instnt.getInvitationURLForSignup = async (transactionId = instnt?.instnttxnid) => {
  let invitation_url;
  try {
    if (!transactionId) {
      instnt.remoteLogger.error("Instnt : Not Able to found transactionId to get invitation_url for signup");
      return invitation_url;
    }
    const response = await fetch(`${instnt.serviceURL}/ssi/verifier/invitation/${transactionId}/`,{
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    const invitation = await response.json();
    instnt.remoteLogger.log("Instnt : getInvitation: ", invitation);
    invitation_url = invitation?.invitation_url;
    return invitation_url;
  } catch (e) {
    instnt.remoteLogger.error("Instnt : Error while calling getInvitationURLForSignup");
    instnt.remoteLogger.error(e);
    return invitation_url;
  }
}

/* instnt.getInvitationURLForLogin --- get invitation url for login (When users attempt to login, we provide option to login using VC)*/
instnt.getInvitationURLForLogin = async (transactionId = instnt?.instnttxnid) => {
  let invitation_url;
  try {
    if (!transactionId) {
      instnt.remoteLogger.error("Instnt : Not Able to found transactionId to get invitation_url for login");
      return invitation_url;
    }
    const response = await fetch(`${instnt.serviceURL}/ssi/verifier/auth/invitation/${transactionId}/`,{
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    const invitation = await response.json();
    instnt.remoteLogger.log("Instnt : getInvitation: ", invitation);
    invitation_url = invitation?.invitation_url;
    return invitation_url;
  } catch (e) {
    instnt.remoteLogger.error("Instnt : Error while calling getInvitationURLForLogin");
    instnt.remoteLogger.error(e);
    return invitation_url;
  }
}

/* instnt.buildErrorMessage --- build error message for OTP response */
instnt.buildErrorMessage = (process, context, data, responseStatus) => {
  let errorMessage = 'Received error while ' + context;
  if(data && data.response && data.response.errors) {
    if(data.response.errors.length > 0) {
      // When twilio response has variable valid False then it had something error in variable errors
      var str = data.response.errors[0];
      var patt = new RegExp(/The requested resource[\s\S]*VerificationCheck was not found/gmi);
      var isMatched = patt.test(str);   
      if(isMatched) {
        errorMessage = ' The OTP code has expired. Please request a new code to verify your mobile number.'; 
      } else {
        errorMessage = data.response.errors[0];
      }
    } 
  } else {
    errorMessage += " Invalid response format";
  }
  return {
    type: process + '.error',
    data: { 'message': errorMessage, 'status': responseStatus, 'type': 'error' }
  }
}

/* instnt.sendOTP --- send otp for specific number */
instnt.sendOTP = async (mobileNumber) => {
  const context = "sending OTP";
  if (!instnt.otpVerification) {
    instnt.remoteLogger.error('Instnt : OTP Verification is disabled');
    instnt.emit({
      type: 'otp.error',
      data: { 'message': 'OTP Verification is disabled. Please enable OTP verification on Instnt dashboard', 'type': 'error' }
    });
    return false;
  }
  //Check is mobile number field available then validate it
  if(mobileNumber.length < 1) { 
    return false;
  }
  const url = instnt.serviceURL + '/public/transactions/'+ instnt.instnttxnid +'/otp';
  
  const requestPayload = {
    "phone" : mobileNumber
  }
  instnt.remoteLogger.log("Instnt : sendOTP requestPayload: ", requestPayload);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestPayload)
    });
    const data = await response.json();
    if(response.ok) {
      if(data && data.response && data.response.errors && data.response.errors.length == 0) {
        instnt.emit({
          type: 'otp.sent',
          data: { mobileNumber: mobileNumber, "instnttxnid" :instnt.instnttxnid},  
        });
      } else {
          instnt.emit(instnt.buildErrorMessage('otp', context, data, response.status));
      }  
    } else {
        instnt.emit(instnt.buildErrorMessage('otp', context, data, response.status));
    }
  } catch (error) {
    instnt.remoteLogger.error("Instnt : Error while calling sendOTP end point");
    instnt.remoteLogger.error("Instnt : Error while connecting to " + url, error);
    instnt.emit({
      type: 'otp.error',
      data: { 'message': 'Received error: ' + error.message + ' while ' + context, 'type': 'error' }
    });
  }
}

/* instnt.verifyOTP --- verify otp we received from instnt.sendOTP */
instnt.verifyOTP = async (mobileNumber, otpCode) => {
  const context = "verifying OTP";
  const url = instnt.serviceURL + '/public/transactions/'+ instnt.instnttxnid +'/otp';
  if (typeof otpCode !="string") {
    instnt.emit({
      type: 'otp.error',
      data: { 'message': 'Received invalid otpCode : ' + otpCode + ' otpCode has to be a string'}
    });
    return;
  }
  if (otpCode.length != 6) {
    instnt.emit({
      type: 'otp.error',
      data: { 'message': 'Received invalid otpCode : ' + otpCode + ' otpCode has to be a string of 6 characters'}
    });
    return;
  }

  const requestPayload = {
    "phone" : mobileNumber,
    "otp" : otpCode,
    "isVerify" : true
  }
  instnt.remoteLogger.log("Instnt : verifyOTP requestPayload: ", requestPayload);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestPayload)
    });
    const data = await response.json();
    if(response.ok) {
      if(data && data.response && data.response.errors && data.response.errors.length == 0) {
        instnt.emit({
          type: 'otp.verified',
          data: { "mobileNumber": mobileNumber, "otpCode": otpCode, "instnttxnid" :instnt.instnttxnid},  
        });
      } else {
          instnt.emit(instnt.buildErrorMessage('otp', context, data, response.status));
      }
    } else {
        instnt.emit(instnt.buildErrorMessage('otp', context, data, response.status));
    }
  } catch (error) {
    instnt.remoteLogger.error("Instnt : Error while calling verifyOTP end point");
    instnt.remoteLogger.error("Instnt : Error while connecting to " + url, error);
    instnt.emit({
      type: 'otp.error',
      data: { 'message': 'Received error: ' + error.message + ' while ' + context, 'type': 'error' }
    });
  }
}

/* instnt.getTransactionStatus --- getTransactionStatus for specific transaction */
instnt.getTransactionStatus = async (transaction_id) => {
  instnt.remoteLogger.log('Instnt : Getting transaction status for ' + transaction_id);
  const context = 'fetching transaction status';
  const url = instnt.serviceURL + '/public/transactions/' + transaction_id;
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    const data = await response.json();
    if (response.ok) {
      instnt.remoteLogger.log("Instnt : transaction status: ", data);
      return data;
    } else {
      instnt.remoteLogger.error("Instnt : Error processing " + url, data);
      instnt.emit({
        type: 'transaction.error',
        data: { 'message': 'Received error: ' + data.errorMessage + ' while ' + context, 'status': data.status, 'type': 'error' }
      });
    }
  } catch (error) {
    instnt.remoteLogger.error("Instnt : Error while connecting to " + url, error);
    instnt.emit({
      type: 'transaction.error',
      data: { 'message': 'Received error: ' + error.message + ' while ' + context, 'type': 'error' }
    });
  }
}

/* instnt.endSignupSession --- end behaviosec/signup transaction */
instnt.endSignupSession = () => {
  if (instnt) {
    //stop any previous event polling
    // //instnt.isAsync && instnt.stopEventPolling();
    window.bw && window.bw.stopMonitor();
  }
}

/* instnt.captureDocument --- capture document */
instnt.captureDocument = (
  documentSettings = {},
  autoUpload = true, 
  captureFrameworkDebug,
) => {
  let modifiedDocumentSettings = documentSettings;
  if(instnt.compareAIDVersionWithLatestAID(instnt.idmetrics_version) === 'GREATER' && !modifiedDocumentSettings.hasOwnProperty('companyLogo')){
    modifiedDocumentSettings = {...modifiedDocumentSettings, companyLogo: instnt.getDefaultInstntBase64String};
  }
  instnt.documentSettingsOverride = modifiedDocumentSettings;
  if(window.documentCapture) {
    window.documentCapture(
      modifiedDocumentSettings.documentType,
      modifiedDocumentSettings.documentSide,
      modifiedDocumentSettings.captureMode,
      autoUpload,
      captureFrameworkDebug,
      modifiedDocumentSettings
    );
  } else {
    return "Instnt SDK not initialized properly. Please Initiate Instnt SDK before calling this function";
  }
}

/* instnt.captureSelfie --- capture selfie */
instnt.captureSelfie = (
  selfieSettings = {}, 
  autoUpload = true, 
  captureFrameworkDebug
) => {
  let modifiedSelfieSettings = selfieSettings;
  instnt.selfieSettingsOverride = modifiedSelfieSettings;
  if(window.selfieCapture) {
    window.selfieCapture(modifiedSelfieSettings.captureMode, autoUpload, captureFrameworkDebug, modifiedSelfieSettings);
  } else {
    return "Instnt SDK not initialized properly. Please Initiate Instnt SDK before calling this function";
  }
}

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

instnt.getSkipVendorLoadingFlag = () => {
  if(['sandbox.acmebank.org'].includes(window?.location?.hostname)){
    return true;
  }
  return false;
}

instnt.skipVendorLoading = instnt.getSkipVendorLoadingFlag();

/* instnt.initFingerprintJS --- initialize fingerprintJS script and assign its value */
instnt.initFingerprintJS = async () => {
  const fpPromise = import(`https://fpjscdn.net/v3/${instnt.fingerprintjsBrowserToken}`).then(FingerprintJS => FingerprintJS.load())
  fpPromise.then(fp => fp.get()).then(result => {
    const stringifyResult = JSON.stringify(result);
    if(document.getElementById("fingerprint_txt")){
      document.getElementById("fingerprint_txt").value= stringifyResult;
    }else{
      instnt.fingerprint_txt = stringifyResult;
    }
    instnt.remoteLogger.info(`Instnt Fingerprint Initialization with ${stringifyResult}`)
    instnt.remoteLogger.info(`Instnt : FingerprintJS initialized with transactionId ${instnt.instnttxnid}`)
          
  })
};

/* instnt.base64toBlob --- convert base64 image into blob */
instnt.base64toBlob = (b64Data, sliceSize = 512) => {
  const byteArrays = [];
  const contentString = b64Data.split(',')[1];
  const mimeString = b64Data.split(',')[0].split(':')[1].split(';')[0]
  const byteCharacters = atob(contentString);
  for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
    const slice = byteCharacters.slice(offset, offset + sliceSize);
    const byteNumbers = new Array(slice.length);
    for (let i = 0; i < slice.length; i++) {
      byteNumbers[i] = slice.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    byteArrays.push(byteArray);
  }
  const blob = new Blob(byteArrays, { type: mimeString });
  return blob;
}

/* instnt.uploadAttachment --- upload document for specific transactions */
instnt.uploadAttachment = async (attachment, documentSide, isSelfie = false, documentType = "DRIVERS_LICENSE") => {
  const context = "uploading document ";
  /* getUploadUrl for document upload */
  const getUploadUrl = async (docSuffix)  => {
    const context = "initiating document upload ";
    const url = instnt.serviceURL + '/public/transactions/' + instnt.instnttxnid + '/attachments/';
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          transaction_attachment_type: "IMAGE",
          document_type: documentType,
          doc_suffix : docSuffix,
          instnttxnid: instnt.instnttxnid,
        })
      });
      const data = await response.json();
      if (response.ok) {
        return data.s3_key;
      } else {
        instnt.remoteLogger.error("Instnt : Error processing " + url, data);
        instnt.emit({
            type: 'document.error',
            data: { 'message': 'Received error: ' + data.errorMessage + ' while ' + context, 'status': data.status, 'type': 'error' }
        });
      }
    } catch (error) {
      instnt.remoteLogger.error("Instnt : Error while calling getUploadUrl for documents");
      instnt.remoteLogger.error("Instnt : Error while connecting to " + url, error);
      instnt.emit({
        type: 'document.error',
        data: { 'message': error.message + ' ' + url, 'type': 'error' }
      });
    }
  }
  let presignedS3Url = null;
  try {
    let docSuffix = 'F';
    if(documentSide && documentSide === 'Back') {
      docSuffix = 'B';
    }
    if(isSelfie) {
      docSuffix = 'S';
    }
    presignedS3Url = await getUploadUrl(docSuffix);
    const file_name = window.instnt.instnttxnid + docSuffix + '.jpg';
    const file = new File([window.instnt.base64toBlob(attachment)], file_name, { type: "image/jpeg" });
    const response = await fetch(presignedS3Url, {
      method: 'PUT',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'image/jpeg', 
      },
      body: file
    });
    const data = await response.text();
    if (response.ok) {
      instnt.emit({
        type: 'document.uploaded',
        data: {
          attachment,
          documentSide,
          isSelfie
        }
      });
    } else {
      instnt.remoteLogger.error("Error processing " + presignedS3Url, data);
      instnt.emit({
        type: 'document.error',
        data: { 'message': 'Received error: ' + data.errorMessage + ' while ' + context, 'status': data.status, 'type': 'error' }
        });
      }
  } catch (error) {
    instnt.remoteLogger.error("Instnt : Error while calling presignedS3Url end point");
    instnt.remoteLogger.error("Instnt : Error while connecting to " + presignedS3Url, error);
    instnt.emit({
      type: 'document.error',
      data: { 'message': 'Received error: ' + error.message + ' while ' + context, 'type': 'error' }
    });
  }
}

/* instnt.initImageProcessor --- initImageProcessor */
instnt.initImageProcessor = () => {
  window.documentCapture = (
    documentType,
    documentSide,
    captureMode,
    autoUpload,
    captureFrameworkDebug,
    customDocumentSettings = {}
  ) => {
    window.captureFrameworkDebug = captureFrameworkDebug;
    const defaultDocumentSettings = new window.DocumentSettings();
    defaultDocumentSettings.documentType = documentType;
    defaultDocumentSettings.documentSide = documentSide;
    defaultDocumentSettings.captureMode = captureMode;
    //defaultDocumentSettings.setManualTimeout = 8;

    const documentSettings = Object.assign(defaultDocumentSettings, customDocumentSettings);
    const captureResult = new window.CaptureResult();
    captureResult.setOnAborted(function (error) {
      instnt.remoteLogger.error(error);
      window.instnt.emit({
          type: 'document.capture-cancelled',
          data: { documentType, error },
          });
      });
    captureResult.setOnEvent(function (statusCode, statusCodeMessage, data) {
      instnt.remoteLogger.log("Instnt : OnEvent()", data);
      window.instnt.emit({
        type: 'document.capture-onEvent',
        data: {
          documentSettings,
          statusCode,
          statusCodeMessage,
          data
        }
      });
      captureResult.continue();
    });

    captureResult.setOnFinish(function () {              
      if (autoUpload) {
        window.instnt.uploadAttachment(captureResult.result, documentSettings.documentSide);
      } 
      window.instnt.emit({
        type: 'document.captured',
        data: {
          documentSettings,
          captureResult,
        }
      });
    });

    captureResult.setOnCaptureModeChange(function (captureMode, configuration) {
      instnt.remoteLogger.info("Instnt : OnCaptureModeChange()");
      instnt.remoteLogger.info(captureMode);
      instnt.remoteLogger.info(configuration);
    });
    window.capture.scanDocument(documentSettings, captureResult);
  }

  window.selfieCapture = (
    captureMode,
    autoUpload,
    captureFrameworkDebug,
    customSelfieSettings = {}
  ) => {
    window.captureFrameworkDebug = captureFrameworkDebug;
    const defaultSelfieSettings = new window.SelfieSettings();
    defaultSelfieSettings.useBackCamera = false;
    defaultSelfieSettings.captureMode = captureMode;
    //defaultSelfieSettings.setManualTimeout = 30;
    const selfieSettings = Object.assign(defaultSelfieSettings, customSelfieSettings); 
    const captureResult = new window.CaptureResult();
    captureResult.setOnAborted(function (error) {
      window.instnt.emit({
        type: 'document.capture-cancelled',
        data: { error },
      });
    });

    captureResult.setOnEvent(function (statusCode, statusCodeMessage, data) {
      instnt.remoteLogger.log("Instnt : OnEvent()", data);
      window.instnt.emit({
        type: 'document.capture-onEvent',
        data: {
          selfieSettings,
          statusCode,
          statusCodeMessage,
          data
        }
      });
      captureResult.continue();
    });
    
    captureResult.setOnFinish(function () {
      const file_name = window.instnt.instnttxnid + 'S.jpg';
      const file = new File(
        [window.instnt.base64toBlob(captureResult.result)],
        file_name,
        { type: "image/jpeg" }
      );
      if (autoUpload) {
        window.instnt.uploadAttachment(captureResult.result, null, true);
      } 
      window.instnt.emit({
        type: 'document.captured',
        data: {
          selfieSettings,
          captureResult
          }
      });
    });
    
    captureResult.setOnCaptureModeChange(function (captureMode, currentSettings) {
      instnt.remoteLogger.log("Instnt : OnCaptureModeChange()");
      instnt.remoteLogger.log('Instnt : captureMode: ' + JSON.stringify(captureMode));
      instnt.remoteLogger.log('Instnt : currentSettings: ' + JSON.stringify(currentSettings));
      window.instnt.emit({
        type: 'document.capture-modeChanged',
        data: {
          captureMode,
          currentSettings
        }
      });
    });
    window.capture.scanSelfie(selfieSettings, captureResult);
  }
  
  window.onCaptureFrameworkLoaded = () => {
    instnt.remoteLogger.info('Instnt : Document capture Framework loaded successfully');
    window.capture = window.IDMetricsCaptureFramework;
    window.capture.GetSDKVersion(function (x) { instnt.remoteLogger.info("Instnt : IDMetricsCaptureFramework v" + x + " loaded successfully"); });
    instnt.remoteLogger.log("Instnt : Device detected:", window.DeviceInfo);
    instnt.remoteLogger.log("Instnt : Device thresholds active:", window.deviceThreshold);
    if(instnt.compareAIDVersionWithLatestAID(instnt.idmetrics_version) === 'GREATER' || instnt.compareAIDVersionWithLatestAID(instnt.idmetrics_version) === "EQUAL"){
      const detectionProvider = 2;
      let devLicenseKey = undefined;
      if(instnt.aidWhitelistedDomain !== 'None' && instnt.aidWhitelistedDomain.length > 4){
        instnt.remoteLogger.info('Whitelisted Domain configured so no license key needed');
      }else{
        devLicenseKey = instnt.defaultDevAidLicenseKey;
        instnt.remoteLogger.info('Default AuthenticId Testing License key Applied');
      }
      window.rootResourcePath = instnt.sdkAssetRoot + `/assets/scripts/authenticid/sdk_resource/${instnt.idmetrics_version}/${instnt.environmentName(instnt.sdkAssetRoot)}`;
      window.capture.setDetectionProvider(detectionProvider, devLicenseKey).then(function () {
        // SDK is ready to be used.
        window.instnt.emit({
          type: 'document.capture-frameworkLoaded',
          data: { 
            deviceInfo: window.DeviceInfo,
            deviceThreshold: window.deviceThreshold
          },
        });
      });
      return ;
    }
    window.instnt.emit({
      type: 'document.capture-frameworkLoaded',
      data: { 
        deviceInfo: window.DeviceInfo,
        deviceThreshold: window.deviceThreshold
      },
    });
  }
  
  window.onCaptureFrameworkLoadFailed = () => {
    instnt.remoteLogger.log('Instnt : Document capture framework loading failed');
    window.instnt.emit({
      type: 'document.capture-frameworkLoadFailed',
      data: { 'message': 'Document capture framework loading failed. Please check browser console for detail.', 'type': 'error' }
    });
  }
  
  window.loadIDMDeviceThresholds = () => {
    instnt.remoteLogger.log("Instnt : loadDeviceThresholds()");
    return new Promise(function (resolve, reject) {
      resolve("Hello Need to look ");
    });
  }
}

/*  Get instnt base64 Image String */
instnt.getInstntBase64String = () =>{
  function getBase64ImageFromUrl(url, callback) {
    var img = new Image();
    img.crossOrigin = "Anonymous"; // This is important for cross-origin images
    img.onload = function() {
      var canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      var ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);
      var dataURL = canvas.toDataURL("image/png");
      callback(dataURL);
    };
    img.src = url;
  }
  const imageUrl = instnt.sdkAssetRoot + '/assets/scripts/image/instnt.png';
  getBase64ImageFromUrl(imageUrl, function(base64String) {
    instnt.getDefaultInstntBase64String = base64String;
  });
}

/* instnt.initBehaviosecSDK --- initialize behaviosecSDK script */
instnt.initBehaviosecSDK = async () => {
  window.bw.stopMonitor();
  window.bw.startMonitor({
    mouseLimit:1500
    });
  instnt.remoteLogger.info(`Instnt : Behaviosec initialized with transactionId ${instnt.instnttxnid}`);
}


/* instnt.initVendorCall  */
instnt.initVendorCall = async () => {
  if (!instnt.skipVendorLoading) {
    instnt.remoteLogger.log('loading premodule  init()', Date());
    if(instnt.documentVerification){
      // await instnt.initImageProcessor();
      // await instnt.load_scripts([instnt.sdkAssetRoot + '/assets/scripts/authenticid/sdk/IDMetricsCaptureFramework-' +  instnt.idmetrics_version + '.js'])
       await Promise.all([
        instnt.initImageProcessor(),
        instnt.load_scripts([instnt.sdkAssetRoot + '/assets/scripts/authenticid/sdk/IDMetricsCaptureFramework-' +  instnt.idmetrics_version + '.js'])
       ])
    }
    //await instnt.load_scripts([instnt.sdkAssetRoot + '/assets/scripts/collector.js'])
    await Promise.all([
      instnt.load_scripts([instnt.sdkAssetRoot + '/assets/scripts/collector.js']),
      instnt.initFingerprintJS(),
      instnt.initBehaviosecSDK()
    ]);
    // await instnt.initFingerprintJS();
    // await instnt.initBehaviosecSDK();
    instnt.getInstntBase64String();
    instnt.remoteLogger.log('premodule loading finished', Date());
  }
};

/* instnt.pollEvents --- get called for polling mechanism once instnt.isAsync is true */
instnt.pollEvents = async () => {
  let stopPolling = false;
  const terminalEventTypes = ['authentication.success','authentication.failed','transaction.accepted', 'transaction.rejected','transaction.review', 'transaction.failed'];
  if (instnt.instnttxnid) {
    const url = `${instnt.serviceURL}/public/transactions/${instnt.instnttxnid}/events?from=${instnt.pollEvents.lastTimestamp || 0}`;
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });
      const data = await response.json();
      instnt.pollEvents.lastTimestamp = data.to;
      const events = data.events;
      for (const event of events) {
        if(event.event_type === 'transaction.failed'){
          event.event_data.message = event.event_data.errorMessage;
          event.event_data.type = 'error';
        }
        const event_updated_data = {...event , event_data : {...event.event_data, instnt}};
        if(!(event.event_type === 'otp.sent' || event.event_type === 'otp.verified')){
          instnt.emit(event_updated_data)
        }
        if(event.event_type && terminalEventTypes.includes(event.event_type)) {
          stopPolling = true;
        }
      }
      stopPolling && instnt.stopEventPolling();
    } catch (error) {
      instnt.remoteLogger.error("Instnt : Error receiving events", error);
      instnt.stopEventPolling();
    }
  }
}

/** Start Polling */
instnt.startPolling = () =>{
  if (instnt.isAsync) {
    instnt.pollEventsInterval = setInterval(instnt.pollEvents, 3000);
  }
}

 /* instnt.stopEventPolling --- stop polling mechanism */
instnt.stopEventPolling = () => {
  if (instnt.pollEventsInterval) {
    try {
      clearInterval(instnt.pollEventsInterval);
    } catch (e) {
      instnt.remoteLogger.log(e);
    }
  };
}

/** instnt.init-- Call public API to get JSON response */
instnt.init = async (formKey, serviceURL, instnttxnid, idmetrics_version) => {
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
        /** Instnt Property Definition */
        instnt.documentVerification = data.document_verification;
        instnt.formKey = data.form_key_id;
        instnt.instnttxnid = data.instnttxnid;
        instnt.otpVerification = data.otp_verification;
        instnt.sdkAssetRoot = data.sdk_asset_root;
        instnt.invitation_url = data.invitation_url;
        instnt.serviceURL = data.backend_service_url;
        instnt.isAsync = data.form?.instnt_access;
        instnt.idmetrics_version = data.idmetrics_version;
        instnt.aidWhitelistedDomain = data.authenticID_license;
        instnt.defaultDevAidLicenseKey = data.default_authenticID_license;
        instnt.fingerprintjsBrowserToken = data.fingerprintjs_browser_token;
         /** Instnt Property Definition */
        let event = {
          event_type: 'transaction.initiated',
          event_data: { instnt },
        }
        instnt.emit(event);
        instnt.initializeLogger(data.sdk_log_level);
        instnt.initVendorCall();
        data.document_verification && instnt.startPolling();
        } else {
          instnt.remoteLogger.log(' init finished', Date())  
          instnt.remoteLogger.error('error', 'Error processing :', `${url}, ${data}`);
        }
    } catch (error) {
      instnt.remoteLogger.error('error', 'Error while initiating signup transaction process');
      instnt.remoteLogger.error('error', 'Error while connecting to :', `${url}, ${error}`);
    }
}
