// *****************************************************
// *****************************************************
// SUPPORT FOR SCANNING QR CODES

import jsQR from "./jsQR2.js";
import { decodeJWT } from "./credential.js";

import {
  mylog,
  myerror,
  settingsPut,
  settingsGet,
  settingsDelete,
  settingsDeleteAll,
  credentialsSave,
  credentialsDeleteCred,
  credentialsDelete,
  credentialsDeleteAll,
  credentialsGet,
  credentialsGetAllRecent,
  credentialsGetAllKeys,
} from "./db.js";

import { CWT } from "./cwt.js"

// Scan interval in ms
const scanRefreshInterval = 50;

function detectQRtype(prefix) {
  // Try to detect the type of data received

  mylog(prefix);

  if (prefix.startsWith("https")) {
    // We require secure connections
    // Normal QR: we receive a URL where the real data is located
    return "URL";
  } else if (prefix.startsWith("multi|w3cvc|")) {
    // A multi-piece JWT
    return "MultiJWT";
  } else if (prefix.startsWith("GFX")) {
    // A multi-piece JWT
    alert("Test Tube detected");
    return "TestTube";
  } else if (prefix.startsWith("HC1:")) {
    console.log("HEALTH-HEALTH");
    return "HC1";
  }

  // The magic 3 bytes for COSE objects
  let prefix0 = 0xd9;
  let prefix1 = 0xd9;
  let prefix2 = 0xf7;
  // TODO: implement recognition of COSE prefix

  myerror("Unknown QR scanned");
  return "unknown";
}

// Start the camera to scan the QR
// The scan can be used either by the Passenger or the Verifier
export async function initiateReceiveQRScanning(
  _canvasElement,
  _qrMessageElement,
  _displayQRPage,
  _callerType
) {
  // _canvasElement: DOM element where the images will be displayed
  // _qrMessageElement: DOM element to display info messages
  // _displayQRPage: page to switch to display contents of the QR
  // _callerType: who is calling, to customise the display of the QR

  // This is the state object used by the background animation routine.
  // Its values are set by the QR scanning initialization routine
  var qrScan = {
    // The page that has invoked the scan
    callerPage: "",

    // The HTML element where the video frames will be placed for analysis
    canvasElement: "",

    // The canvas context with image data
    canvas: "",

    // The element in the page to display messages about status of scanning
    progressMessages: "",

    // The page where thee coded QR will be displayed
    displayQRPage: "",

    // Page that initiated the scanning
    callerType: "",

    // To build the whole JWT from the received pieces
    receivedQRPieces: [],
    receivedPieces: "",

    // The HTML element where the video stream is going to be placed
    video: "",

    // The video stream object
    myStream: "",
  };

  // Get the current page where scanning is started
  var currentPage = "";
  if (window.history.state != null) {
    currentPage = window.history.state.pageName;
  }
  qrScan["callerPage"] = currentPage;

  // The HTML element where the video frames will be placed for analysis
  qrScan["canvasElement"] = _canvasElement;

  // Save in global variable the element to display messages about progress of scanning
  qrScan["progressMessages"] = _qrMessageElement;

  // Save the input parameters in global variables to keep state across timer ticks
  qrScan["displayQRPage"] = _displayQRPage;

  // Save the input parameters in global variables to keep state across timer ticks
  qrScan["callerType"] = _callerType;

  // Reset the variables holding the received pieces
  qrScan["receivedQRPieces"] = [];
  qrScan["receivedPieces"] = new Set();

  // Get the canvas context with image data and store in global variable
  qrScan["canvas"] = qrScan["canvasElement"].getContext("2d");

  // Create the HTML element to place the video stream and save in global variable
  qrScan["video"] = document.createElement("video");

  // Make sure that the canvas element is hidden for the moment
  qrScan["canvasElement"].hidden = true;

  // Display a message while we have not detected anything
  qrScan["progressMessages"].innerText = "Waiting for QR .........";

  // Request permission from user to get the video stream
  // Use "facingMode: environment" to attempt to get the main camera on phones
  navigator.mediaDevices
    .getUserMedia({ video: { facingMode: "environment" } })
    .then(function (stream) {
      // Store the stream in global variable for later
      qrScan["myStream"] = stream;

      // Connect the video stream to the "video" element in the page
      qrScan["video"].srcObject = stream;
      qrScan["video"].setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
      qrScan["video"].play();

      // Call the "tick" function on the next animation interval
      setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);
    });
}

// This function is called periodically until we get a result from the scan
// We use global variables to know the context on which it was called
async function ReceiveQRtick(qrScan) {
  try {
    // Load variables for easier referencing
    var video = qrScan["video"];
    var canvas = qrScan["canvas"];
    var canvasElement = qrScan["canvasElement"];
    var receivedPieces = qrScan["receivedPieces"];
    var receivedQRPieces = qrScan["receivedQRPieces"];
    var progressMessages = qrScan["progressMessages"];
    var myStream = qrScan["myStream"];
    if (!myStream) {
      console.error("Not MyStream");
    }
    var callerType = qrScan["callerType"];
    var callerPage = qrScan["callerPage"];
    var displayQRPage = qrScan["displayQRPage"];

    var currentPage = "";
    if (window.history.state != null) {
      currentPage = window.history.state.pageName;
    }
    // Ckeck if we are running in the context of the page that initiated scanning
    if (currentPage != callerPage) {
      // The user navigated out of the scan page, should stop using the camera
      stopMediaTracks(myStream);

      // Return without activating the callback again, so it will stop completely
      return;
    }

    // We have to wait until the video stream is ready
    if (video.readyState !== video.HAVE_ENOUGH_DATA) {
      // We are not yet ready

      // Request to be called again in next frame
      setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

      // Exit from the function until it will be called again
      return;
    }

    // Video is ready, display canvas
    canvasElement.hidden = false;

    // Set the canvas size to match the video stream
    canvasElement.height = video.videoHeight;
    canvasElement.width = video.videoWidth;

    // Get a video frame and decode an image data using the canvas element
    canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
    var imageData = canvas.getImageData(
      0,
      0,
      canvasElement.width,
      canvasElement.height
    );

    // Try to decode the image as a QR code
    var code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "dontInvert",
    });

    // If unsuccessful, exit requesting to be called again at next animation frame
    if (!code) {
      // Request to be called again in next frame
      setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

      // Exit from the function
      return;
    }

    // If we reached up to here, we have a valid QR

    // Try to detect the type of data received
    var qrType = detectQRtype(code.data);
    if (qrType == "unknown") {
      // We do not know what type it is. Continue scanning

      // Request to be called again in next frame
      setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

      // Exit from the function
      return;
    }

    if (qrType == "MultiJWT") {
      mylog("Scanned MultiJWT QR");
      // We are going to receive a series of QRs and then join the pieces together
      // Each piece has the format: "xx|yy|data" where
      //   xx is the total number of pieces to receive, expressed as two decimal digits
      //   yy is the index of this piece in the whole data, expressed as two decimal digits
      //   data is the actual data of the piece

      // Split the data in the QR in the components
      var components = code.data.split("|");

      // The first and second components are "multi" and "w3cvc" and we do not need them

      // The third component is the total number of pieces to receive
      var total = components[2];

      // The fourth is the index of the received component
      var index = components[3];

      // And the fifth is the actual piece of data
      var piece = components[4];

      // Check if we received two integers each with two digits, from "00" to "99"
      // ASCII code for "0" is 48 and for "9" is 57
      var total1 = total.charCodeAt(0);
      var total2 = total.charCodeAt(1);
      var index1 = index.charCodeAt(0);
      var index2 = index.charCodeAt(1);
      if (
        total1 < 48 ||
        total1 > 57 ||
        total2 < 48 ||
        total2 > 57 ||
        index1 < 48 ||
        index1 > 57 ||
        index2 < 48 ||
        index2 > 57
      ) {
        // Invalid data received, keep trying
        // Request to be called again in next frame
        setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

        // Exit from the function
        return;
      }

      // Check if we already received this piece
      if (receivedPieces.has(index)) {
        // Already received, continue scanning

        // Request to be called again in next frame
        setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

        // Exit from the function
        return;
      }

      // This is a new piece. Add it to the set
      receivedPieces.add(index);
      receivedQRPieces[+index] = piece; // Make sure that index is considered an integer and not a string

      // Display in the page the number of the object received.
      progressMessages.innerText = "Received piece: " + index;

      // Check if we need more pieces
      if (receivedPieces.size < total) {
        // Continue scanning

        // Request to be called again in next frame
        setTimeout(ReceiveQRtick, scanRefreshInterval, qrScan);

        // Exit from the function
        return;
      }

      // We have received all pieces

      // Stop the media stream
      stopMediaTracks(myStream);

      // Hide the picture
      canvasElement.hidden = true;

      mylog("Received all pieces", receivedQRPieces);

      // Assemble all pieces together
      var jwt = receivedQRPieces.join("");
      mylog("Received jwt", jwt);

      // Extract the credential and save in the temporary storage
      try {
        var cred = decodeJWT(jwt);

        // Store in temporal storage so the page will retrieve it
        let currentCredential = {
          type: "w3cvc",
          encoded: jwt,
          decoded: cred,
        };
        mylog("Writing current cred: ", currentCredential);
        await settingsPut("currentCredential", currentCredential);
      } catch (error) {
        myerror(error);
        progressMessages.innerText = error;
        return;
      }

      // Switch to the presentation of results
      gotoPage(displayQRPage, { screenType: callerType });

      return;
    }

    if (qrType == "URL") {
      // We received a URL in the QR. Perform a GET to obtain the JWT from a server
      mylog("Scanned normal URL QR");

      // Stop the media stream
      stopMediaTracks(myStream);

      // Build the URL to call
      let targetURLRead = code.data.trim();

      // Check if the URL points to a JWT or to the wallet
      if (targetURLRead.startsWith(MYSELF)) {
        // The URL points to the wallet. There is a param with the credential id
        const url = new URL(targetURLRead);

        // First we check for a normal credential
        let credId = url.searchParams.get("id");
        if (credId) {
          targetURLRead = ISSUER_GET_CREDENTIAL + credId;
        } else {
          // Now check for a Public Credential
          credId = url.searchParams.get("pubid");
          if (credId) {
            targetURLRead = ISSUER_GET_PUBLIC_CREDENTIAL + credId;
          }
        }
      }

      // Retrieve the credential from the server and display it
      await requestQRAndDisplay(targetURLRead, displayQRPage, callerType);

      return;
    }

    const HC_ISS = 1;
    const HC_IAT = 6;
    const HC_EXP = 4;
    const HC_CTI = 7;
    const HC_HCERT = -260;

    if (qrType == "HC1") {
      // We received a Health Certificate (HC) version 1 encoded QR.
      mylog("Scanned HC1 QR");

      let plain = await CWT.decodeHC1QR(code.data);
      console.log("CWT.decodeHC1QR", plain)

      // Store in temporal storage so the page will retrieve it
      let currentCredential = {
        type: "hcert",
        encoded: code.data,
        decoded: plain,
      };
      await settingsPut("currentCredential", currentCredential);

      // Stop the media stream
      stopMediaTracks(myStream);

      // Switch to the presentation of results
      gotoPage(displayQRPage, { screenType: callerType });

      return;
    }

    if (qrType == "Base64") {
      // We received a Base64 encoded QR. May be it is the UK Immigration document
      mylog("Scanned Base64 simple QR");

      let decodedQR = JSON.parse(atobUrl(code.data));

      // Store in temporal storage so the page will retrieve it
      let currentCredential = {
        type: "ukimmigration",
        encoded: code.data,
        decoded: decodedQR,
      };
      await settingsPut.setItem("currentCredential", currentCredential);

      // Stop the media stream
      stopMediaTracks(myStream);

      // Switch to the presentation of results
      gotoPage(displayQRPage, { screenType: callerType });

      return;
    }
  } catch (error) {

    // Stop the media stream
    stopMediaTracks(myStream);

    console.error(error)
    alert(`Error: ${error}`)

    // Go to the home page to start again
    gotoPage(homePage);

    // Exit from the function
    return;
  }
}

function stopMediaTracks(stream) {
  // Stop the media stream

  var tracks = stream.getTracks();
  tracks[0].stop();

  return;
}
