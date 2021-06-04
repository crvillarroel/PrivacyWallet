//"use strict";

// Logging level (if false, only log Errors)
const LOG_ALL = true

// Universal Resolver, Verifier and Fake Issuer URLs
//const MY_SERVER = window.location.origin
const MY_SERVER = "https://safeislandtest.hesusruiz.org"
const MYSELF = "https://www.lanzarotesafe.org"

const UNIVERSAL_RESOLVER = MY_SERVER + "/api/did/v1/identifiers/"
const VERIFY_CREDENTIAL = MY_SERVER + "/api/verifiable-credential/v1/verifiable-credential-validations"
const FAKE_ISSUER_GET_CREDENTIALS = MY_SERVER + "/api/verifiable-credential/v1/credentials"
const FAKE_ISSUER_GET_PUBLIC_CREDENTIALS = MY_SERVER + "/api/verifiable-credential/v1/public/credentials"
const ISSUER_GET_CREDENTIAL = "https://api.lanzarotesafe.org/sms/"
const ISSUER_GET_PUBLIC_CREDENTIAL = MY_SERVER + "/api/verifiable-credential/v1/public/"

// Compile the templates for displaying the credentials
compileCredentialTemplates();

// Get a reference to the Navigator, to facilitate access later
var nav = document.querySelector('#navigator')

// **************************************************
// Local database management
// **************************************************

// We use a library on top of IndexedDB
// There are two application stores and one logging store:
//    "credentials" for storing the credentials
//    "settings" for miscellaneous things
//    "logs" for persistent logging of important events for diagnostic

var db = new Dexie('SafeIslandNew');
db.version(0.4).stores({
    credentials: 'hash, timestamp, type',
    settings: 'key',
    logs: '++id, timestamp'
});

// Basic persistent rotating log on top of IndexedDB
const MAX_LOG_ENTRIES = 1000

async function mylog_entry(_level, _desc, _item) {

    // _item should be compatible with Dexie (most objects are)
    
    // Create the object to store
    var logItem = {
        timestamp: Date.now(),
        level: _level,
        desc: _desc,
        item: _item
    }

    // Store the object
    try {
        await db.logs.add(logItem)
    } catch (error) {
        // If error, we can not do anything
        console.error("Error in log add")
    }

    // Check if we should prune old records
    var numEntries = await db.logs.count()
    if (numEntries <= MAX_LOG_ENTRIES) {
        return
    }

    // Perform pruning of the oldest entry
    var oldestEntry = await db.logs.orderBy("id").first()
    try {
        await db.logs.delete(oldestEntry.id)
    } catch (error) {
        console.error("Error in log prune")
    }

}

async function mylog(_desc) {
    if (LOG_ALL) {
        var args = Array.prototype.slice.call(arguments, 1);
        console.log(_desc, args)
        mylog_entry("N", _desc, args)
    }
}

async function myerror(_desc) {
    var args = Array.prototype.slice.call(arguments, 1);
    console.error(_desc, args)
    mylog_entry("E", _desc, args)
}


// The following are simple wrappers to insulate from future changes in the db
async function settingsPut(key, value) {
    try {
        await db.settings.put({ key: key, value: value })
    } catch (error) {
        console.error(error);
        alert("Error in put setting")
    }
}

async function settingsGet(key) {
    try {
        var setting = await db.settings.get(key)
    } catch (error) {
        console.error(error);
        alert("Error in get setting")
    }
    if (setting == undefined) {
        return undefined;
    }
    return setting.value;
}

async function settingsDelete(key) {
    try {
        await db.settings.delete(key)
    } catch (error) {
        console.error(error);
        alert("Error deleting setting")
    }
}

async function settingsDeleteAll() {
    try {
        await db.settings.clear()
    } catch (error) {
        console.error(error);
        alert("Error deleting all settings")
    }

}


async function credentialsSave(_credential) {

    // The _credential object has the following structure:
    // _credential = {
    //     type: the type of credential: "w3cvc", "eHealth", "ukimmigration", etc
    //     encoded: the credential encoded in JWT, COSE or any other suitable format
    //     decoded: the credential in plain format as a Javascript object
    // }

    mylog("CredentialSave", _credential)

    // Calculate the hash of the encoded credential to avoid duplicates
    var data = new TextEncoder().encode(_credential.encoded);
    var hash = await crypto.subtle.digest('SHA-256', data)
    var hashArray = Array.from(new Uint8Array(hash));   // convert buffer to byte array
    var hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Create the object to store
    var credential = {
        hash: hashHex,
        timestamp: Date.now(),
        type: _credential.type,
        encoded: _credential.encoded,
        decoded: _credential.decoded
    }

    // Check if the credential is already in the database
    oldCred = await credentialsGet(hashHex)
    if (oldCred != undefined) {
        myerror("Credential already exists", oldCred, hashHex)
        showError("Can not save credential: already exists")

        // Return an error
        return undefined;
    }

    // Store the object, catching the exception if duplicated
    try {
        await db.credentials.add(credential)
    } catch (error) {
        myerror("Error saving credential", error)
        return undefined;
    }

    return credential;

}


async function credentialsDeleteCred(_credential) {

    // The _credential object has the following structure:
    // _credential = {
    //     type: the type of credential: "w3cvc", "eHealth", "ukimmigration", etc
    //     encoded: the credential encoded in JWT, COSE or any other suitable format
    //     decoded: the credential in plain format as a Javascript object
    // }

    mylog("credentialsDeleteCred", _credential)

    // Calculate the hash of the encoded credential, which will be the key
    var data = new TextEncoder().encode(_credential.encoded);
    var hash = await crypto.subtle.digest('SHA-256', data)
    var hashArray = Array.from(new Uint8Array(hash));   // convert buffer to byte array
    var hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Delete the credential
    try {
        await db.credentials.delete(hashHex)
    } catch (error) {
        myerror(error);
        alert("Error deleting credential")
    }
}


async function credentialsDelete(key) {
    try {
        await db.credentials.delete(key)
    } catch (error) {
        console.error(error);
        alert("Error deleting credential")
    }
}

async function credentialsDeleteAll() {
    try {
        await db.credentials.clear()
    } catch (error) {
        console.error(error);
        alert("Error deleting all credentials")
    }
}

async function credentialsGet(key) {
    try {
        var credential = await db.credentials.get(key)
    } catch (error) {
        console.error(error);
        alert("Error getting credential")
    }

    console.log("CredentialGet: ", credential)
    return credential;

}

// Retrieve all credentials since some period
async function credentialsGetAllRecent(days) {
    if (days == undefined) {
        days = 7
    }
    const oneWeekAgo = new Date(Date.now() - 60 * 60 * 1000 * 24 * days);

    try {
        var credentials = await db.credentials
            .where('timestamp').aboveOrEqual(oneWeekAgo).toArray();
    } catch (error) {
        console.error(error);
        alert("Error getting recent credentials")
    }

    return credentials;
}

// Get all the keys to iterate all credentials in the store
async function credentialsGetAllKeys() {
    try {
        var keys = await db.credentials.orderBy("timestamp").primaryKeys();
    } catch (error) {
        console.error(error);
        alert("Error getting all credentials")
    }

    return keys;

}


// **************************************************
// End of Local database management
// **************************************************

// ***************************************************
// ***************************************************
// Support for app installation for off-line support
//

var deferredInstallPrompt = null;
const installButton = document.getElementById('butInstall');

installButton.addEventListener('click', installPWA);
window.addEventListener('beforeinstallprompt', saveBeforeInstallPromptEvent);

function saveBeforeInstallPromptEvent(evt) {
    mylog("saveBeforeInstallPromptEvent");

    // Save the prompt event for later when the user wants to click the Install button
    deferredInstallPrompt = evt;

    // Show the button only when the browser has generated this event
    // If the app is already installed, the browser does not generate the event
    $("#butInstall").show();

}

function installPWA(evt) {
    mylog("installPWA event")
    deferredInstallPrompt.prompt();

    // Hide install button, can only be invoked once per event
    $("#butInstall").hide();

    // Log the choice that the user made
    deferredInstallPrompt.userChoice
        .then((choice) => {
            if (choice.outcome === 'accepted') {
                mylog('User accepted the A2HS prompt', choice);
            } else {
                mylog('User dismissed the A2HS prompt', choice);
            }
            deferredInstallPrompt = null;
        });

}

// To log all events of app installation, even if the user does not click our Install button
window.addEventListener('appinstalled', logAppInstalled);
function logAppInstalled(evt) {
    mylog('SafeIsland app was installed.', evt);
}

//
// End of Support for app installation for off-line support
// ********************************************************
// ********************************************************


// This function is called on first load and when a refresh is triggered in any page
// When called the DOM is fully loaded and safe to manipulate
$(async function () {

    // Install service worker for better off-line support
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js')
          .then(() => { mylog('Service Worker Registered'); });
    }

    // Handle one-time initialization when the user executes for the first time the app
    await performOneTimeInitialization();

    // Check if a credential id was specified in the URL
    let credId = searchParams.get("id")

    if (credId) {

        // Build the URL of the server to retrieve the credential
        var targetURLRead = ISSUER_GET_CREDENTIAL + credId

        // Request the credential
        await requestQRAndDisplay(targetURLRead, "#displayCredentialPage", ST_PASSENGER_SCAN)

        return
    }

    // Check if a public credential id was specified in the URL
    credId = searchParams.get("pubid")

    if (credId) {

        // Build the URL of the server to retrieve the credential
        var targetURLRead = ISSUER_GET_PUBLIC_CREDENTIAL + credId
        console.log("Public Credential", targetURLRead)

        // Request the credential
        await requestQRAndDisplay(targetURLRead, "#displayCredentialPage", ST_PASSENGER_SCAN)

        return
    }


    // Show current page and execute logic on page transition
    mylog(homePage)
    processPageEntered(homePage, undefined);

});


// Listen for PopStateEvent (Back or Forward buttons are clicked)
window.addEventListener("popstate", async function (event) {

    // Set defaults
    var pageName = homePage
    var pageData = undefined

    // Get current state data if not null
    var state = event.state
    if (state != null) {
        pageName = state.pageName
        pageData = state.pageData
    }
    mylog("Popstate: ", pageName)

    // Process the page transition
    await processPageEntered(pageName, pageData)

});



// Handle page transition
async function processPageEntered(pageName, pageData) {

    // Hide all pages of the application. Later we unhide the one we are entering
    $(".jrmpage").hide();
    // Hide the loader
    $("#loader").hide();
    // Set the default status of the Navbar
    headerBrandBack(false)

    // If the hash is not a registered page, go to the home page
    if (pages[pageName] == null) {
        pageName = homePage
    }

    // Make sure the page is at the top
    window.scrollTo(0, 0);

    // Show the page before invoking the page enter event
    $(pageName).show();

    // Invoke the registered function when page has entered
    // This will allow the page to create dynamic content
    await pages[pageName](pageData);

}


async function gotoPage(pageName, pageData) {

    // If the hash is not a registered page, go to the home page
    if (pages[pageName] == null) {
        myerror("Target page does not exist: ", pageName)
        return;
    }

    mylog("Navigating to ", pageName, pageData)

    // Create a new history state
    window.history.pushState({ pageName: pageName, pageData: pageData }, `${pageName}`);

    // Process the page transition
    await processPageEntered(pageName, pageData)

}


// Initialize the app when the user downloads the application for the first time,
// or when a factory reset is performed by the user
// The function is safe to be called many times
async function performOneTimeInitialization() {
    mylog("Performing OneTime Initialization")

    // Check if this is the first time that the user downloads the app
    // There is a persistent flag in the local storage
    var alreadyInitialized = await settingsGet("initialized");

    if (alreadyInitialized != true) {

        try {
            // Save the host from where the app was loaded
            await settingsPut("apiHost", MY_SERVER);
        } catch (error) {
            // Log the error
            myerror("Onetime initialization error")
        }

        // Signal that we already performed initialization
        await settingsPut("initialized", true);

    }

}

// Generate the Peer DID for the user
async function getOrGeneratePeerDID() {

    // Check if we already have the peerDID in the database
    var didData = await settingsGet("didData");
    if (didData == null) {
        didData = await generateDidPeer();
        mylog(didData.did, didData.keyPair);
        await settingsPut("didData", didData);
    }

    return didData;

}



// Call the server to verify a W3C VC in JWT serialized format
async function verifyJwtVc(jwt) {

    // Build the body of the request
    let body = JSON.stringify({ payload: jwt })

    // Perform validation as a POST request
    // Do not handle errors here and leave it to the caller to catch the exception
    let claims = await $.post(VERIFY_CREDENTIAL, body);
    return claims;

}

// Perform DID Resolution, which is also a DID verification
function verifyDID(inputDID) {

    mylog(inputDID);

    // Build the URL of the server to resolve the DID
    var targetURL = UNIVERSAL_RESOLVER + inputDID

    // Use the URL to get the DID Document from server
    $.get(targetURL, function (data) {

        // The actual data is inside a "payload" entry in the response
        mylog(data.payload);
        didDoc = data.payload;

        // Get the Issuer DID from inside the received data
        receivedDID = didDoc.id;

        // Log the Issuer DID inside the received data
        mylog(receivedDID);

        // The DID that we resolved should be the same as the one inside the DID Document
        if (inputDID == receivedDID) {
            mylog("VERIFICATION SUCCESSFUL");
        } else {
            myerror("ERROR: DIDs DO NOT MATCH");
        }

    }, "json");

}



// This is triggered by the onclick event of each credential summary in the Issuer page
// We save the credential ID to display and switch to the genericDisplayQR page
// This page change will trigger the genericDisplayQR() function
// A page refresh by the user while in the genericDisplayQR page will trigger the same routine,
// using the saved variable (issuerCredentialID)
async function transferViaQR(jwt) {
    mylog("In transferViaQR")

    // Extract the credential and set the current data for the display page
    try {
        cred = decodeJWT(jwt);
        currentCredential = {
            type: "w3cvc",
            encoded: jwt,
            decoded: cred
        }
        await settingsPut("currentCredential", currentCredential);
    } catch (error) {
        myerror("Error decoding credential", error);
        return;
    }

    // Transfer control to the page for display
    gotoPage("#displayCredentialPage", { screenType: "fromIssuer" })

}



var qrDisplayType = ""
var QRpieces = []
var qrelement = ""
var realqrelement = ""
var elwidth = 0
var frameSeparation = 400
var thePage = ""

// Triggers from the #passengerDisplayQR page change
// This page generates the QR so it can be scanned by the Verifier
// In order to send big amounts of data, it displays several QRs in sequence
async function passengerDisplayQR(page, credential) {

    thePage = page
    qrDisplayType = credential["type"]
    if (credential["decoded"]['body']['vc']['credentialSchema']['id'] == "publicCredential") {
        qrDisplayType = "publicCredential"
    }
    var credentialJWT = credential["encoded"]

    // The DOM element where the library will create the QR. Hidden to avoid flickering
    qrelement = page.querySelector("#offPlaceholderQR");
    mylog("Unreal: ", qrelement)
    qrelement.style.display = "none";

    // The DOM element where we will display the QR.
    // We use this to avoid flickering when QRs are of different sizes
    realqrelement = page.querySelector("#realplaceholderQR");
    mylog("Real: ", realqrelement)

    // We will tell the QR library to generate a QR with the width of the DOM element
    //    elwidth = Math.floor($(realqrelement).width())
    //    elwidth = Math.floor(realqrelement.style.width)
    elwidth = Math.min(screen.availWidth - 60, 350)
    mylog("Element width:", elwidth)

    if (qrDisplayType == "ukimmigration") {

        QRpieces = [credentialJWT]

    } else if (qrDisplayType == "publicCredential") {
        
        console.log("Display of public credential")
        QRpieces = ["https://www.lanzarotesafe.org/?pubid=" + credential["decoded"]['body']['uuid']]

    } else {

        // Calculate a number of pieces to divide the whole JWT
        // The target size is 300 chars, but we will divide the JWT in similar size pieces,
        // so all the QRs look similar, including the last one
        var totalLength = credentialJWT.length
        var targetPieceSize = 300

        var numPieces = Math.floor(totalLength / targetPieceSize)
        var remainder = totalLength % targetPieceSize
        var extraChars = Math.ceil(remainder / numPieces)

        // Calculate the real size of each piece
        var pieceSize = targetPieceSize + extraChars
        mylog("Piece length: ", pieceSize)

        // Divide the credential string into pieces
        QRpieces = credentialJWT.match(new RegExp('.{1,' + pieceSize + '}', 'g'));
        mylog(QRpieces)

    }

    // Display the first piece (index 0)
    await QRDisplayTick(0)

    return

}


async function QRDisplayTick(index) {

    var currentPage = ""
    if (window.history.state != null) {
        currentPage = window.history.state.pageName
    }
    // Ckeck if we are running in the context of the page that initiated display
    if (currentPage != "#passengerDisplayQR") {
        // The user navigated out of the passengerDisplayQR page, should stop displaying QR
        // Return without activating the callback again, so it will stop
        mylog("Exiting QR timer")
        return
    }

    // Erase the display of the QR
    qrelement.innerText = "";

    numPieces = QRpieces.length
    // Get the current piece to display
    var body = "multi|w3cvc|"
    if (numPieces > 9) {
        body = body + `${numPieces}|`
    } else {
        body = body + `0${numPieces}|`
    }

    if (index > 9) {
        body = body + `${index}|`
    } else {
        body = body + `0${index}|`
    }

    if (qrDisplayType == "ukimmigration") {

        body = QRpieces[0]

    } else if (qrDisplayType == "publicCredential") {

        body = QRpieces[0]
        
    } else {

        body = body + `${QRpieces[index]}`

    }

    // Build the QR and display in the DOM element
    var qrcode = new QRCode(
        qrelement,                              // Place to display QR image
        {
            drawer: "canvas",
            height: elwidth,
            width: elwidth,
            text: body,  // Contents of the QR
            onRenderingStart: function (options) {
            },
            onRenderingEnd: function (options, dataURL) {
                //                var imageQR = document.getElementById('realplaceholderQR')
                var imageQR = thePage.querySelector("#realplaceholderQR");
                imageQR.setAttribute(
                    'src', dataURL
                );
                imageQR.style.width = elwidth

            }
        }
    );

    // Set the next timer for displaying the next piece of the QR
    var nextIndex = index + 1
    if (nextIndex >= QRpieces.length) {
        nextIndex = 0
    }
    setTimeout(QRDisplayTick, frameSeparation, nextIndex)

}



function btoaUrl(input) {

    // Encode using the standard Javascript function
    astr = btoa(input)

    // Replace non-url compatible chars with base64 standard chars
    astr = astr.replace(/\+/g, '-').replace(/\//g, '_');

    return astr;
}

function atobUrl(input) {

    // Replace non-url compatible chars with base64 standard chars
    input = input.replace(/-/g, '+').replace(/_/g, '/');

    // Decode using the standard Javascript function
    bstr = decodeURIComponent(escape(atob(input)));

    return bstr;
}


function decodeJWT(jwt) {
    // We will decode the JWT without checking the signature
    // But we will perform some important validations like expiration

    // This is the object that will be returned
    let decoded = {
        error: false,
        header: undefined,
        body: undefined
    }

    let components = ""

    // Check that jwt is a string
    if(typeof jwt === "string" || jwt instanceof String){
        // Split the input in three components using the dots "." as separator
        components = jwt.split(".");
    } else {
        decoded.error = "Format error. Encoded credential is not a string"
        myerror(decoded.erro)
        return decoded;
    }    

    if (components.length != 3) {
        decoded.error = "Malformed certificate"
        myerror(decoded.error);
        return decoded;
    }

    // Decode the header and the body into JSON objects
    try {
        decoded.header = JSON.parse(atobUrl(components[0]))
        decoded.body = JSON.parse(atobUrl(components[1]))       
    } catch (error) {
        decoded.error = "Error parsing header or body"
        myerror(decoded.error)
        return decoded;        
    }

    // Perform some consistency checks
    if (!decoded.header) {
        decoded.error = "Field does not exist in JWT (header)"
        myerror(decoded.error)
        return decoded;
    }
    try {
        let schema = decoded['body']['vc']['credentialSchema']['id']        
    } catch (error) {
        decoded.error = "Field does not exist in JWT (body, vc, credentialSchema, id)"
        myerror(decoded.error)
        return decoded;
    }

    // Check expiration (in seconds since January 1, 1970 00:00:00 UTC.)
    let expiration = decoded.body.exp
    let now = Date.now() / 1000     // In seconds
    let leeway = 60 * 60            // We allow a leeway of 1 hour in the comparison
    // If it has expired more than one hour before now, give an error
    if (expiration + leeway < now) {
        decoded.error = "Expired certificate"
        myerror(decoded.error)
    }

    return decoded;

}


// Utility function to generate a cryptographically unique number
async function generateUID() {
    // Get the Crypto object (with support for IE11)
    //    var cryptoObj = window.crypto || window.msCrypto;
    const array = new Uint32Array(2);
    crypto.getRandomValues(array);
    var UID = array[0].toString() + array[1].toString();
    mylog(`New UID: ${UID}`)
    return UID;
}

// Generate key fingerprint to use in DIDs and Key identifiers
// The format used here is for Peer DIDs (see spec for details)
async function keyPairFingerprint(keyPair) {

    // Get the Public key
    let PK = keyPair.publicKey;

    // Export the Public Key in a byte array
    let PKexported = await crypto.subtle.exportKey("raw", PK);
    let byteView = new Uint8Array(PKexported);

    // Create a bigger array to concatenate with the multicodec value
    let wholeArray = new Uint8Array(byteView.length + 2);

    // The multicodec for P-256 is 0x1200
    const multicodecP256 = 0x1200;
    wholeArray[0] = 0x12;
    wholeArray[1] = 0x00;

    // Concatenate the public key raw values
    wholeArray.set(byteView, 2);

    // Encode in Base58 the result of concatenation
    let b58encoded = to_b58(wholeArray);

    let fingerprint = `0z${b58encoded}`;

    return fingerprint;

}

// Generate a DID in format of Peer DID (see spec for details)
// The key used is Elliptic but restricted to the one supported by browsers
// in the standard crypto Subtle subsystem
async function generateDidPeer() {

    // Ask browser to create a key pair with the p256 curve
    var keyPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );

    // Export both keys to the JWK format (see spec for details)
    var privateKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    var publicKeyJWK = await crypto.subtle.exportKey("jwk", keyPair.publicKey);

    // Get the key fingerprint in Peer DID format
    let fingerprint = await keyPairFingerprint(keyPair);

    // Buid the DID string
    var did = `did:peer:${fingerprint}`;

    // Return an object with the DID and both keys
    return { did: did, privateKey: privateKeyJWK, publicKey: publicKeyJWK };

}

// Generate a symmetric key for encrypting credentials when in transit
// The credentials (and other material) will be encrypted when sent to the
// Secure Messaging Server
async function generateEncryptionKey() {

    // Ask browser to create a symmetric key
    var key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );

    // The JWK format is verbose, but the advantage is that it isself-describing
    return keyJWK;

}

// Convert a key in CryptoKey (native) format to JWK format
async function exportToJWK(key) {
    // Export the key to the JWK format (see spec for details)
    var keyJWK = await crypto.subtle.exportKey("jwk", key);
    return keyJWK;
}

// Convert a private key in JWK format to CryptoKey (native) format
async function importFromJWK(jwk) {

    // Assume for the moment that it is a private key
    var keyUsages = ["sign"];

    // Check if it is a public key
    // In that case, the field "d" should not exist
    if (jwk["d"] == undefined) {
        keyUsages = ["verify"];
    }

    // Perform the import
    return await crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "ECDSA",
            namedCurve: "P-384"
        },
        true,
        keyUsages
    );
}

// Encrypt a string message with a symmetric key
async function encryptMessage(keyJWT, stringdata) {

    // Encode the received string into UTF8 bytes
    var enc = new TextEncoder();
    var encodedBytes = enc.encode(stringdata);

    // Generate the iv
    // The iv must never be reused with a given key.
    iv = crypto.getRandomValues(new Uint8Array(12));

    // Perform the actual encryption
    ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encodedBytes
    );

    // Return the resulting ArrayBuffer, together with the iv
    return { iv: iv, ciphertext: ciphertext };

}

async function decryptMessage(key, iv, ciphertext) {

    // Perform the decryption of the received ArrayBuffer
    var decrypted = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ciphertext
    );

    // We got UTF8 bytes, should decode into a string
    var dec = new TextDecoder();
    return dec.decode(decrypted);
}


async function didDocFromDid(did) {

}

var MSB = 0x80
    , REST = 0x7F
    , MSBALL = ~REST
    , INT = Math.pow(2, 31)

function encode(num, out, offset) {
    if (Number.MAX_SAFE_INTEGER && num > Number.MAX_SAFE_INTEGER) {
        encode.bytes = 0
        throw new RangeError('Could not encode varint')
    }
    out = out || []
    offset = offset || 0
    var oldOffset = offset

    while (num >= INT) {
        out[offset++] = (num & 0xFF) | MSB
        num /= 128
    }
    while (num & MSBALL) {
        out[offset++] = (num & 0xFF) | MSB
        num >>>= 7
    }
    out[offset] = num | 0

    encode.bytes = offset - oldOffset + 1

    return out
}

var B58MAP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

var to_b58 = function (
    B            //Uint8Array raw byte input
) {
    var d = [],   //the array for storing the stream of base58 digits
        s = "",   //the result string variable that will be returned
        i,        //the iterator variable for the byte input
        j,        //the iterator variable for the base58 digit array (d)
        c,        //the carry amount variable that is used to overflow from the current base58 digit to the next base58 digit
        n;        //a temporary placeholder variable for the current base58 digit
    for (i in B) { //loop through each byte in the input stream
        j = 0,                           //reset the base58 digit iterator
            c = B[i];                        //set the initial carry amount equal to the current byte amount
        s += c || s.length ^ i ? "" : 1; //prepend the result string with a "1" (0 in base58) if the byte stream is zero and non-zero bytes haven't been seen yet (to ensure correct decode length)
        while (j in d || c) {             //start looping through the digits until there are no more digits and no carry amount
            n = d[j];                    //set the placeholder for the current base58 digit
            n = n ? n * 256 + c : c;     //shift the current base58 one byte and add the carry amount (or just add the carry amount if this is a new digit)
            c = n / 58 | 0;              //find the new carry amount (floored integer of current digit divided by 58)
            d[j] = n % 58;               //reset the current base58 digit to the remainder (the carry amount will pass on the overflow)
            j++                          //iterate to the next base58 digit
        }
    }
    while (j--)        //since the base58 digits are backwards, loop through them in reverse order
        s += B58MAP[d[j]]; //lookup the character associated with each base58 digit
    return s          //return the final base58 string
}


var from_b58 = function (
    S            //Base58 encoded string input
) {
    var d = [],   //the array for storing the stream of decoded bytes
        b = [],   //the result byte array that will be returned
        i,        //the iterator variable for the base58 string
        j,        //the iterator variable for the byte array (d)
        c,        //the carry amount variable that is used to overflow from the current byte to the next byte
        n;        //a temporary placeholder variable for the current byte
    for (i in S) { //loop through each base58 character in the input string
        j = 0,                             //reset the byte iterator
            c = B58MAP.indexOf(S[i]);             //set the initial carry amount equal to the current base58 digit
        if (c < 0)                          //see if the base58 digit lookup is invalid (-1)
            return undefined;              //if invalid base58 digit, bail out and return undefined
        c || b.length ^ i ? i : b.push(0); //prepend the result array with a zero if the base58 digit is zero and non-zero characters haven't been seen yet (to ensure correct decode length)
        while (j in d || c) {               //start looping through the bytes until there are no more bytes and no carry amount
            n = d[j];                      //set the placeholder for the current byte
            n = n ? n * 58 + c : c;        //shift the current byte 58 units and add the carry amount (or just add the carry amount if this is a new byte)
            c = n >> 8;                    //find the new carry amount (1-byte shift of current byte value)
            d[j] = n % 256;                //reset the current byte to the remainder (the carry amount will pass on the overflow)
            j++                            //iterate to the next byte
        }
    }
    while (j--)               //since the byte array is backwards, loop through it in reverse order
        b.push(d[j]);      //append each byte to the result
    return new Uint8Array(b) //return the final byte array in Uint8Array format
}


/**
 * Converts an Ed25519KeyPair object to a `did:key` method DID Document.
 *
 * @param {Ed25519KeyPair} edKey
 * @returns {DidDocument}
 */
async function keyToDidDoc(keyPair) {
    const did = `did:peer:${await keyPairFingerprint(keyPair)}`;
    const keyId = `${did}#${await keyPairFingerprint(keyPair)}`;
    const keyController = did;
    const keyType = "Ed25519VerificationKey2018";

    const didDoc = {
        '@context': ['https://w3id.org/did/v0.11'],
        id: did,
        publicKey: [{
            id: keyId,
            type: keyType,
            controller: keyController,
            publicKeyBase58: did
        }],
        authentication: [keyId],
        assertionMethod: [keyId],
        capabilityDelegation: [keyId],
        capabilityInvocation: [keyId],
        keyAgreement: [{
            id: keyId,
            type: keyType,
            controller: did,
            publicKeyBase58: did
        }]
    };

    return didDoc;
}

/**
 * Computes and returns the id of a given key. Used by `did-io` drivers.
 *
 * @param {LDKeyPair} key
 *
 * @returns {string} Returns the key's id.
 */
async function computeKeyId({ key }) {
    return `did:peer:${keyPairFingerprint(key)}#${keyPairFingerprint(key)}`;
}


// *****************************************************
// *****************************************************
// SUPPORT FOR SCANNING QR CODES

// This is the global state object used by the background animation routine.
// Its values are set by the QR scanning initialization routine
// The object can be re-used by different pages, as only one scanning can be running at a given moment
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
    myStream: ""

}

function detectQRtype(prefix) {
    // Try to detect the type of data received

    mylog(prefix)

    if (prefix.startsWith("https")) {
        // We require secure connections
        // Normal QR: we receive a URL where the real data is located
        return "URL"
    } else if (prefix.startsWith("multi|w3cvc|")) {
        // A multi-piece JWT
        return "MultiJWT"
    } else if (prefix.startsWith("HC1:")) {
        console.log("HEALTH-HEALTH")
        return "HC1"
    }

    // The magic 3 bytes for COSE objects
    let prefix0 = 0xd9
    let prefix1 = 0xd9
    let prefix2 = 0xf7
    // TODO: implement recognition of COSE prefix

    myerror("Unknown QR scanned")
    return "unknown"

}

// Start the camera to scan the QR
// The scan can be used either by the Passenger or the Verifier
async function initiateReceiveQRScanning(_canvasElement, _qrMessageElement, _displayQRPage, _callerType) {
    // _canvasElement: DOM element where the images will be displayed
    // _qrMessageElement: DOM element to display info messages
    // _displayQRPage: page to switch to display contents of the QR
    // _callerType: who is calling, to customise the display of the QR

    qrScan = {}

    var currentPage = ""
    if (window.history.state != null) {
        currentPage = window.history.state.pageName
    }
    qrScan["callerPage"] = currentPage;

    // The HTML element where the video frames will be placed for analysis
    qrScan["canvasElement"] = _canvasElement;

    // Save in global variable the element to display messages about progress of scanning
    qrScan["progressMessages"] = _qrMessageElement;

    // Save the input parameters in global variables to keep state across timer ticks
    qrScan["displayQRPage"] = _displayQRPage

    // Save the input parameters in global variables to keep state across timer ticks
    qrScan["callerType"] = _callerType

    // Reset the variables holding the received pieces
    qrScan["receivedQRPieces"] = []
    qrScan["receivedPieces"] = new Set()

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
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(function (stream) {
        // Store the stream in global variable for later
        qrScan["myStream"] = stream;

        // Connect the video stream to the "video" element in the page
        qrScan["video"].srcObject = stream;
        qrScan["video"].setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
        qrScan["video"].play();

        // Call the "tick" function on the next animation interval
        requestAnimationFrame(ReceiveQRtick);
    });

}

// This function is called periodically until we get a result from the scan
// We use global variables to know the context on which it was called
async function ReceiveQRtick() {

    // Load variables for easier referencing
    var video = qrScan["video"]
    var canvas = qrScan["canvas"]
    var canvasElement = qrScan["canvasElement"]
    var receivedPieces = qrScan["receivedPieces"]
    var receivedQRPieces = qrScan["receivedQRPieces"]
    var progressMessages = qrScan["progressMessages"]
    var myStream = qrScan["myStream"]
    var callerType = qrScan["callerType"]
    var callerPage = qrScan["callerPage"]
    var displayQRPage = qrScan["displayQRPage"]

    var currentPage = ""
    if (window.history.state != null) {
        currentPage = window.history.state.pageName
    }
    // Ckeck if we are running in the context of the page that initiated scanning
    if (currentPage != callerPage) {
        // The user navigated out of the scan page, should stop using the camera
        stopMediaTracks(myStream);

        // Return without activating the callback again, so it will stop completely
        return
    }

    // We have to wait until the video stream is ready
    if (video.readyState !== video.HAVE_ENOUGH_DATA) {
        // We are not yet ready

        // Request to be called again in next frame
        requestAnimationFrame(ReceiveQRtick);

        // Exit from the function until it will be called again
        return
    }

    // Video is ready, display canvas
    canvasElement.hidden = false;

    // Set the canvas size to match the video stream
    canvasElement.height = video.videoHeight;
    canvasElement.width = video.videoWidth;

    // Get a video frame and decode an image data using the canvas element
    canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
    var imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);

    // Try to decode the image as a QR code
    var code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
    });

    // If unsuccessful, exit requesting to be called again at next animation frame
    if (!(code)) {

        // Request to be called again in next frame
        requestAnimationFrame(ReceiveQRtick);

        // Exit from the function
        return
    }

    // If we reached up to here, we have a valid QR

    // Try to detect the type of data received
    qrType = detectQRtype(code.data)
    if (qrType == "unknown") {
        // We do not know what type it is. Continue scanning
        
        // Request to be called again in next frame
        requestAnimationFrame(ReceiveQRtick);

        // Exit from the function
        return

    }

    if (qrType == "MultiJWT") {
        mylog("Scanned MultiJWT QR")
        // We are going to receive a series of QRs and then join the pieces together
        // Each piece has the format: "xx|yy|data" where
        //   xx is the total number of pieces to receive, expressed as two decimal digits
        //   yy is the index of this piece in the whole data, expressed as two decimal digits
        //   data is the actual data of the piece

        // Split the data in the QR in the components
        var components = code.data.split("|")

        // The first and second components are "multi" and "w3cvc" and we do not need them

        // The third component is the total number of pieces to receive
        var total = components[2]

        // The fourth is the index of the received component
        var index = components[3]

        // And the fifth is the actual piece of data
        var piece = components[4]

        // Check if we received two integers each with two digits, from "00" to "99"
        // ASCII code for "0" is 48 and for "9" is 57
        var total1 = total.charCodeAt(0)
        var total2 = total.charCodeAt(1)
        var index1 = index.charCodeAt(0)
        var index2 = index.charCodeAt(1)
        if ((total1 < 48 || total1 > 57) || (total2 < 48 || total2 > 57) ||
            (index1 < 48 || index1 > 57) || (index2 < 48 || index2 > 57)) {

            // Invalid data received, keep trying
            // Request to be called again in next frame
            requestAnimationFrame(ReceiveQRtick);

            // Exit from the function
            return

        }

        // Check if we already received this piece
        if (receivedPieces.has(index)) {
            // Already received, continue scanning

            // Request to be called again in next frame
            requestAnimationFrame(ReceiveQRtick);

            // Exit from the function
            return

        }

        // This is a new piece. Add it to the set
        receivedPieces.add(index)
        receivedQRPieces[+index] = piece    // Make sure that index is considered an integer and not a string

        // Display in the page the number of the object received.
        progressMessages.innerText = "Received piece: " + index;

        // Check if we need more pieces
        if (receivedPieces.size < total) {
            // Continue scanning

            // Request to be called again in next frame
            requestAnimationFrame(ReceiveQRtick);

            // Exit from the function
            return

        }

        // We have received all pieces

        // Stop the media stream
        stopMediaTracks(myStream);

        // Hide the picture
        canvasElement.hidden = true;

        mylog("Received all pieces", receivedQRPieces)

        // Assemble all pieces together
        var jwt = receivedQRPieces.join("")
        mylog("Received jwt", jwt)

        // Extract the credential and save in the temporary storage
        try {
            var cred = decodeJWT(jwt);

            // Store in temporal storage so the page will retrieve it
            currentCredential = {
                type: "w3cvc",
                encoded: jwt,
                decoded: cred,
            }
            mylog("Writing current cred: ", currentCredential)
            await settingsPut("currentCredential", currentCredential);

        } catch (error) {
            myerror(error)
            progressMessages.innerText = error;
            return
        }

        // Switch to the presentation of results
        gotoPage(displayQRPage, { screenType: callerType })

        return

    }

    if (qrType == "URL") {
        // We received a URL in the QR. Perform a GET to obtain the JWT from a server
        mylog("Scanned normal URL QR")

        // Stop the media stream
        stopMediaTracks(myStream);

        // Build the URL to call
        var targetURLRead = code.data.trim()

        // Check if the URL points to a JWT or to the wallet
        if (targetURLRead.startsWith(MYSELF)) {
            // The URL points to the wallet. There is a param with the credential id
            const url = new URL(targetURLRead)

            // First we check for a normal credential
            let credId = url.searchParams.get("id")
            if (credId) {
                targetURLRead = ISSUER_GET_CREDENTIAL + credId
            } else {
                // Now check for a Public Credential
                credId = url.searchParams.get("pubid")
                if (credId) {
                    targetURLRead = ISSUER_GET_PUBLIC_CREDENTIAL + credId
                }
            }

        }


        // Retrieve the credential from the server and display it
        await requestQRAndDisplay(targetURLRead, displayQRPage, callerType)

        return

    }

    const HC_ISS = 1
    const HC_IAT = 6
    const HC_EXP = 4
    const HC_CTI = 7
    const HC_HCERT = -260

    if (qrType == "HC1") {
        // We received a Health Certificate (HC) version 1 encoded QR.
        mylog("Scanned HC1 QR")

        // Stop the media stream
        stopMediaTracks(myStream);

        let certB45 = code.data.substring(4)
        let certCompressed = decodeB45(certB45)
        let certCOSE = pako.inflate(certCompressed)
        let aux = new COSE(certCOSE)
        let plain = aux.decode()
        console.log(plain)

        // The object plain is an array of 4 elements
        // The third is the body of the credential, and we will decode it

        let body = new COSE(plain[2])
        body = body.cbor2json()
        console.log(body)


        // Store in temporal storage so the page will retrieve it
        currentCredential = {
            type: "hcert",
            encoded: code.data,
            decoded: plain
        }
        await settingsPut.setItem("currentCredential", currentCredential);

        // Switch to the presentation of results
        gotoPage(displayQRPage, { screenType: callerType })

        return

    }

    if (qrType == "Base64") {
        // We received a Base64 encoded QR. May be it is the UK Immigration document
        mylog("Scanned Base64 simple QR")

        // Stop the media stream
        stopMediaTracks(myStream);

        var decodedQR = JSON.parse(atobUrl(code.data))

        // Store in temporal storage so the page will retrieve it
        currentCredential = {
            type: "ukimmigration",
            encoded: code.data,
            decoded: decodedQR
        }
        await settingsPut.setItem("currentCredential", currentCredential);

        // Switch to the presentation of results
        gotoPage(displayQRPage, { screenType: callerType })

        return

    }

}


function stopMediaTracks(stream) {
    // Stop the media stream
    tracks = stream.getTracks();
    tracks[0].stop();

    return
}


// Retrieve a QR from a URL and display it so the user can save it
async function requestQRAndDisplay(targetURLRead, displayQRPage, callerType) {

    // Flag to perform verification of received credential
    verifyCred = false

    // Get the JWT from the server
    data = "";
    try {
        data = await $.get(targetURLRead);
        mylog("Received credential from Issuer", data);
    } catch (error) {
        myerror("Error gettting credential from Issuer");
        alert("Error gettting credential")
        return;
    }

    // We have received a JWT in the payload field of the result body
    jwt = data;

    if (verifyCred) {
        // Verify the jwt including the signature (queries Issuer signature in the blockchain)
        try {
            claims = await verifyJwtVc(jwt);
            console.log("Verified:", claims);
        } catch (error) {
            myerror(error.responseText);
            return
        }
    }

    // Extract the credential and save in the temporary storage
    try {
        var cred = decodeJWT(jwt);
        console.log("Extracted credential", cred)

        // Store in temporal storage so the page will retrieve it
        currentCredential = {
            type: "w3cvc",
            encoded: jwt,
            decoded: cred
        }
        await settingsPut("currentCredential", currentCredential);

    } catch (error) {
        myerror(error.responseText)
        return
    }

    // Switch to the presentation of results
    gotoPage(displayQRPage, { screenType: callerType })

    return

}