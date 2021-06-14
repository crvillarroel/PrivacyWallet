
import { myerror } from "./db.js";

export function decodeJWT(jwt) {
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
        myerror(decoded.error)
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
        decoded.error = "Field does not exist in JWT (body->vc->credentialSchema->id)"
        myerror(decoded.error)
        return decoded;
    }

    // Check expiration (in seconds since January 1, 1970 00:00:00 UTC.)
    let expiration = decoded.body.exp
    if (expiration) {
        let now = Date.now() / 1000     // In seconds
        let leeway = 60 * 60            // We allow a leeway of 1 hour in the comparison
        // If it has expired more than one hour before now, give an error
        if (expiration + leeway < now) {
            decoded.error = "Expired certificate"
            console.warn(decoded.error)
//            myerror(decoded.error)
        }
    }

    return decoded;

}

function btoaUrl(input) {

    // Encode using the standard Javascript function
    let astr = btoa(input)

    // Replace non-url compatible chars with base64 standard chars
    astr = astr.replace(/\+/g, '-').replace(/\//g, '_');

    return astr;
}

function atobUrl(input) {

    // Replace non-url compatible chars with base64 standard chars
    input = input.replace(/-/g, '+').replace(/_/g, '/');

    // Decode using the standard Javascript function
    let bstr = decodeURIComponent(escape(atob(input)));

    return bstr;
}

