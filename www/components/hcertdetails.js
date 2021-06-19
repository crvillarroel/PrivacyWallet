import { html, css, LitElement } from "lit";

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
  recentLogs,
  clearLogs,
  resetDatabase,
} from "./db.js";

export class HcertDetails extends LitElement {
  static get styles() {
    return css`
      p {
        color: blue;
      }
    `;
  }

  static get properties() {
    return {
      key: { type: String },
    };
  }

  constructor() {
    super();
    this.key = "";
  }

  render() {
    // Retrieve the credential and extract its components
    let cred = await credentialsGet(this.key);

    let payload = cred["decoded"][1];

    // Calculate the display name and date for the card
    let displayName = "Unrecognized";
    let cred_date = "Unrecognized";

    let theHtml = "Unrecognized";

    if (payload["certType"] == "v") {
      theHtml = html`
        <div class="container mb-2 border bg-light">
          <div class="hcert title">EU DIGITAL COVID CERTIFICATE</div>
          <div class="hcert subtitle">Vaccination</div>
        </div>

        <div class="container mb-2 border">
          <div class="mb-2">
            <div class="etiqueta mt-3">Name</div>
            <div class="valor mb-3">${payload.fullName}</div>
          </div>
          <div>
            <div class="etiqueta">Date of birth</div>
            <div class="valor">${payload.dateOfBirth}</div>
          </div>
        </div>

        <div class="container">
          <div class="hcert subtitle">Vaccination details</div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Certificate identifier</div>
              <div class="etiqueta mb-3 text-break">
                <strong>${payload.uniqueIdentifier}</strong>
              </div>

              <div class="etiqueta">Certificate issuer</div>
              <div class="valor">${payload.certificateIssuer}</div>
            </div>
          </div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Disease targeted</div>
            </div>
            <div class="col">
              <div class="valor mt-3">${payload.diseaseTargeted}</div>
            </div>
          </div>
        </div>

        <div class="container border">
          <div class="row mb-3">
            <div class="col-sm">
              <div class="etiqueta mt-3">Vaccine/profilaxis targeted</div>
              <div class="valor mb-3">${payload.vaccineProphylaxis}</div>

              <div class="etiqueta">Vaccine medicinal product</div>
              <div class="valor mb-3">${payload.medicinalProduct}</div>

              <div class="etiqueta">Manufacturer</div>
              <div class="valor">${payload.manufacturer}</div>
            </div>

            <div class="col-sm">
              <div class="etiqueta mt-3">Dose number/Total doses</div>
              <div class="valor mb-3">
                ${payload.doseNumber}/${payload.doseTotal}
              </div>

              <div class="etiqueta">Date of vaccination</div>
              <div class="valor mb-3">${payload.dateVaccination}</div>

              <div class="etiqueta">Member State of vaccination</div>
              <div class="valor">${payload.country}</div>
            </div>
          </div>
        </div>
      `;
    }

    if (payload["certType"] == "t") {
      theHtml = html`
        <div class="container mb-2 border bg-light">
          <div class="hcert title">EU DIGITAL COVID CERTIFICATE</div>
          <div class="hcert subtitle">Test</div>
        </div>

        <div class="container mb-2 border">
          <div class="mb-2">
            <div class="etiqueta mt-3">Name</div>
            <div class="valor mb-3">${payload.fullName}</div>
          </div>
          <div>
            <div class="etiqueta">Date of birth</div>
            <div class="valor">${payload.dateOfBirth}</div>
          </div>
        </div>

        <div class="container">
          <div class="hcert subtitle">Test details</div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Certificate identifier</div>
              <div class="etiqueta mb-3 text-break">
                <strong>${payload.uniqueIdentifier}</strong>
              </div>

              <div class="etiqueta">Certificate issuer</div>
              <div class="valor">${payload.certificateIssuer}</div>
            </div>
          </div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Disease targeted</div>
            </div>
            <div class="col">
              <div class="valor mt-3">${payload.diseaseTargeted}</div>
            </div>
          </div>
        </div>

        <div class="container border">
          <div class="row mb-3">
            <div class="col-sm">
              <div class="etiqueta mt-3">Type of Test</div>
              <div class="valor mb-3">${payload.typeTest}</div>

              <div class="etiqueta">NAA Test Name</div>
              <div class="valor mb-3">${payload.testName}</div>

              <div class="etiqueta">Manufacturer</div>
              <div class="valor">${payload.manufacturer}</div>
            </div>

            <div class="col-sm">
              <div class="etiqueta mt-3">Test Result</div>
              <div class="valor mb-3">${payload.testResult}</div>

              <div class="etiqueta">Date/Time of Sample Collection</div>
              <div class="valor mb-3">${payload.timeSample}</div>

              <div class="etiqueta">Testing Centre</div>
              <div class="valor">${payload.testingCentre}</div>
            </div>
          </div>
        </div>
      `;
    }

    if (payload["certType"] == "r") {
      theHtml = html`
        <div class="container mb-2 border bg-light">
          <div class="hcert title">EU DIGITAL COVID CERTIFICATE</div>
          <div class="hcert subtitle">Recovery</div>
        </div>

        <div class="container mb-2 border">
          <div class="mb-2">
            <div class="etiqueta mt-3">Name</div>
            <div class="valor mb-3">${payload.fullName}</div>
          </div>
          <div>
            <div class="etiqueta">Date of birth</div>
            <div class="valor">${payload.dateOfBirth}</div>
          </div>
        </div>

        <div class="container">
          <div class="hcert subtitle">Recovery details</div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Disease targeted</div>
            </div>
            <div class="col">
              <div class="valor mt-3">${payload.diseaseTargeted}</div>
            </div>
          </div>
        </div>

        <div class="container border">
          <div class="row mb-3">
            <div class="col-sm">
              <div class="etiqueta mt-3">Date of positive</div>
              <div class="valor mb-3">${payload.datePositive}</div>
            </div>

            <div class="col-sm">
              <div class="etiqueta mt-3">Valid from</div>
              <div class="valor mb-3">${payload.dateFrom}</div>
            </div>

            <div class="col-sm">
              <div class="etiqueta mt-3">Valid to</div>
              <div class="valor">${payload.dateUntil}</div>
            </div>
          </div>
        </div>

        <div class="container mb-2 border">
          <div class="row">
            <div class="col">
              <div class="etiqueta mt-3">Certificate identifier</div>
              <div class="etiqueta mb-3 text-break">
                <strong>${payload.uniqueIdentifier}</strong>
              </div>

              <div class="etiqueta">Certificate issuer</div>
              <div class="valor">${payload.certificateIssuer}</div>

              <div class="etiqueta">Country of Test</div>
              <div class="valor">${payload.country}</div>
            </div>
          </div>
        </div>
      `;
    }

    return theHtml;
  }
}

customElements.define("hcert-details", SimpleGreeting);
