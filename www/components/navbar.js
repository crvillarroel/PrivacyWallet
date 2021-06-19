import { html, css, LitElement } from "lit";

export class NavBar extends LitElement {
  static get styles() {
    return css`
      :host {
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

  createRenderRoot() {
    return this;
  }

  render() {
    return html`
      <!-- We use two headers, displayed/hidden depending on the specific page -->
      <!-- The first header is displayed by default and is used for main pages -->
      <div id="headerBrandNormal">
        <a class="navbar-brand" onclick="gotoPage(homePage)">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="25"
            height="25"
            fill="currentColor"
            class="bi bi-person-square"
            viewBox="0 0 20 20"
          >
            <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z" />
            <path
              d="M2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H2zm12 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1v-1c0-1-1-4-6-4s-6 3-6 4v1a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h12z"
            />
          </svg>
          <span>SafeIsland credentials </span>
          <button
            id="butInstall"
            class="btn btn-sm btn-primary"
            style="display: none"
            type="button"
          >
            Install
          </button>
        </a>
      </div>

      <!-- The second header is for pages with a back arrow -->
      <div id="headerBrandBack" style="display: none">
        <a class="navbar-brand" onclick="history.back()">
          <i class="bi bi-arrow-left"></i>
          <span>Back</span>
        </a>
      </div>
    `;
  }
}

customElements.define("nav-bar", NavBar);
