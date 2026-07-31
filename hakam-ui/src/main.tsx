import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import Poster from "./components/Poster";

// Minimal path-based routing — no router dependency. `/poster` renders the
// SAIF scientific-poster canvas; everything else is the live HUD.
const isPoster = window.location.pathname.replace(/\/+$/, "") === "/poster";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{isPoster ? <Poster /> : <App />}</React.StrictMode>,
);
