import React from "react";
import ReactDOM from "react-dom/client";
import TrayMenu from "./TrayMenu";
import { syncThemeFromStorage } from "./lib/theme";
import "./App.css";
import "./tray.css";

syncThemeFromStorage();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <TrayMenu />
  </React.StrictMode>
);
