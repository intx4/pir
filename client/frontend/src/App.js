import "./App.css";
import React, { useState, useEffect } from "react";
//BootStrap react imports
import "bootstrap/dist/css/bootstrap.min.css";
import Home from "./components/Home";

import {
  BrowserRouter as Router,
  Route,
  Routes,
} from "react-router-dom";


//components
const NotFound = () => <h1>404: Page not found</h1>;

//Routes
const routes = [
  { path: "/", component: Home, protected: false },
  { path: "/*", component: NotFound, protected: false },
];

function App() {

  const addr = "127.0.0.1";
  return (
    <div className="App" style={{background:"black", color:"grey"}}>
        <Router>
          <Routes>
            <Route exact path="/" element={<Home addr={addr} />} />
            <Route path="/*" element={<NotFound/>}/>
          </Routes>
        </Router>
    </div>
  );
}

export default App;
