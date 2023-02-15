import { useNavigate } from "react-router-dom";
import React, { useState, useEffect, useRef } from "react";
//BootStrap react imports
import Container from "react-bootstrap/Container";
import Button from "react-bootstrap/Button";
import Navbar from "react-bootstrap/Navbar";
import "bootstrap/dist/css/bootstrap.min.css";
import logo from "../img/p3li5.png"
export default function Nav(props) {
  return (
    <Container>
      <Navbar sticky="top" style={{background:"black"}}>
        <Container fluid className="d-flex">
          <Navbar.Brand>
            <img
              src={logo}
              width="300"
              height="120"
              className="d-inline-block align-top"
            />
          </Navbar.Brand>
        </Container>
      </Navbar>
    </Container>
  );
}
