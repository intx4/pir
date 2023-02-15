import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import React, { useState, useEffect, useRef } from "react";

export default function AssociationsComp (props) {
    console.log("Association list")
    const items = Array.from(props.items).map(([key, value]) => ({
        value,
    }));
    console.log(items);
    return (
        <Container fluid>
            <Row>
                <h1>Associations</h1>
            </Row>
            <Row>
                <Col md={2} xl={2} lg={2}><h2>SUPI</h2></Col>
                <Col md={2} xl={2} lg={2}><h2>SUCI</h2></Col>
                <Col md={2} xl={2} lg={2}><h2>GUTI</h2></Col>
                <Col ><h2>Start-Time</h2></Col>
                <Col ><h2>End-Time</h2></Col>
            </Row>
            <div style={{
                overflow: "auto",
                width: "100%",
                height: 300,}}>
            {items.map(item => {
                let color = "";
                if (item.value.leakage <= 0.1){
                    color = "green_assoc";
                }else if (item.value.leakage > 0.1 && item.value.leakage <= 0.5){
                    color = "yellow_assoc";
                }else{
                    color = "red_assoc";
                }
                return (
                    <div key={item.value.id} className={color}>
                        <Row>
                            <Col  style={{ borderRight: '1px solid #ddd' }} md={2} xl={2} lg={2} className={"justify-content-center"}>{item.value.supi}</Col>
                            <Col  style={{ borderRight: '1px solid #ddd' }} md={2} xl={2} lg={2} className={"justify-content-center"}>{item.value.suci}</Col>
                            <Col  style={{ borderRight: '1px solid #ddd' }} md={2} xl={2} lg={2} className={"justify-content-center"}>{item.value.guti}</Col>
                            <Col  style={{ borderRight: '1px solid #ddd' }}  className={"justify-content-center"}>{item.value.startTimestamp}</Col>
                            <Col  style={{ borderRight: '1px solid #ddd' }}  className={"justify-content-center"}>{item.value.endTimestamp}</Col>
                        </Row>
                </div>)
            })}
            </div>
        </Container>
    );
}