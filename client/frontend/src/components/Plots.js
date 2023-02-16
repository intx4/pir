import {XYPlot, XAxis, YAxis, VerticalBarSeries, Label, HorizontalBarSeries, HorizontalGridLines, VerticalGridLines} from 'react-vis';

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

const MAXBARS = 10;
function LeakageChart(props) {
    let data = [...props.data];
    let i = 1;
    while (data.length < MAXBARS){
        data.push({timestamp:" ".repeat(i), leakage:0});
        i += 1;
    }
    if (data.length > MAXBARS){
        data = data.slice(-MAXBARS);
    }
    return (
        <XYPlot
            style={{ background: "#000", color: "#fff" }}
            xType="ordinal"
            width={data.length * 100}
            height={230}
            yDomain={[0, Math.max(...data.map(v => v.leakage*100))]}
        >
            <VerticalBarSeries barWidth={0.75} spacing={0.2}  data={data.map(v => ({x: v.timestamp, y: v.leakage*100}))} fill="yellow" color="yellow"/>
            <XAxis style={{ text: {stroke: 'none', fill: 'yellow', fontWeight: 600}}}  position="start" />
            <YAxis style={{ text: {stroke: 'none', fill: 'yellow', fontWeight: 600}}}
            />
        </XYPlot>
    );
}

function LatencyChart(props) {
    let data = [...props.data];
    let i = 1;
    while (data.length < MAXBARS){
        data.push({timestamp:" ".repeat(i), latency:0});
        i += 1;
    }
    if (data.length > MAXBARS){
        data = data.slice(-MAXBARS);
    }
    return (
        <XYPlot
            style={{ background: "#000", color: "#fff" }}
            xType="ordinal"
            width={data.length * 100}
            height={230}
            yDomain={[0, Math.max(...data.map(v => v.latency))]}
        >
            <VerticalGridLines />
            <HorizontalGridLines />
            <VerticalBarSeries barWidth={0.75} spacing={0.2} data={data.map(v => ({x: v.timestamp, y: v.latency}))} fill="orange" color="orange"/>
            <XAxis style={{ text: {stroke: 'none', fill: 'orange', fontWeight: 600}}} position="start" />
            <YAxis style={{ text: {stroke: 'none', fill: 'orange', fontWeight: 600}}} />
        </XYPlot>
    );
}

export default function Plots(props){
    return (
        <Container fluid className={"justify-content-md-center"}>
            <Row>
                <Col className={"justify-content-left"}> <h3 style={{color:"yellow"}}>Leakage</h3> </Col>
                <Col className={"justify-content-left"}> <h3 style={{color:"orange"}}>Latency</h3> </Col>
            </Row>
            <Row>
                <Col className={"justify-content-md-center"}>
                    <LeakageChart data={props.leakageMeasures} />
                </Col>
                <Col>
                    <LatencyChart data={props.latencyMeasures} />
                </Col>
            </Row>
        </Container>
    );
}