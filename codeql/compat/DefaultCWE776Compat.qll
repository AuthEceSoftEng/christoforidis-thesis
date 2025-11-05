private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.XmlBombQuery::XmlBombConfig as XBC

module DefaultCWE776Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        XBC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        XBC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        XBC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        XBC::isBarrier(node)
    }
}