private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.XxeQuery::XxeConfig as XC

module DefaultCWE611Compat {

    predicate defaultIsSource(DataFlow::Node source) {
        XC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        XC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        XC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        XC::isBarrier(node)
    }
}