private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.InsecureRandomnessQuery::InsecureRandomnessConfig as IRC

module DefaultCWE338Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        IRC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        IRC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        IRC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        IRC::isBarrier(node)
    }
}