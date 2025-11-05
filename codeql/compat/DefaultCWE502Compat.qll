private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.UnsafeDeserializationQuery::UnsafeDeserializationConfig as UDC

module DefaultCWE502Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        UDC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        UDC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        UDC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        UDC::isBarrier(node)
    }
}