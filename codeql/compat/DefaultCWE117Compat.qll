private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.LogInjectionQuery::LogInjectionConfig as LIC

module DefaultCWE117Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        LIC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        LIC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        LIC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        LIC::isBarrier(node)
    }
}