private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.XpathInjectionQuery::XpathInjectionConfig as XIC

module DefaultCWE643Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        XIC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        XIC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        XIC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        XIC::isBarrier(node)
    }
}