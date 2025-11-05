private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.RegExpInjectionQuery::RegExpInjectionConfig as RIC

module DefaultCWE730Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        RIC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        RIC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        RIC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        RIC::isBarrier(node)
    }
}