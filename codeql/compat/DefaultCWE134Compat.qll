private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.TaintedFormatStringQuery::TaintedFormatStringConfig as TFS

module DefaultCWE134Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        TFS::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        TFS::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        TFS::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        TFS::isBarrier(node)
    }
}