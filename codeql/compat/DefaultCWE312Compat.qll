private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.BuildArtifactLeakQuery::BuildArtifactLeakConfig as BALC
import semmle.javascript.security.dataflow.CleartextLoggingQuery::CleartextLoggingConfig as CLLC
import semmle.javascript.security.dataflow.CleartextStorageQuery::ClearTextStorageConfig as CTSC

module DefaultCWE312Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        BALC::isSource(source)
        or CLLC::isSource(source)
        or CTSC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        BALC::isSink(sink)
        or CLLC::isSink(sink)
        or CTSC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        BALC::isAdditionalFlowStep(pred, succ)
        or CLLC::isAdditionalFlowStep(pred, succ)
        or CTSC::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        BALC::isBarrier(node)
        or CLLC::isBarrier(node)
        or CTSC::isBarrier(node)
    }
}