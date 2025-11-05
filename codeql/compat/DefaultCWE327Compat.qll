private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.BrokenCryptoAlgorithmQuery::BrokenCryptoAlgorithmConfig as BCA

module DefaultCWE327Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        BCA::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        BCA::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        BCA::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        BCA::isBarrier(node)
    }
}