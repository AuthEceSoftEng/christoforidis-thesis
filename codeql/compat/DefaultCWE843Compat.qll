private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.TypeConfusionThroughParameterTamperingQuery as TCC

module DefaultCWE843Compat {
    
    predicate defaultIsSource(DataFlow::Node source) {
        TCC::TypeConfusionConfig::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        TCC::TypeConfusionConfig::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        TCC::TypeConfusionConfig::isAdditionalFlowStep(pred, succ)
    }
    predicate defaultBarrier(DataFlow::Node node) {
        TCC::TypeConfusionConfig::isBarrier(node)
    }
}