private import javascript
private import DataFlow
import semmle.javascript.security.dataflow.ExternalAPIUsedWithUntrustedDataQuery as EUD

module DefaultCWE20Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        EUD::ExternalAPIUsedWithUntrustedDataConfig::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        EUD::ExternalAPIUsedWithUntrustedDataConfig::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        EUD::ExternalAPIUsedWithUntrustedDataConfig::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        EUD::ExternalAPIUsedWithUntrustedDataConfig::isBarrier(node)
    }
}
