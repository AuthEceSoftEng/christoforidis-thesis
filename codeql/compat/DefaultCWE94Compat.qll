private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.CodeInjectionQuery::CodeInjectionConfig as CIC
import semmle.javascript.security.dataflow.UnsafeCodeConstruction::UnsafeCodeConstruction::UnsafeCodeConstructionConfig as UCCC
import semmle.javascript.security.dataflow.UnsafeDynamicMethodAccessQuery::UnsafeDynamicMethodAccessConfig as UDMAC
import semmle.javascript.security.dataflow.ImproperCodeSanitizationQuery::ImproperCodeSanitizationConfig as ICSC

module DefaultCWE94Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        CIC::isSource(source)
        or UCCC::isSource(source)
        or exists(UDMAC::FlowState st | UDMAC::isSource(source, st))
        or ICSC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        CIC::isSink(sink)
        or UCCC::isSink(sink)
        or exists(UDMAC::FlowState st | UDMAC::isSink(sink, st))
        or ICSC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        CIC::isAdditionalFlowStep(pred, succ)
        or UCCC::isAdditionalFlowStep(pred, succ)
        or exists(UDMAC::FlowState s1, UDMAC::FlowState s2 |
      UDMAC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or ICSC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        CIC::isBarrier(node)
        or UCCC::isBarrier(node)
        or UDMAC::isBarrier(node) or
    exists(UDMAC::FlowState st | UDMAC::isBarrier(node, st))
        or ICSC::isBarrier(node)
    }
}