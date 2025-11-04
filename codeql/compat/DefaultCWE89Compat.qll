private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.SqlInjectionQuery::SqlInjectionConfig as SIC
import semmle.javascript.security.dataflow.NosqlInjectionQuery::NosqlInjectionConfig as NIC

module DefaultCWE89Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        SIC::isSource(source)
        or
        exists(NIC::FlowState st | NIC::isSource(source, st))
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        SIC::isSink(sink)
        or
        exists(NIC::FlowState st | NIC::isSink(sink, st))
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        SIC::isAdditionalFlowStep(pred, succ)
        or
        exists(NIC::FlowState s1, NIC::FlowState s2 |
      NIC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    }

    predicate defaultBarrier(DataFlow::Node node) {
        SIC::isBarrier(node)
        or
        NIC::isBarrier(node) or
    exists(NIC::FlowState st | NIC::isBarrier(node, st))
    }
}