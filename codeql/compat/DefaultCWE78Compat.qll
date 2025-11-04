private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.CommandInjectionQuery::CommandInjectionConfig as CIC
import semmle.javascript.security.dataflow.IndirectCommandInjectionQuery::IndirectCommandInjectionConfig as ICIC
import semmle.javascript.security.dataflow.SecondOrderCommandInjectionQuery::SecondOrderCommandInjectionConfig as SOCIC
import semmle.javascript.security.dataflow.ShellCommandInjectionFromEnvironmentQuery::ShellCommandInjectionFromEnvironmentConfig as SCEIC
import semmle.javascript.security.dataflow.UnsafeShellCommandConstructionQuery::UnsafeShellCommandConstructionConfig as USCIC

module DefaultCWE78Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        CIC::isSource(source)
        or ICIC::isSource(source)
        or exists(SOCIC::FlowState st | SOCIC::isSource(source, st))
        or SCEIC::isSource(source)
        or USCIC::isSource(source)
    }

    predicate defaultIsSink(DataFlow::Node sink) {
        CIC::isSink(sink)
        or ICIC::isSink(sink)
        or exists(SOCIC::FlowState st | SOCIC::isSink(sink, st))
        or SCEIC::isSink(sink)
        or USCIC::isSink(sink)
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        CIC::isAdditionalFlowStep(pred, succ)
        or ICIC::isAdditionalFlowStep(pred, succ)
        or exists(SOCIC::FlowState s1, SOCIC::FlowState s2 |
      SOCIC::isAdditionalFlowStep(pred, s1, succ, s2)
        )
        or SCEIC::isAdditionalFlowStep(pred, succ)
        or USCIC::isAdditionalFlowStep(pred, succ)
    }

    predicate defaultBarrier(DataFlow::Node node) {
        CIC::isBarrier(node)
        or ICIC::isBarrier(node)
        or SOCIC::isBarrier(node) or
    exists(SOCIC::FlowState st | SOCIC::isBarrier(node, st))
        or SCEIC::isBarrier(node)
        or USCIC::isBarrier(node)
    }
}