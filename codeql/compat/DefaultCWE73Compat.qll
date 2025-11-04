private import javascript
private import DataFlow

private import semmle.javascript.security.dataflow.TemplateObjectInjectionQuery::TemplateObjectInjectionConfig as TOIC


module DefaultCWE73Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(TOIC::FlowState st | TOIC::isSource(source, st))
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(TOIC::FlowState st | TOIC::isSink(sink, st))
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(TOIC::FlowState s1, TOIC::FlowState s2 |
      TOIC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    TOIC::isBarrier(node) or
    exists(TOIC::FlowState st | TOIC::isBarrier(node, st))
  }
}