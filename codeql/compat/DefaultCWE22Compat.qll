private import javascript
private import DataFlow

private import semmle.javascript.security.dataflow.TaintedPathQuery::TaintedPathConfig as TPC
private import semmle.javascript.security.dataflow.ZipSlipQuery::ZipSlipConfig as ZSC

module DefaultCWE22Compat {
  predicate defaultIsSource(DataFlow::Node source) {
    exists(TPC::FlowState st | TPC::isSource(source, st))
    or
    exists(ZSC::FlowState st | ZSC::isSource(source, st))
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(TPC::FlowState st | TPC::isSink(sink, st))
    or
    exists(ZSC::FlowState st | ZSC::isSink(sink, st))
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(TPC::FlowState s1, TPC::FlowState s2 |
      TPC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or
    exists(ZSC::FlowState s1, ZSC::FlowState s2 |
      ZSC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    TPC::isBarrier(node) or
    exists(TPC::FlowState st | TPC::isBarrier(node, st))
    or
    ZSC::isBarrier(node) or
    exists(ZSC::FlowState st | ZSC::isBarrier(node, st))
  }
}