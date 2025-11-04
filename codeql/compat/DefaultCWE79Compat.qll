private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.ExceptionXssQuery::ExceptionXssConfig as EXC
import semmle.javascript.security.dataflow.ReflectedXssQuery::ReflectedXssConfig as RXC
import semmle.javascript.security.dataflow.StoredXssQuery::StoredXssConfig as SXC
import semmle.javascript.security.dataflow.UnsafeHtmlConstructionQuery::UnsafeHtmlConstructionConfig as UHC
import semmle.javascript.security.dataflow.UnsafeJQueryPluginQuery::UnsafeJQueryPluginConfig as UJC
import semmle.javascript.security.dataflow.DomBasedXssQuery::DomBasedXssConfig as DBC
import semmle.javascript.security.dataflow.XssThroughDomQuery::XssThroughDomConfig as XTC

module DefaultCWE79Compat {
    predicate defaultIsSource(DataFlow::Node source) {
    exists(EXC::FlowState st | EXC::isSource(source, st))
    or RXC::isSource(source)
    or SXC::isSource(source)
    or exists(UHC::FlowState st | UHC::isSource(source, st))
    or UJC::isSource(source)
    or exists(DBC::FlowState st | DBC::isSource(source, st))
    or XTC::isSource(source)
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(EXC::FlowState st | EXC::isSink(sink, st))
    or RXC::isSink(sink)
    or SXC::isSink(sink)
    or exists(UHC::FlowState st | UHC::isSink(sink, st))
    or UJC::isSink(sink)
    or exists(DBC::FlowState st | DBC::isSink(sink, st))
    or XTC::isSink(sink)
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    exists(EXC::FlowState s1, EXC::FlowState s2 |
      EXC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or RXC::isAdditionalFlowStep(pred, succ)
    or SXC::isAdditionalFlowStep(pred, succ)
    or exists(UHC::FlowState s1, UHC::FlowState s2 |
      UHC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or UJC::isAdditionalFlowStep(pred, succ)
    or exists(DBC::FlowState s1, DBC::FlowState s2 |
      DBC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or XTC::isAdditionalFlowStep(pred, succ)
  }

  predicate defaultBarrier(DataFlow::Node node) {
    EXC::isBarrier(node)
    or RXC::isBarrier(node)
    or SXC::isBarrier(node)
    or UHC::isBarrier(node)
    or UJC::isBarrier(node)
    or DBC::isBarrier(node)
    or exists(DBC::FlowState st | DBC::isBarrier(node, st))
    or XTC::isBarrier(node)
  }
}