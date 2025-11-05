private import javascript
private import DataFlow
private import semmle.javascript.security.dataflow.ConditionalBypassQuery as CBQ
private import CBQ::ConditionalBypassFlow::PathGraph

module DefaultCWE807Compat {
  // Compute valid (source,sink) endpoint pairs once
  private predicate validPair(
    CBQ::ConditionalBypassFlow::PathNode s,
    CBQ::ConditionalBypassFlow::PathNode t
  ) {
    exists(CBQ::SensitiveAction action |
      CBQ::ConditionalBypassFlow::flowPath(s, t) and
      CBQ::isTaintedGuardNodeForSensitiveAction(t, s, action) and
      not CBQ::isEarlyAbortGuardNode(t, action)
    )
  }

  // Map PathNodes to DataFlow::Nodes once, to be reused by both ends
  private predicate defaultPairNodes(DataFlow::Node src, DataFlow::Node snk) {
    exists(
      CBQ::ConditionalBypassFlow::PathNode s,
      CBQ::ConditionalBypassFlow::PathNode t |
      validPair(s, t) and
      src = s.getNode() and
      snk = t.getNode()
    )
  }

  // Reuse the shared pair relation for each end
  predicate defaultIsSource(DataFlow::Node source) {
    exists(DataFlow::Node sink | defaultPairNodes(source, sink))
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(DataFlow::Node source | defaultPairNodes(source, sink))
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    CBQ::ConditionalBypassConfig::isAdditionalFlowStep(pred, succ)
  }

  predicate defaultBarrier(DataFlow::Node node) {
    CBQ::ConditionalBypassConfig::isBarrier(node)
  }
}