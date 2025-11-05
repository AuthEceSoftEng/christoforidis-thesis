private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.HardcodedCredentialsQuery::HardcodedCredentialsConfig as HCC

module DefaultCWE798Compat {
    predicate defaultIsSource(DataFlow::Node source) {
        HCC::isSource(source)
    }
    predicate defaultIsSink(DataFlow::Node sink) {
        HCC::isSink(sink)
    }
    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
        HCC::isAdditionalFlowStep(pred, succ)
    }

    // Heuristic from the default query
  bindingset[s]
  private predicate looksLikeATemplate(string s) {
    s.regexpMatch(".*((\\{\\{.*\\}\\})|(<.*>)|(\\(.*\\))).*")
  }

  // Treat obvious dummy/template constants as sanitizers (node-level)
  private predicate isDummyCredentialConstant(DataFlow::Node node) {
    exists(string val |
      node.asExpr() instanceof ConstantString and
      val = node.getStringValue() and
      (
        PasswordHeuristics::isDummyPassword(val) or
        PasswordHeuristics::isDummyAuthHeader(val) or
        looksLikeATemplate(val)
      )
    )
  }
    predicate defaultBarrier(DataFlow::Node node) {
        HCC::isBarrier(node)
        or isDummyCredentialConstant(node)
    }
}