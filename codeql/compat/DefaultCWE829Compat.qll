private import javascript
private import DataFlow

import semmle.javascript.security.dataflow.InsecureDownloadQuery::InsecureDownloadConfig as IDC

module DefaultCWE829Compat {

    predicate defaultIsSource(DataFlow::Node source) {
    exists(IDC::FlowState st | IDC::isSource(source, st))
  }

    predicate defaultIsSink(DataFlow::Node sink) {
        exists(IDC::FlowState st | IDC::isSink(sink, st))
    }

    predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
      IDC::isAdditionalFlowStep(pred, succ)
  }

  predicate defaultBarrier(DataFlow::Node node) {
    IDC::isBarrier(node)
  }

}