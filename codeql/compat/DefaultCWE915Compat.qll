private import javascript
private import DataFlow
private import semmle.javascript.DynamicPropertyAccess
private import semmle.javascript.dataflow.InferredTypes
import semmle.javascript.security.dataflow.PrototypePollutingAssignmentQuery as PPAQ
private import PPAQ::PrototypePollutingAssignmentFlow::PathGraph
import semmle.javascript.security.dataflow.PrototypePollutionQuery::PrototypePollutionConfig as PPC

module DefaultCWE915Compat {
  //
  // Helper patterns (adapted from the default query)
  //

  private predicate ppaValidPair(
    PPAQ::PrototypePollutingAssignmentFlow::PathNode s,
    PPAQ::PrototypePollutingAssignmentFlow::PathNode t
  ) {
    PPAQ::PrototypePollutingAssignmentFlow::flowPath(s, t) and
    not PPAQ::isIgnoredLibraryFlow(s.getNode(), t.getNode())
  }

  /** x.split(".") where x is a parameter (typical deep-assign key source). */
  class SplitCall extends StringSplitCall {
    SplitCall() {
      this.getSeparator() = "." and
      this.getBaseString().getALocalSource() instanceof DataFlow::ParameterNode
    }
  }

  /** Copy array elements through common array ops (push/spread/concat). */
  private predicate copyArrayStep(DataFlow::SourceNode pred, DataFlow::SourceNode succ) {
    // x -> [...x]
    exists(SpreadElement spread |
      pred.flowsTo(spread.getOperand().flow()) and
      succ.asExpr().(ArrayExpr).getAnElement() = spread
    )
    or
    // y.push( x[i] )
    exists(DataFlow::MethodCallNode push |
      push = succ.getAMethodCall("push") and
      (
        getAnEnumeratedArrayElement(pred).flowsTo(push.getAnArgument()) or
        pred.flowsTo(push.getASpreadArgument())
      )
    )
    or
    // x.concat(...)
    exists(DataFlow::MethodCallNode concat_ |
      concat_.getMethodName() = "concat" and
      (pred = concat_.getReceiver() or pred = concat_.getAnArgument()) and
      succ = concat_
    )
  }

  /** Holds if node may refer to a split array or a copy thereof. */
  private predicate isSplitArray(DataFlow::SourceNode node) {
    node instanceof SplitCall
    or
    exists(DataFlow::SourceNode pred | isSplitArray(pred) |
      copyArrayStep(pred, node)
      or
      pred.flowsToExpr(node.(DataFlow::CallNode).getACallee().getAReturnedExpr())
    )
  }

  /** A property name originating from a x.split(".") call. */
  class SplitPropName extends DataFlow::SourceNode {
    DataFlow::SourceNode array;
    SplitPropName() {
      isSplitArray(array) and
      this = getAnEnumeratedArrayElement(array)
    }
    DataFlow::SourceNode getArray() { result = array }
    SplitPropName getAnAlias() { result.getArray() = this.getArray() }
  }

  /** Properties of node are enumerated locally. */
  private predicate arePropertiesEnumerated(DataFlow::SourceNode node) {
    node = any(EnumeratedPropName name).getASourceObjectRef()
  }

  /** Prototype pollution payload-like property name sources. */
  private predicate isPollutedPropNameSource(DataFlow::Node node) {
    node instanceof EnumeratedPropName
    or
    node instanceof SplitPropName
  }

  /** base[prop] = rhs with computed property name and plausible RHS. */
  private predicate dynamicPropWrite(DataFlow::Node base, DataFlow::Node prop, DataFlow::Node rhs) {
    exists(DataFlow::PropWrite write |
      write.getBase() = base and
      write.getPropertyNameExpr().flow() = prop and
      rhs = write.getRhs()
    )
    and not exists(prop.getStringValue())
    and not arePropertiesEnumerated(base.getALocalSource())
    and not exists(Expr e | e = rhs.asExpr() |
      e instanceof Literal or e instanceof ObjectExpr or e instanceof ArrayExpr
    )
  }


  predicate defaultIsSource(DataFlow::Node source) {
    isPollutedPropNameSource(source)
    or exists(
      PPAQ::PrototypePollutingAssignmentFlow::PathNode s,
      PPAQ::PrototypePollutingAssignmentFlow::PathNode t |
      ppaValidPair(s, t) and source = s.getNode()
    )
    or exists(PPC::FlowState st | PPC::isSource(source, st))
  }

  predicate defaultIsSink(DataFlow::Node sink) {
    exists(DataFlow::Node base, DataFlow::Node prop, DataFlow::Node rhs |
      dynamicPropWrite(base, prop, rhs) and sink = base
    )
    or exists(
      PPAQ::PrototypePollutingAssignmentFlow::PathNode s,
      PPAQ::PrototypePollutingAssignmentFlow::PathNode t |
      ppaValidPair(s, t) and sink = t.getNode()
    )
    or exists(PPC::FlowState st | PPC::isSink(sink, st))
  }

  predicate defaultAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // p -> x[p] (key to dynamic read)
    exists(DataFlow::PropRead read |
      pred = read.getPropertyNameExpr().flow() and
      not read.(DynamicPropRead).hasDominatingAssignment() and
      succ = read
    )
    or
    // x -> x[p] (base to dynamic read)
    exists(DynamicPropRead read |
      not read.hasDominatingAssignment() and
      pred = read.getBase() and
      succ = read
    )
    or
    // Argument/parameter propagation (incl. simple callback hop)
    DataFlow::argumentPassingStep(_, pred, _, succ)
    or
    exists(DataFlow::FunctionNode fn, DataFlow::ParameterNode cb, int i |
      pred = cb.getAnInvocation().getArgument(i) and
      DataFlow::argumentPassingStep(_, fn, _, cb) and
      succ = fn.getParameter(i)
    )
    or
    exists(PPAQ::PrototypePollutingAssignmentConfig::FlowState s1, PPAQ::PrototypePollutingAssignmentConfig::FlowState s2 |
      PPAQ::PrototypePollutingAssignmentConfig::isAdditionalFlowStep(pred, s1, succ, s2)
    )
    or exists(PPC::FlowState s1, PPC::FlowState s2 |
      PPC::isAdditionalFlowStep(pred, s1, succ, s2)
    )
  }

  predicate defaultBarrier(DataFlow::Node node) {
    node instanceof TaintTracking::AdditionalBarrierGuard
    or node instanceof TaintTracking::MembershipTestSanitizer
    or node instanceof TaintTracking::PositiveIndexOfSanitizer
    or PPAQ::PrototypePollutingAssignmentConfig::isBarrier(node) or
    exists(PPAQ::PrototypePollutingAssignmentConfig::FlowState st | PPAQ::PrototypePollutingAssignmentConfig::isBarrier(node, st))
    or exists(PPC::FlowState st | PPC::isBarrier(node, st))
  }
}