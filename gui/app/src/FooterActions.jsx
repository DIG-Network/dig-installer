// The wizard footer's right-hand action row. Extracted from App so the button
// composition per step is unit-testable and the row can own its own responsive
// wrapping (#716): it wraps below the left cluster on a narrow window / long
// locale rather than clipping a button past the window edge.

export function FooterActions({
  cur,
  step,
  installing,
  error,
  canContinue,
  primaryLabel,
  onBack,
  onViewLog,
  onOpenDocs,
  onClose,
  onNext,
}) {
  const showBack = step > 0 && !installing && cur !== "finish";
  const showViewLog = installing && error;
  const isFinish = cur === "finish";

  return (
    <div className="foot-actions">
      {/* Back: hidden on the first step and while installing/finishing. */}
      {showBack && (
        <button className="btn btn-secondary" onClick={onBack}>
          Back
        </button>
      )}

      {/* Error state while installing gets a "View log" secondary action. */}
      {showViewLog && (
        <button className="btn btn-secondary" onClick={onViewLog}>
          View log
        </button>
      )}

      {/* Done screen: "Open Documentation" secondary + "Close" as the primary
          escape hatch — the user is never trapped (§6.1). The generic
          step-advance primary is suppressed here. */}
      {isFinish ? (
        <>
          <button className="btn btn-secondary" onClick={onOpenDocs}>
            Open Documentation
          </button>
          <button className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </>
      ) : (
        <button
          className={"btn " + (installing && error ? "btn-danger" : "btn-primary")}
          onClick={onNext}
          disabled={!canContinue && !(installing && error)}
        >
          {primaryLabel}
        </button>
      )}
    </div>
  );
}
