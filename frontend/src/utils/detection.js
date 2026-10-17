// Shared wording for how a session came to be flagged.
export const DETECTION_LABELS = {
  ml_model: "Statistical anomaly (ML model)",
  repeat_pattern_override: "Repeated suspicious pattern (rule-based override)",
  confirmed_threat_pattern: "Matches a pattern an administrator confirmed as a threat",
};

export function describeDetection(reason) {
  return DETECTION_LABELS[reason] || reason || DETECTION_LABELS.ml_model;
}

const SIGNATURE_LABELS = {
  offhours: "unusual hour",
  weekend: "weekend",
  newip: "unfamiliar location",
  highwrite: "many writes",
  highdelete: "many deletions",
  highresourcevariety: "wide range of resources",
  highvolume: "high activity volume",
};

// "highvolume|newip" -> "high activity volume, unfamiliar location"
export function describeSignature(signature) {
  if (!signature || signature === "normal") return "";
  return signature.split("|").map((flag) => SIGNATURE_LABELS[flag] || flag).join(", ");
}