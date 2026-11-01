# Key code segments (Chapter 5)

Five short excerpts copied exactly from the repository (branch state of 31 October 2026, after issues #87, #88
and #89). Each heading gives the file and line numbers; `...` marks lines left out. Nothing inside the code has
been changed.

| # | Segment | File |
|---|---|---|
| 1 | Point-in-time comparison features | `backend/app/ml/feature_engineering.py` |
| 2 | Training and per-tier percentile thresholds | `backend/app/services/model_registry_service.py` |
| 3 | Scoring a session: threshold, flag, SHAP explanation | `backend/app/services/anomaly_service.py` |
| 4 | Live provisional scoring (R5): warm-up and throttle | `backend/app/services/live_detection_service.py` |
| 5 | A retraining guardrail check | `backend/app/services/model_registry_service.py` |

---

## 1. Point-in-time comparison features

`backend/app/ml/feature_engineering.py`, lines 45–47, 62–65 and 224–239

```python
MIN_HISTORY_FOR_ZSCORE = 5      # normal sessions needed before personal z-scores are used
RELATIVE_STD_FLOOR = 0.10       # standard deviation is never below 10% of the user's average
Z_CLIP = 10.0                   # z-scores are clamped to [-Z_CLIP, +Z_CLIP]
...
def _zscore(value: float, mean: float, std: float, floor: float) -> float:
    scale = max(std, RELATIVE_STD_FLOOR * abs(mean), floor)
    z = (value - mean) / scale
    return max(-Z_CLIP, min(Z_CLIP, z))
...
    raw = build_raw_session_features(db, session, live_duration_sec=live_duration_sec)
    stats = build_user_history_stats(
        db, session.user_id, exclude_session_id=session.session_id,
        include_simulated=include_simulated_in_baseline,
        before=session.login_time,
    )
    enough_history = stats["n_sessions"] >= MIN_HISTORY_FOR_ZSCORE

    features = dict(raw)
    for col in ZSCORE_SOURCE_COLUMNS:
        if enough_history:
            features[f"{col}_zscore"] = _zscore(
                raw[col], stats[f"{col}_mean"], stats[f"{col}_std"], MIN_STD[col]
            )
        else:
            features[f"{col}_zscore"] = 0.0
```

Each session is compared with the same user's own history, but only with sessions that started **before** it
(`before=session.login_time`). That way neither training nor scoring can see the future. Until a user has 5 earlier
normal sessions, the personal comparisons are set to neutral (0) instead of being computed from too little data.
Every z-score uses a floored standard deviation and is clipped to ±10, so a very regular user cannot turn a tiny
difference into an extreme value.

---

## 2. Training and per-tier percentile thresholds

`backend/app/core/dsfs_catalog.py`, line 52, and `backend/app/services/model_registry_service.py`, lines 247–251
and 409–418

```python
TIER_PERCENTILES = {"high": 90, "standard": 95, "low": 97}
...
def _fit(X: np.ndarray):
    scaler = StandardScaler().fit(X)
    model = IsolationForest(**MODEL_PARAMS).fit(scaler.transform(X))
    scores = -model.score_samples(scaler.transform(X))
    return model, scaler, scores
...
        # 1) Out-of-time check: fit on older sessions, count flags on the most recent ones
        n_holdout = max(1, int(round(n * HOLDOUT_FRACTION)))
        m_h, s_h, scores_h = _fit(X[:-n_holdout])
        thr_h = float(np.percentile(scores_h, TIER_PERCENTILES["standard"]))
        holdout_rate = _flag_rate(m_h, s_h, thr_h, X[-n_holdout:])

        # 2) Final model on all normal sessions
        model, scaler, scores = _fit(X)
        threshold = float(np.percentile(scores, TIER_PERCENTILES["standard"]))
        tier_thresholds = {t: float(np.percentile(scores, p)) for t, p in TIER_PERCENTILES.items()}
```

The model is trained only on normal sessions: the scaler and the Isolation Forest are fitted on the same training
rows. The anomaly thresholds are percentiles of the training scores, one per risk tier: high-privilege roles at
the 90th percentile (stricter), standard roles at the 95th and low-risk roles at the 97th. Before that, a copy is
trained on older sessions only and checked against the most recent ones, which gives an honest false-alarm rate
for the guardrails.

---

## 3. Scoring a session: threshold, flag and SHAP explanation

`backend/app/services/anomaly_service.py`, lines 263–299 (`_threshold_for_tier`, lines 114–117, returns the
tier's percentile threshold from the live model's metadata)

```python
    risk_tier = _user_risk_tier(session)
    threshold_used = _threshold_for_tier(risk_tier)
    prior_sessions = _count_prior_sessions(db, session)
    is_learning = prior_sessions < MIN_HISTORY_FOR_ZSCORE

    scaled = _scaler.transform(ordered_values)
    raw_score = float(-_model.score_samples(scaled)[0])
    is_anomaly = bool(raw_score >= threshold_used)
...
    contributions = _compute_shap_contributions(scaled)

    alert = AnomalyAlert(
        session_id=session_id,
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        ...
        threshold_used=threshold_used,
        risk_tier=risk_tier,
        ...
    )
```

When a session ends, its threshold is chosen from the user's risk tier, and the session is flagged if its anomaly
score reaches that threshold. The lines left out (272–284) apply the administrator's earlier verdicts: a session
that repeats a pattern confirmed as a threat is flagged even if the model lets it through. SHAP contributions are
stored with every alert, together with the threshold and tier used, so the explanation and the decision can be
shown later exactly as they were made.

---

## 4. Live provisional scoring (R5): warm-up and throttle

`backend/app/services/live_detection_service.py`, lines 471–491; limits in `backend/app/core/dsfs_catalog.py`,
lines 91–93 (`model_min_events: 10`, `model_min_elapsed_sec: 300`, `model_interval_sec: 60`)

```python
def _check_model(db: DBSession, session: UserSession, features, elapsed: float, now: datetime) -> None:
    n_events = db.query(AccessLog).filter(AccessLog.session_id == session.session_id).count()
    # Warm-up: a session's first minutes look unusual simply because they are short.
    if n_events < LIVE_DETECTION["model_min_events"] and elapsed < LIVE_DETECTION["model_min_elapsed_sec"]:
        return

    previous = db.query(LiveSessionScore).filter(LiveSessionScore.session_id == session.session_id).first()
    if previous is not None and (now - previous.scored_at).total_seconds() < LIVE_DETECTION["model_interval_sec"]:
        return

    if not anomaly_service._load_artifacts():
        return

    # The same model, scaler, tier threshold and SHAP explainer as end-of-session scoring.
    feature_values = features()
    scaled = anomaly_service._scaler.transform([[feature_values[col] for col in FEATURE_COLUMNS]])
    score = float(-anomaly_service._model.score_samples(scaled)[0])
    risk_tier = anomaly_service._user_risk_tier(session)
    threshold = anomaly_service._threshold_for_tier(risk_tier)
    is_learning = anomaly_service._count_prior_sessions(db, session) < MIN_HISTORY_FOR_ZSCORE
    contributions = anomaly_service._compute_shap_contributions(scaled)
```

While a session is still running, the model scores the session so far, so an administrator can act before it ends.
It waits until the session has 10 actions or has lasted 5 minutes, because any session looks unusual in its first
minute. It scores at most once a minute per session, so requests stay fast. It reuses the end-of-session model,
tier threshold and SHAP explainer; the result is an early warning, and the score when the session ends stays the
official verdict.

---

## 5. A retraining guardrail check

`backend/app/services/model_registry_service.py`, lines 59–64 and 302–322

```python
MIN_SESSIONS_TO_TRAIN = 30
HOLDOUT_FRACTION = 0.20
MIN_HOLDOUT_FOR_CHECK = 20
MAX_HOLDOUT_FLAG_RATE = 0.15
MIN_KNOWN_BAD_FOR_CHECK = 5
KNOWN_BAD_TOLERANCE = 0.10
...
    if n_holdout >= MIN_HOLDOUT_FOR_CHECK and holdout_flag_rate is not None:
        checks.append(_check(
            "recent_false_alarms", holdout_flag_rate <= MAX_HOLDOUT_FLAG_RATE,
            f"{holdout_flag_rate:.1%} of the {n_holdout} most recent normal sessions would be flagged "
            f"(limit {MAX_HOLDOUT_FLAG_RATE:.0%}, about {EXPECTED_FLAG_RATE:.0%} expected)"))
    ...
    if n_known_bad >= MIN_KNOWN_BAD_FOR_CHECK and known_bad_rate_new is not None:
        ...
        else:
            ok = known_bad_rate_new >= known_bad_rate_live - KNOWN_BAD_TOLERANCE
            checks.append(_check("known_attacks", ok,
                                 f"catches {known_bad_rate_new:.0%} of {n_known_bad} known attacks, "
                                 f"live model {known_bad_rate_live:.0%} "
                                 f"(may be at most {KNOWN_BAD_TOLERANCE:.0%} lower)"))
```

A newly trained model only goes live if it passes every guardrail. This excerpt shows two of the four. It must not
flag more than 15% of the most recent normal sessions (about 5% is expected at the 95th percentile). It must also
catch the known attacks and confirmed threats at least as well as the live model, allowing at most 10 percentage
points less. The other two checks require at least 30 training sessions and scores that actually vary between
sessions.
