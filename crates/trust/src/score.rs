use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trust level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// No trust established
    None,
    /// Basic trust level
    Low,
    /// Moderate trust level
    Medium,
    /// High trust level
    High,
    /// Very high trust level
    VeryHigh,
}

/// Trust metrics used in score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMetrics {
    /// Direct trust score (0.0 to 1.0)
    pub direct_trust: f64,
    /// Indirect trust score (0.0 to 1.0)
    pub indirect_trust: f64,
    /// Historical trust score (0.0 to 1.0)
    pub historical_trust: f64,
    /// Behavioral trust score (0.0 to 1.0)
    pub behavioral_trust: f64,
    /// Identity verification score (0.0 to 1.0)
    pub identity_verification: f64,
    /// Additional custom metrics
    #[serde(default)]
    pub custom_metrics: HashMap<String, f64>,
}

impl Default for TrustMetrics {
    fn default() -> Self {
        Self {
            direct_trust: 0.0,
            indirect_trust: 0.0,
            historical_trust: 0.0,
            behavioral_trust: 0.0,
            identity_verification: 0.0,
            custom_metrics: HashMap::new(),
        }
    }
}

/// Trust score with associated metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// The calculated trust score (0.0 to 1.0)
    pub score: f64,
    /// The trust level based on the score
    pub level: TrustLevel,
    /// The individual trust metrics
    pub metrics: TrustMetrics,
    /// Timestamp when the score was calculated
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Score confidence (0.0 to 1.0)
    pub confidence: f64,
    /// Score validity period
    pub validity_period: chrono::Duration,
}

impl TrustScore {
    /// Create a new trust score
    pub fn new(
        score: f64,
        level: TrustLevel,
        metrics: TrustMetrics,
        confidence: f64,
        validity_period: chrono::Duration,
    ) -> crate::Result<Self> {
        if !(0.0..=1.0).contains(&score) {
            return Err(crate::TrustError::InvalidTrustScore(
                "Score must be between 0.0 and 1.0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&confidence) {
            return Err(crate::TrustError::InvalidTrustScore(
                "Confidence must be between 0.0 and 1.0".into(),
            ));
        }

        Ok(Self {
            score,
            level,
            metrics,
            timestamp: chrono::Utc::now(),
            confidence,
            validity_period,
        })
    }

    /// Check if the trust score is still valid
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now();
        now - self.timestamp < self.validity_period
    }

    /// Calculate the weighted trust score from metrics
    pub fn calculate_weighted_score(metrics: &TrustMetrics, weights: &HashMap<String, f64>) -> f64 {
        let default_weights: HashMap<&str, f64> = [
            ("direct_trust", 0.3),
            ("indirect_trust", 0.2),
            ("historical_trust", 0.2),
            ("behavioral_trust", 0.2),
            ("identity_verification", 0.1),
        ]
        .into_iter()
        .collect();

        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        // Calculate weighted sum for standard metrics
        weighted_sum += metrics.direct_trust
            * weights
                .get("direct_trust")
                .unwrap_or(&default_weights["direct_trust"]);
        weighted_sum += metrics.indirect_trust
            * weights
                .get("indirect_trust")
                .unwrap_or(&default_weights["indirect_trust"]);
        weighted_sum += metrics.historical_trust
            * weights
                .get("historical_trust")
                .unwrap_or(&default_weights["historical_trust"]);
        weighted_sum += metrics.behavioral_trust
            * weights
                .get("behavioral_trust")
                .unwrap_or(&default_weights["behavioral_trust"]);
        weighted_sum += metrics.identity_verification
            * weights
                .get("identity_verification")
                .unwrap_or(&default_weights["identity_verification"]);

        total_weight += weights
            .get("direct_trust")
            .unwrap_or(&default_weights["direct_trust"]);
        total_weight += weights
            .get("indirect_trust")
            .unwrap_or(&default_weights["indirect_trust"]);
        total_weight += weights
            .get("historical_trust")
            .unwrap_or(&default_weights["historical_trust"]);
        total_weight += weights
            .get("behavioral_trust")
            .unwrap_or(&default_weights["behavioral_trust"]);
        total_weight += weights
            .get("identity_verification")
            .unwrap_or(&default_weights["identity_verification"]);

        // Add custom metrics
        for (key, value) in &metrics.custom_metrics {
            if let Some(weight) = weights.get(key) {
                weighted_sum += value * weight;
                total_weight += weight;
            }
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Determine trust level from a score
    pub fn determine_trust_level(score: f64, thresholds: &[(TrustLevel, f64)]) -> TrustLevel {
        let mut level = TrustLevel::None;
        for (trust_level, threshold) in thresholds {
            if score >= *threshold {
                level = *trust_level;
            } else {
                break;
            }
        }
        level
    }
}
