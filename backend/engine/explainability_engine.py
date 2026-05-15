"""
backend/engine/explainability_engine.py
=========================================
Explainability Engine for PhishGuard v2.
Produces structured, human-readable explanations in English and Swahili.
"""
import logging
from typing import Dict, Any, List
from backend.engine.scoring_engine import ScoringResult

logger = logging.getLogger(__name__)

TRANSLATIONS = {
    "en": {
        "legitimate":   "Legitimate",
        "suspicious":   "Suspicious",
        "phishing":     "Phishing",
        "risk_low":     "Low Risk",
        "risk_medium":  "Medium Risk",
        "risk_high":    "High Risk",
        "narrative_legitimate":
            "This email appears to be legitimate. The analysis examined {rule_count} potential "
            "indicators and found a risk score of {score}/100. "
            "{legit_note}No significant phishing patterns were detected.",
        "narrative_suspicious":
            "This email shows suspicious characteristics. {rule_count} rule(s) were triggered "
            "with a risk score of {score}/100. {composite_note}"
            "Exercise caution before clicking links or providing any information.",
        "narrative_phishing":
            "⚠️ WARNING: This email has strong indicators of a phishing attack. "
            "{rule_count} rule(s) triggered with a risk score of {score}/100. "
            "{composite_note}"
            "Do NOT click any links, open attachments, or provide personal information.",
        "url_analysis":          "URL Analysis",
        "content_keyword":       "Content & Keywords",
        "sender_verification":   "Sender Verification",
        "header_authentication": "Header Authentication",
        "html_obfuscation":      "HTML Obfuscation",
        "behavioral":            "Behavioral Patterns",
        "linguistic_analysis":   "Linguistic Analysis",
        "confidence_high":       "High Confidence",
        "confidence_medium":     "Moderate Confidence",
        "confidence_low":        "Low Confidence",
        "recommendation_phishing":
            "Recommended actions: Do NOT reply. Do NOT click any links. "
            "Report to your IT Security team. Delete the email immediately.",
        "recommendation_suspicious":
            "Recommended actions: Verify the sender through a separate channel "
            "(phone call using a number you already know). Do NOT provide credentials. "
            "Contact IT Security if unsure.",
        "recommendation_legitimate":
            "This email appears safe. Stay vigilant — always verify unexpected "
            "requests through official channels before acting.",
        "legitimacy_note_prefix": "Legitimacy signals reduced the risk score: ",
        "composite_note_prefix":  "Correlated attack patterns detected: ",
    },
    "sw": {
        "legitimate":   "Halali",
        "suspicious":   "Inashuku",
        "phishing":     "Udanganyifu",
        "risk_low":     "Hatari Ndogo",
        "risk_medium":  "Hatari ya Wastani",
        "risk_high":    "Hatari Kubwa",
        "narrative_legitimate":
            "Barua pepe hii inaonekana kuwa halali. Uchambuzi ulitathmini viashiria {rule_count} "
            "na kupata alama ya hatari ya {score}/100. "
            "{legit_note}Hakuna mfumo wa udanganyifu mkubwa uliogundulika.",
        "narrative_suspicious":
            "Barua pepe hii inaonyesha sifa za kushuku. Sheria {rule_count} zilianzishwa "
            "na alama ya hatari ya {score}/100. {composite_note}"
            "Kuwa makini kabla ya kubonyeza viungo au kutoa taarifa yoyote.",
        "narrative_phishing":
            "⚠️ ONYO: Barua pepe hii ina dalili kali za shambulio la udanganyifu. "
            "Sheria {rule_count} zilianzishwa na alama ya hatari ya {score}/100. "
            "{composite_note}"
            "USIBONYEZE viungo, usifungue viambatisho, wala usitoe taarifa za kibinafsi.",
        "url_analysis":          "Uchambuzi wa URL",
        "content_keyword":       "Maudhui na Maneno",
        "sender_verification":   "Uthibitishaji wa Mtumaji",
        "header_authentication": "Uthibitishaji wa Kichwa",
        "html_obfuscation":      "Uficho wa HTML",
        "behavioral":            "Mifumo ya Tabia",
        "linguistic_analysis":   "Uchambuzi wa Lugha",
        "confidence_high":       "Uhakika wa Juu",
        "confidence_medium":     "Uhakika wa Wastani",
        "confidence_low":        "Uhakika Mdogo",
        "recommendation_phishing":
            "Hatua zinazopendekezwa: USIIJIBU. USIBONYEZE viungo vyovyote. "
            "Ripoti kwa Usalama wa IT. Futa barua pepe mara moja.",
        "recommendation_suspicious":
            "Hatua zinazopendekezwa: Thibitisha mtumaji kupitia njia nyingine. "
            "Usitoe nywila. Wasiliana na Usalama wa IT ukishindwa.",
        "recommendation_legitimate":
            "Barua pepe hii inaonekana salama. Daima kuwa macho na uthibitishe "
            "maombi yasiyotarajiwa kupitia njia rasmi.",
        "legitimacy_note_prefix": "Ishara za uhalisi zilipunguza alama ya hatari: ",
        "composite_note_prefix":  "Mifumo ya mashambulizi iliyounganishwa imegunduliwa: ",
    }
}


class ExplainabilityEngine:

    def explain(self, scoring_result: ScoringResult, language: str = "en") -> Dict[str, Any]:
        lang = language if language in TRANSLATIONS else "en"
        T    = TRANSLATIONS[lang]
        clf  = scoring_result.classification
        score = scoring_result.risk_score
        n     = len(scoring_result.rule_matches)

        # Legitimacy note
        legit_note = ""
        if scoring_result.legitimacy_deduction > 0 and scoring_result.legitimacy_details:
            signals = ", ".join(d["signal"] for d in scoring_result.legitimacy_details[:2])
            legit_note = f"{T['legitimacy_note_prefix']}{signals}. "

        # Composite note
        composite_note = ""
        if scoring_result.composite_details:
            names = ", ".join(d["name"] for d in scoring_result.composite_details[:2])
            composite_note = f"{T['composite_note_prefix']}{names}. "

        narrative_key = f"narrative_{clf}"
        narrative = T[narrative_key].format(
            rule_count=n, score=score,
            legit_note=legit_note,
            composite_note=composite_note,
        )

        # Build rule cards
        rule_cards = []
        for m in sorted(scoring_result.rule_matches,
                        key=lambda x: x.score_contribution, reverse=True):
            rule_cards.append({
                "rule_id":          m.rule_id,
                "name":             m.name,
                "category":         m.category,
                "category_label":   T.get(m.category, m.category),
                "weight":           m.weight,
                "score_contribution": round(m.score_contribution, 3),
                "evidence":         m.evidence,
                "explanation":      m.explanation,
                "severity":         "high" if m.weight >= 2.5 else
                                    "medium" if m.weight >= 1.5 else "low",
            })

        # Category breakdown
        cat_breakdown = [
            {
                "category": cat,
                "label":    T.get(cat, cat),
                "score":    scr,
                "rules":    sum(1 for m in scoring_result.rule_matches if m.category == cat),
            }
            for cat, scr in sorted(
                scoring_result.category_scores.items(),
                key=lambda x: x[1], reverse=True
            )
        ]

        # Confidence label
        conf = scoring_result.confidence
        if conf >= 0.7:
            conf_label = T["confidence_high"]
        elif conf >= 0.4:
            conf_label = T["confidence_medium"]
        else:
            conf_label = T["confidence_low"]

        return {
            "language":            lang,
            "summary":             T[clf],
            "narrative":           narrative,
            "triggered_rules":     rule_cards,
            "composite_patterns":  scoring_result.composite_details,
            "legitimacy_signals":  scoring_result.legitimacy_details,
            "category_breakdown":  cat_breakdown,
            "risk_interpretation": {
                "score":              score,
                "classification":     T[clf],
                "risk_level":         T["risk_high"] if score >= 55
                                      else T["risk_medium"] if score >= 25
                                      else T["risk_low"],
                "confidence":         conf,
                "confidence_label":   conf_label,
                "rules_fired":        n,
                "composite_bonus":    scoring_result.composite_bonus,
                "legitimacy_deduction": scoring_result.legitimacy_deduction,
            },
            "recommendations": T[f"recommendation_{clf}"],
        }
