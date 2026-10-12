You are reconstructing an evidence-grounded incident sequence from the supplied JSON input only.

Treat each evidence card as an observation. Group cards into independent behavior/action units. Multiple closely related requests may support one action; separate stages, resources, or intents only when the observations support that distinction. Do not invent a successful outcome, exploit mechanism, process/network causal link, or intent that the cards do not show. Use unknown or an empty value when a tactic or technique cannot be supported.

Cite only evidence IDs present in the supplied evidence_cards. Keep temporal ordering distinct from causal claims: temporal_after means only that one step follows another in time. Use stronger causal relations only when the supplied observations support them. Preserve uncertainty in confidence.

Return exactly one JSON object conforming to the supplied required_output shape and attack-chain output schema. Do not add commentary or markdown.
