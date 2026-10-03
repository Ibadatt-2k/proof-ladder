"""Demo helper: play the analyst. Correct the first wrong verdict of each known blind spot.

This is what a human would do in the dashboard; scripted so the demo is reproducible.
"""
from sqlalchemy import select

from app.db import Alert, Investigation, SessionLocal
from app.pipeline import correct, rebuild_memory

NOTES = {
    "corporate_vpn_egress": "Zscaler corporate VPN egress, not real travel. Known device and MFA passed.",
    "newsletter_young_tracker": "Established newsletter sender; new click-tracking domain is their ESP, not phishing.",
}

if __name__ == "__main__":
    with SessionLocal() as db:
        rebuild_memory(db)
        for scenario, note in NOTES.items():
            inv = db.execute(select(Investigation).join(Alert).where(Alert.scenario == scenario, Investigation.outcome == "disagree",
                                                                     Investigation.corrected.is_(False)).order_by(Investigation.id)).scalars().first()
            if inv:
                c = correct(db, inv.id, inv.alert.human_verdict, note)
                print(f"corrected investigation {inv.id} ({scenario}) -> {c.corrected_verdict}")
        db.commit()
