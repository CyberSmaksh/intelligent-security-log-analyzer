import sys
sys.path.insert(0, 'siem_project')
import database, loader

database.init_db()
res = loader.reset_and_reload()

print("=== Smoke Test Results ===")
print("Events in file   :", res.total_in_file)
print("Events inserted  :", res.inserted_events)
print("Events skipped   :", res.skipped_events)
print("Events malformed :", res.malformed_events)
print("Alerts inserted  :", res.inserted_alerts)
print("Alerts skipped   :", res.skipped_alerts)
print("Errors           :", res.errors)
print()
print("DB event count   :", database.event_count())
print("DB alert count   :", database.alert_count())
print("Severity counts  :", database.severity_counts())
print()

alerts = database.get_all_alerts()
print("Alerts generated:")
for a in alerts:
    sev = a["severity"]
    rule = a["rule_name"]
    ip = a["source_ip"]
    user = a["user"]
    print("  [" + sev + "] " + rule + " IP=" + ip + " user=" + user)

res2 = loader.load_events_from_file()
assert res2.inserted_events == 0, "Idempotency FAILED: events duplicated!"
assert res2.inserted_alerts == 0, "Idempotency FAILED: alerts duplicated!"
print()
print("Idempotency check PASSED (second load inserted 0 events and 0 alerts).")
print()
print("=== ALL CHECKS PASSED ===")
