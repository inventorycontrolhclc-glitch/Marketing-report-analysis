CREATE TABLE IF NOT EXISTS zetpy_weekly_report (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  date_from TEXT NOT NULL,
  date_to TEXT NOT NULL CHECK (date_to >= date_from),
  scheduled_at INTEGER NOT NULL,
  refreshed_at TEXT NOT NULL,
  order_count INTEGER NOT NULL CHECK (order_count >= 0),
  unit_count INTEGER NOT NULL CHECK (unit_count >= 0),
  report_json TEXT NOT NULL CHECK (json_valid(report_json))
);
