use chrono::{DateTime, Duration, FixedOffset, Local};

pub fn time_now() -> String {
    let created_at = Local::now() + Duration::hours(1); // add 1 hour
    let created_at: DateTime<FixedOffset> = created_at.with_timezone(&created_at.offset());
    let created_at = created_at.to_rfc3339();
    created_at
}
