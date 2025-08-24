use chrono::{DateTime, Duration, Local, SecondsFormat, Utc};

pub fn time_now() -> String {
    let created_at = Local::now();
    let created_at_utc: DateTime<Utc> = created_at.with_timezone(&Utc);
    created_at_utc.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn time_now_plus_one_hour() -> String {
    let created_at = Local::now() + Duration::hours(1); // add 1 hour
    let created_at_utc: DateTime<Utc> = created_at.with_timezone(&Utc);
    created_at_utc.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn time_now_plus_three_days() -> String {
    let created_at = Local::now() + Duration::days(3);
    let created_at_utc: DateTime<Utc> = created_at.with_timezone(&Utc);
    created_at_utc.to_rfc3339_opts(SecondsFormat::Millis, true)
}
