use surrealdb::RecordId;

pub fn get_record_id_from_string(val: String) -> RecordId {
    let mut id_part = val.trim().splitn(2, ':');
    let table = id_part.next().unwrap();
    let key = id_part.next().unwrap();
    RecordId::from_table_key(table, key)
}
