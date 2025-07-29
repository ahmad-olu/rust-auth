pub fn to_slug(val: &str) -> String {
    val.to_lowercase()
        .replace(|c: char| !c.is_alphanumeric() && c != ' ', "")
        .replace(" ", "-")
}
