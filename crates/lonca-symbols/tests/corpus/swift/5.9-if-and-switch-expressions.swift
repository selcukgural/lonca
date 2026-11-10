func label(_ code: Int) -> String {
    let kind = if code < 300 { "ok" } else { "error" }
    let detail = switch code {
    case 404: "missing"
    default: kind
    }
    return detail
}
