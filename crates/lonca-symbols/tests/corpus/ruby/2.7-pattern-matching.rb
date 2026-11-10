def describe(value)
  case value
  in Integer => n if n > 10
    "large"
  in [first, *rest]
    "list of #{rest.size + 1}"
  in {name: String => name, age: 18..}
    name
  else
    "other"
  end
end
