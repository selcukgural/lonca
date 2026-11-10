def same?(value, limit)
  case value
  in ^(limit + 1)
    true
  else
    false
  end
end
