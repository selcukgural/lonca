def first_error(lines)
  case lines
  in [*, /error/ => line, *]
    line
  else
    nil
  end
end
