function init (args)
  local needs = {}
  return needs
end

-- Função para dropar pacotes de acordo com a provabilidade
-- Se retorna 1, dropa
-- Se 0, não dropa
function match(args)
	if math.random() < 1.00 then
    return 1
  end
  return 0
end
