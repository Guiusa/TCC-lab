
function init (args)
    local needs = {} 
    return needs
end

function match(args)
    if math.random() < 0.25 then
        return 1
    end
    return 0
end

