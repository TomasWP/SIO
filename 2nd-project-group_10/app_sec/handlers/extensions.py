def interpretacoes(variaveis):
    if not variaveis:
        return [[]]
    
    resto_combinacoes = interpretacoes(variaveis[1:])
    
    return [[(variaveis[0], True)] + combinacao for combinacao in resto_combinacoes] + [[(variaveis[0], False)] + combinacao for combinacao in resto_combinacoes]

# Exemplo de uso
variaveis_proposicionais = ["a", "b"]
resultado = interpretacoes(variaveis_proposicionais)
print(resultado)
