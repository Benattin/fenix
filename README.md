# Fenix

IA pessoal local do [Gustavo Benatti](https://github.com/Benattin). Roda só na máquina: voz, memória, cofre de arquivos, agenda, e-mail e notícias. O cérebro é o [Ollama](https://ollama.com) — sem API na nuvem.

Portfólio: https://benattin.github.io/

## O que entra no GitHub

Código e arte da FACE. **Não** sobe `data/` (memória, senhas de app, cofre).

| Arquivo | Função |
|---|---|
| `fenix.html` | FACE — chat, voz, cofre, agenda |
| `server.js` | Antena local na porta 4250 |
| `Fenix.bat` | Mata a porta, sobe o Node, abre o Edge em app |
| `fenix-launch.vbs` | Espera o servidor e abre `http://127.0.0.1:4250/?app=1` |
| `fenix-realm.png` / `fenix-knight.png` / `fenix-icon.png` | Fundo, figura e ícone |

## Requisitos

- Windows, Node.js 18+
- [Ollama](https://ollama.com) em `127.0.0.1:11434`

```bat
ollama pull llama3.2:3b
ollama pull moondream
ollama pull qwen2.5-coder:3b
```

`llama3.2` conversa, `moondream` lê imagem, o coder só entra em pedido de código.

## Uso

```bat
Fenix.bat
```

Ou `npm start` e abrir `http://127.0.0.1:4250/?app=1`.

Na engrenagem: iCal secreto da agenda e senha de app do Gmail (não a senha da conta). Os valores ficam em `data/config.json`, fora do Git.

## Análise de arquivo

Cofre → soltar o arquivo → **ANALISAR**, ou *analisa o arquivo foto.png*. Sem arquivo no cofre ela não inventa o conteúdo.
