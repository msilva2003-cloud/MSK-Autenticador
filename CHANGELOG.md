# Histórico de versões

## 0.1.8 — criação de senha e visual do módulo

- Corrige a derivação da senha com o modo HMAC exigido pelo PBKDF2 do Windows.
- Tela de senha refeita com a paleta escura e os botões do MSK Autenticador.
- Mensagens de validação exibidas na própria tela, sem janela de erro separada.

## 0.1.7 — ajuste da tela de senha

- Mais espaço para os campos e botões da tela de senha, com dimensões adaptadas à escala do Windows.
- Centralização da janela de senha na área de trabalho.

## 0.1.6 — senha de acesso e atualização pela aba Sobre

- O módulo solicita a criação de uma senha no primeiro uso e exige a senha para abrir nas próximas vezes.
- A aba **Sobre** permite verificar e instalar uma atualização validada.

## 0.1.5 — colar QR da área de transferência

- Importação de imagem copiada pelo menu **Adicionar QR** ou pelo atalho **Ctrl+V**.
- A imagem é lida em memória, sem criar uma cópia em disco.

## 0.1.4 — janela estreita, câmera, exportação e atualização

- Largura inicial reduzida de 960 para 480 pontos lógicos, com cartões reorganizados.
- Importação de QR pela câmera do computador.
- Exportação individual de conta TOTP como QR para Google Authenticator, somente na tela.
- Verificação automática de releases estáveis no GitHub, conferência de SHA-256 e instalação silenciosa na edição instalada.
- Inclusão da licença do libzint, usado para gerar QRs.

## 0.1.3 — pacote inicial para GitHub

- Aplicativo nativo para Windows x64 com cofre local protegido por DPAPI.
- Importação de QR TOTP e geração de códigos de 6 ou 8 dígitos.
- Interface compacta com renomeação, exclusão e ordenação das contas por arraste.
- Cópia do código por duplo clique, aviso temporário e limpeza condicional da área de transferência após 30 segundos.
- Ícone próprio incorporado ao executável.
- Instalador por usuário criado com Inno Setup 7, com atalhos e desinstalação que preserva o cofre local.

O executável não possui assinatura digital e esta versão ainda não passou por revisão de segurança independente nem ensaio em computadores limpos.
