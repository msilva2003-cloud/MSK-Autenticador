# MSK Autenticador para Windows

<img src="assets/logo.png" alt="Logo do MSK Autenticador" width="96">

Aplicativo nativo em C++20 para Windows 10/11. Lê QRs TOTP de imagens ou pela câmera, calcula códigos com CNG/Bcrypt e guarda as contas em um cofre DPAPI do usuário atual. O módulo exige uma senha própria para abrir e permite verificar atualizações na aba **Sobre**; não envia chaves ou códigos.

## Baixar

Baixe o instalador `MSK-Autenticador-Setup-...exe` ou o ZIP portátil da versão desejada na página **Releases** deste repositório e confira o SHA-256 publicado junto ao arquivo. O instalador cria atalhos e permite desinstalação. Para usar o ZIP, extraia-o para uma pasta local e abra `MSKAuthenticator.exe`. O executável e o instalador ainda não possuem assinatura digital; o Windows pode exibir um aviso de publicador desconhecido.

## Usar

No primeiro uso, crie e confirme uma senha com pelo menos 8 caracteres. O módulo pedirá essa senha toda vez que for aberto. Em seguida, clique em **Mostrar códigos** para visualizar os códigos. Dê dois cliques sobre um código visível para copiá-lo sem espaços. O aviso **Copiado** desaparece após dois segundos; a cópia será removida da área de transferência após 30 segundos, se ainda estiver lá. Os códigos continuam visíveis ao alternar para outra janela e são ocultados após cinco minutos sem interação ou ao clicar em **Ocultar códigos**. Arraste um cartão pela área de texto para mudar sua posição; a nova ordem é salva no cofre. Use **Renomear** para alterar o título exibido de uma conta e **Excluir** para removê-la do cofre após confirmação. Em **Adicionar QR**, escolha uma imagem PNG, JPG, BMP, GIF ou TIFF, abra a câmera ou selecione **Colar imagem do QR**. Também é possível copiar uma captura do QR, ativar a janela do aplicativo e pressionar **Ctrl+V**. A imagem colada é lida da área de transferência sem ser salva pelo aplicativo. Se o Google Authenticator dividir a exportação em vários QRs, importe cada imagem separadamente.

Use **Exportar** no cartão de uma conta para mostrar um QR `otpauth://` que o Google Authenticator pode ler. A exportação é individual e não grava imagem em disco. O QR contém a chave secreta: feche a janela após importá-lo e evite capturas de tela. Contas com período diferente de 30 segundos não podem ser exportadas nesse formato.

O módulo consulta o release estável mais recente no GitHub em toda abertura, após a entrada com senha. Quando há uma versão nova, o menu **Sobre** alterna entre vermelho e branco a cada segundo. Também é possível consultar novamente em **Sobre → Verificar atualizações**. Ao encontrar uma versão maior, o aplicativo baixa o instalador e o arquivo SHA-256 do mesmo release, confere o arquivo e pede confirmação antes de instalar. A edição portátil não instala atualizações pelo aplicativo. O cofre permanece em `%LOCALAPPDATA%\MSKAuthenticator\vault.dpapi`; a senha do módulo é armazenada separadamente, protegida pelo DPAPI do usuário Windows. A senha controla o acesso pela interface do módulo; o cofre continua protegido pelo DPAPI da conta Windows. A versão 0.1.9 e seu instalador ainda não têm assinatura digital; a atualização depende da integridade da conta e do release no GitHub.

O cofre fica em `%LOCALAPPDATA%\MSKAuthenticator\vault.dpapi`. A imagem do QR continua no local de origem; remova essa cópia quando não precisar dela. Não coloque QRs ou backups sem criptografia em pastas sincronizadas ou no repositório.

Em outro computador, abra o executável e importe os QRs novamente. O arquivo DPAPI do cofre não é um backup portátil e normalmente só pode ser aberto pela mesma conta Windows no mesmo computador. Não há sincronização entre computadores.

## Segurança e limites

- O aplicativo não transmite chaves nem códigos para a internet. Para atualizar, consulta a API e os arquivos de release do GitHub, que recebem a conexão de rede do seu computador. Não registra códigos em logs. A área de transferência só recebe um código quando você dá dois cliques nele; outros aplicativos da sua sessão Windows podem ler o código enquanto ele estiver copiado.
- O cofre é cifrado pelo DPAPI do usuário Windows. As chaves são carregadas ao mostrar os códigos e os buffers de chaves controlados pelo aplicativo são limpos ao ocultá-los. Bibliotecas e o próprio Windows podem criar cópias temporárias fora do controle do aplicativo.
- Um malware executado na sessão desbloqueada do mesmo usuário, uma captura de tela ou alguém diante do monitor podem obter os códigos. Bloqueie o Windows quando se afastar. DPAPI não resolve esse cenário sozinho.
- O executável e o instalador ainda não têm assinatura de código. Antes de distribuir amplamente, são recomendados revisão de segurança independente, assinatura e ensaio em máquinas limpas.
- Esta versão nativa não preenche códigos automaticamente no navegador.

Não abra issues com capturas de QR, chaves, códigos TOTP ou arquivos de cofre. Para relatar uma possível falha de segurança, use uma mensagem privada ao mantenedor.

## Compilar

Com Visual Studio 2022 Build Tools e CMake, execute:

    cmake -S . -B build -G "Visual Studio 17 2022" -A x64
    cmake --build build --config Release --target MSKAuthenticator

O CMake obtém ZXing-C++ v3.1.1 na configuração inicial. O arquivo final é build/Release/MSKAuthenticator.exe.
O ícone da aplicação está em assets/app.ico e é incorporado ao executável como recurso Windows.

Para gerar o instalador, instale [Inno Setup 7](https://jrsoftware.org/isdl.php) e execute `ISCC.exe installer.iss` depois da compilação C++. O script instala o aplicativo apenas para o usuário atual e preserva o cofre `%LOCALAPPDATA%\MSKAuthenticator\vault.dpapi` na desinstalação. Para uso comercial do compilador, consulte os [termos do Inno Setup](https://jrsoftware.org/isorder.php).
