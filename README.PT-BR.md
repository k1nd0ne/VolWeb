# VolWeb-Documentation-PT-BR
\







# Documentação do VolWeb

Esta wiki descreve o aplicativo VolWeb com o objetivo de:
* Ajudar o administrador de sistemas (sysadmin) a fazer o deploy da plataforma em um ambiente que não seja de produção.
* Ajudar o administrador de sistemas a fazer o deploy da plataforma em um ambiente de produção.
* Auxiliar um investigador ou desenvolvedor na implantação de uma versão local da plataforma.

Esta documentação evoluirá com as necessidades e contribuições da comunidade.

---

## 🛠 Tutorial - Deploy Padrão em um Ambiente de Não-Produção

Neste tutorial, o leitor aprenderá, passo a passo, como a plataforma VolWeb pode ser implantada em um ambiente de não-produção.

Para fazer o deploy do VolWeb no seu laboratório, você precisa entender seus diferentes componentes. A imagem abaixo fornece uma visão ampla das tecnologias e protocolos envolvidos.

![Diagrama de Arquitetura do VolWeb](https://i.postimg.cc/pdDDhQzT/Copilot-20260319-214520-(1).png)

### Requisitos
Primeiro, você precisará dos seguintes requisitos:
* Ferramenta Docker & docker-compose: https://docs.docker.com/compose/install/
* A versão (release) mais recente do VolWeb: https://github.com/k1nd0ne/VolWeb/releases

### Preparando o Seu Ambiente
Para implantar o volweb no seu ambiente de teste, o arquivo `docker-compose.yaml` na raiz do projeto lhe dá um bom ponto de partida. Copie o arquivo `.env.example` para `.env`. Se você for acessar a instância do volweb via localhost, não precisa alterar nada. Mas, se for acessar de fora, edite a variável de ambiente `CSRF_TRUSTED_ORIGINS` e substitua-a pelo IP/FQDN da máquina host que será acessada pelos clientes.

Uma vez feito isso, você está pronto! Basta executar `docker-compose up`.

### Primeira inicialização:
Navegue até `http://localhost:3000`

Por padrão, as contas de administrador e de usuário criadas terão as seguintes credenciais:
* `admin:password`
* `user:password`

Você pode criar mais contas de analistas e alterar as senhas através do painel de administração do Django -> `https://[IP DO HOST DO VOLWEB]/admin/` ou clicando no nome de usuário no canto superior direito em "Administration", utilizando a conta de admin acima para modificá-las.

---

## 🛠 Tutorial - Deploy Padrão em um Ambiente de Produção

### Requisitos
Primeiro, você precisará dos seguintes requisitos:
* Ferramenta Docker & docker-compose: https://docs.docker.com/compose/install/
* A versão (release) mais recente do VolWeb: https://github.com/k1nd0ne/VolWeb/releases

Para fazer o deploy do VolWeb em um ambiente de produção, você precisará de certificados X509:
Aqui está um exemplo de como gerar um certificado autoassinado (self-signed) para o VolWeb:

```bash
openssl genrsa > ./privkey.pem
openssl req -new -x509 -key ./privkey.pem > ./fullchain.pem
Cuidado
Defina o endereço FQDN/IP da instância do VolWeb ao assinar seus certificados. Se você optar por usar o MINIO em um servidor diferente, certifique-se de assinar o certificado MinIO para o FQDN/IP deste servidor e altere o arquivo .env de acordo. Certifique-se de que os arquivos privkey e fullchain tenham, respectivamente, os mesmos nomes do exemplo acima.

Copie os certificados para ./VolWeb/nginx/ssl/privkey.pem e ./VolWeb/nginx/ssl/fullchain.pem

Cuidado
Se você estiver criando certificados autoassinados, certifique-se de que eles sejam confiáveis no seu navegador. É recomendado gerar certificados usando uma Autoridade Certificadora (CA) confiável.

Preparando o Seu Ambiente
Para implantar o volweb no seu ambiente de produção, o arquivo docker-compose-prod.yaml na raiz do projeto lhe dá um bom ponto de partida com um serviço nginx usado para o fluxo TLS.

Copie o arquivo .env.example para .env. Edite a variável de ambiente CSRF_TRUSTED_ORIGINS e substitua por https://IP_ou_FQDN da máquina host que será acessada pelos clientes.

Uma vez feito isso, você está pronto! Basta executar docker-compose -f docker-compose-prod.yaml up.

Se você estiver usando um FQDN para a plataforma VolWeb, certifique-se de editar o arquivo de configuração do nginx em VolWeb/docker/nginx/nginx.conf

Primeira inicialização:
Navegue até https://fqdn-ou-ip-do-volweb/

Cuidado
Se você estiver usando certificados autoassinados sem adicioná-los à CA confiável do seu navegador, navegue até https://fqdn-ou-ip-do-volweb:9000 para aceitar os riscos, ou então você não conseguirá fazer o upload de evidências no VolWeb.

Por padrão, as contas de administrador e de usuário criadas terão as seguintes credenciais:

admin:password

user:password

Você pode criar mais contas de analistas e alterar as senhas através do painel de administração do Django -> https://[IP DO HOST DO VOLWEB]/admin/ e usar a conta de admin acima para modificá-las.

🛠 Tutorial - Vinculando evidências no VolWeb localizadas em uma solução de armazenamento em nuvem S3 (MINIO/AWS)
Neste tutorial, o leitor aprenderá, passo a passo, como a plataforma VolWeb pode ser implantada em produção usando a AWS em vez do MINIO como solução de armazenamento.

Primeiro, você precisará dos seguintes requisitos:

Uma conta na AWS ou MINIO com a possibilidade de criar buckets, um ID de cliente e uma KEY da AWS.

O uso da AWS com a plataforma VolWeb possui alguns requisitos. Após criar um caso na interface de usuário (UI) do VolWeb, você pode fazer o upload de qualquer imagem de memória via VolWeb-Scripts sem problemas. No entanto, se você quiser ser capaz de vincular imagens de memória da plataforma VolWeb, precisará autorizar o CORS para o ID do bucket vinculado à sua evidência.

Para isso, navegue até as autorizações do seu bucket AWS ou MINIO via navegador da web e adicione a seguinte política CORS:

JSON
[
  {
    "AllowedHeaders": [ "*" ],
    "AllowedMethods": [ "GET", "PUT", "POST", "DELETE", "HEAD" ],
    "AllowedOrigins": [ "*" ],
    "ExposeHeaders": [
      "x-amz-server-side-encryption",
      "x-amz-request-id",
      "x-amz-id-2",
      "ETag"
    ],
    "MaxAgeSeconds": 3000
  }
]
Isso permitirá que a plataforma VolWeb vincule as evidências que estão localizadas em seus buckets.

🛠 Tutorial - Deploy do VolWeb com Kubernetes
Criamos um arquivo de manifesto de kubernetes de exemplo para fazer uma implantação rápida.

Para fazer isso, edite o arquivo .env com a configuração do seu contexto e execute as seguintes ações:

Bash
# Crie o secret para os seus certificados TLS
kubectl -n volweb create secret tls volweb-tls --cert=fullchain.pem --key=privkey.pem

# Crie os secrets do volweb para o env
kubectl -n volweb create secret generic volweb-secrets --from-env-file=.env

# Inicie
kubectl -n volweb apply -f volweb.yaml
Sinta-se à vontade para ajustar o manifesto se quiser configurações específicas.

🛠 Tutorial - Deploy do VolWeb em um Computador Local ou Contribuindo
Para contribuir:

Faça uma proposição primeiro abrindo uma discussão (discussion).

Configurar o Seu Ambiente de Desenvolvimento
Para configurar o ambiente de desenvolvimento, siga estes passos:

Configurar o Ambiente de Desenvolvimento Docker

Bash
cd VolWeb/
docker-compose -f docker-compose-dev.yaml up
Configurar o Seu Ambiente Python3
Em um novo terminal, configure um ambiente virtual Python3 (virtual env) e instale as dependências:

Bash
cd VolWeb/backend
python3 -m venv ./venv
source ./env.dev
source ./venv/bin/activate
pip3 install -r requirements.txt
Em seguida, aplique todas as migrações (migrations), inicialize as contas padrão e inicie o servidor web:

Bash
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py initadmin
python3 manage.py runserver 8000
Iniciar o Celery
Em um novo terminal, você precisará iniciar um worker do celery para que as tarefas de análise possam ser executadas. (Certifique-se de ativar também o venv).

Bash
cd VolWeb/backend
source ./venv/bin/activate
source .env.dev
celery -A backend worker --loglevel=INFO
Configurar o frontend
Você precisa instalar o nodejs com npm primeiro.
Em um novo terminal, você precisará instalar o frontend:

Bash
cd VolWeb/frontend
npm install
npm run dev
Assim que a sua funcionalidade tiver sido desenvolvida, atualize as configurações para produção e teste o seu código com o docker-compose.yaml de produção. O VolWeb está em desenvolvimento ativo; suas funcionalidades podem levar algum tempo para serem integradas, dependendo do roadmap.

Documentação da API
O swagger está disponível em http://IP_ou_FQDN/swagger/

Sinta-se à vontade para desenvolver seus próprios scripts e compartilhá-los aqui: https://github.com/forensicxlab/VolWeb-Scripts

Usando o VolWeb: Guia de Melhores Práticas
As seções a seguir o ajudarão a usar o VolWeb e a otimizar o desempenho da plataforma VolWeb.

Dica 1: Escolhendo o Formato Correto da Imagem de Memória
Antes de fazer o upload da sua imagem de memória para a plataforma VolWeb, é recomendado usar um formato bruto (raw) a fim de realizar menos operações de tradução.
Exemplo: Considere converter uma imagem vmem e o vmss associado para uma imagem raw, e depois faça o upload do resultado para a plataforma VolWeb.

Dica 2: Verifique os Resultados da Análise
Quando uma análise é concluída, você pode verificar os resultados produzidos por cada plugin. Abaixo está o significado de cada status:

"Success": O plugin produziu um resultado.

"Unsatisfied requirement": Geralmente há um requisito de símbolo (symbol) ausente. Considere importar o ISF correto.

Dica 3: Não Pare de Usar a CLI do Volatility3
O VolWeb não tem a intenção de substituir a CLI do Volatility3; de fato, alguns plugins estão faltando e serão integrados assim que encontrarmos o método de visualização adequado para eles. A CLI do Volatility3 v2.5.2 fornece a capacidade de realizar suas análises no bucket remoto do Min.IO contendo sua evidência. Veja como você ainda pode usar a CLI do Volatility3 com a plataforma VolWeb:

Bash
~» export AWS_ENDPOINT_URL="https://seu-minio/instancia-volweb:9000"
~» export AWS_ACCESS_KEY_ID=REDACTED
~» export AWS_SECRET_ACCESS_KEY=REDACTED
~» vol -f bucketID/Nome_Da_Evidencia.raw windows.pstree
Nota
Você pode recuperar a localização da evidência acessando a instância do MinIO ou obtendo os metadados da evidência através da API REST exposta do VolWeb. Mais informações sobre a interação com a API REST e exemplos de scripts aqui: https://github.com/forensicxlab/VolWeb-Scripts

Dica 4: Peça Ajuda!
Se você precisar de suporte para fazer o deploy do VolWeb em seu laboratório, use as discussões (discussions) para pedir ajuda, propor novos recursos, ... : https://github.com/k1nd0ne/VolWeb/discussions

Dica 5: Use o painel de administração
Se você for o administrador do VolWeb, use o painel de administração localizado em https://volweb-uri/admin/. Você poderá criar, modificar e excluir usuários. Você também poderá esvaziar (flush) as evidências se necessário. Algumas evidências podem travar devido a um bug não identificado, e você pode excluí-las pelo painel de administração (elas serão excluídas automaticamente do bucket S3 também).
