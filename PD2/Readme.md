# Relatório do Projecto de Desenvolvimento II (ES)

## Autores 
* Ivo Miguel Alves Ribeiro Pg53886
* Henrique Ribeiro Fernandes A95323
* Paulo Henrique Pianissola de Cerqueira PG52699

## Introdução

A empresa que contratou o serviço de compartilhamento de mensagens (PD1) expressou grande entusiasmo com o produto, a ponto de compartilhar essa experiência com a empresa mãe. Como resultado, o departamento de suporte informático recebeu a incumbência de adquirir um produto semelhante, porém com um escopo expandido para todas as empresas do grupo, e adaptado aos requisitos do novo contexto.

**Descrição do Projeto:**

O projeto em questão visa desenvolver um serviço de gestão de mensagens, expandindo a funcionalidade proposta no projeto anterior (PD1) para atender às necessidades de todas as empresas do grupo. O departamento de suporte informático enfatiza aspectos-chave:

* Robustez e Segurança: Prioriza-se a qualidade sobre a quantidade de funcionalidades, garantindo que o serviço oferecido seja robusto e seguro.
A documentação do processo de desenvolvimento, especialmente na análise de riscos e avaliação da segurança, é privilegiada para garantir a integridade do produto.

* Resolução de Problemas: Todos os problemas identificados na versão anterior do produto (PD1), incluindo questões funcionais e de segurança, serão devidamente tratados, com documentação detalhada do processo.

**Novos Requisitos Tecnológicos:**

* Arquitetura de Micro-serviços: Em vez da arquitetura cliente/servidor, o projeto adotará uma abordagem baseada em micro-serviços, onde os diferentes comandos serão transformados em métodos de uma API responsável pelo serviço de gestão de mensagens. Foi utilizada a framework Flask.

* Criptografia Utilizando JSON: funcionalidade criptográfica do serviço adotará o formato JSON, utilizando o padrão JavaScript Object Signing and Encryption (JOSE).

* Autenticação de Usuários: A solução de autenticação baseada em TLS será submetida a um escrutínio particular para explicitar as suposições e garantias associadas.
Como alternativa foi desenvilcida a autenticação baseada em JSON Web Tokens (JWT).

## Justificação das *frameworks* escolhidas

A escolha do Python com Flask e JWT (JSON Web Tokens) para o desenvolvimento deste sistema de mensagens pode ser justificada por várias razões:

* Facilidade de Desenvolvimento: Python com Flask oferece uma sintaxe simples e direta, permitindo o desenvolvimento rápido e eficiente do sistema de mensagens.
* A adoção de JWT para autenticação e autorização proporciona um método seguro e eficaz de proteger as rotas da API. Com JWT, os tokens são assinados digitalmente e podem incluir dados adicionais sobre o usuário, tornando-os uma opção amplamente utilizada para sistemas de autenticação stateless.
* Flask, apesar de ser ideal para projetos de menor e médio porte, demonstra escalabilidade para suportar aplicações mais robustas.

Em resumo, a escolha de Flask e JWT para o desenvolvimento deste sistema de mensagens oferece uma combinação de facilidade de uso, rapidez de desenvolvimento, segurança e flexibilidade, tornando-os uma escolha sólida para vários projetos de software.

## Análise de Risco

Para garantir a robustez e a segurança do sistema de mensagens, é essencial realizar uma análise abrangente de riscos. Esta análise identifica potenciais vulnerabilidades e ameaças, além de estabelecer estratégias de mitigação para proteger o sistema. É crucial considerar fatores que possam afetar a integridade, confidencialidade e disponibilidade das informações trocadas entre os usuários, bem como as informações armazenadas no sistema.

A análise de riscos envolve a identificação de ativos críticos, ameaças potenciais e vulnerabilidades, avaliando o impacto e a probabilidade de ocorrência de cada risco. No contexto do novo sistema de mensagens, os ativos principais incluem dados de usuários, mensagens trocadas, componentes do sistema e infraestrutura de TI.

### Principais Vulnerabilidades, Ameaças e Estratégias de Mitigação

* **Autenticação e Autorização:** Para fortalecer a autenticação e autorização em nosso sistema, implementamos o uso de JWT (JSON Web Tokens) em conjunto com assinaturas digitais e certificados digitais. O JWT proporciona uma maneira segura e eficiente de autenticar usuários e autorizar acesso a recursos protegidos, enquanto as assinaturas digitais garantem a integridade e autenticidade dos tokens JWT. Além disso, a utilização de certificados digitais reforça a segurança do processo de autenticação, garantindo a identidade dos usuários e a confiabilidade das transações realizadas no sistema. Essas medidas combinadas fornecem uma camada adicional de proteção, garantindo a segurança e a confiança do nosso ambiente de autenticação e autorização.
* **Transmissão de Dados:** Implementamos medidas para assegurar a transmissão segura de dados em nosso sistema. Reconhecendo os riscos associados à falta de criptografia durante a transmissão, implementamos uma solução de criptografia ponta a ponta. Isso garante que todas as informações sensíveis sejam protegidas durante o trânsito, prevenindo assim possíveis ataques de Man-In-The-Middle ou replay attacks. Ao adotar essa abordagem, garantimos que apenas destinatários autorizados possam decifrar as mensagens, proporcionando um ambiente seguro e confiável para nossos usuários.
* **Execução de Código e Integração de Serviços:** Bugs de software, vulnerabilidades em bibliotecas de terceiros ou falhas na configuração de serviços podem ser explorados, levando à execução remota de código, ataques de injeção ou exploração de vulnerabilidades de *software*. Para evitar tais ataques, as bibliotecas e softwares utilizados devem estar sempre atualizados nas versões mais estáveis, devem ser realizados processos de auditoria de segurança do código/*benchmarking* e limitar as permissões de acordo com o princípio de menor privilégio.
* **Disponibilidade do Sistema:** Garantir a disponibilidade de um sistema é essencial para manter a continuidade dos serviços. Isso pode ser alcançado através da implementação de firewalls e proteções de rede para defender contra ataques externos, da replicação de dados e redundância para garantir a operação contínua em caso de falhas, da implementação de políticas de backup e restauração de dados para rápida recuperação em caso de perda de dados, e da utilização de recursos de escalabilidade automática para adaptar dinamicamente os recursos conforme a demanda do usuário, garantindo assim uma disponibilidade contínua e confiável do sistema.

## Arquitetura da Solução

O projeto desenvolvido para o PD1 era um serviço cliente-servidor, porém, no PD2, foi solicitada a implementação de um serviço baseado em micro-serviços. Optou-se por utilizar a estrutura existente do código do PD1, que já estava razoavelmente modularizada, evitando assim uma reestruturação extensa.

## API

A nova API implementada em Flask contém todas as funcionalidades do servidor original do PD1. A transição para Flask mantém a integridade das operações, garantindo a mesma eficiência e resultados. Essa implementação assegura a continuidade dos serviços, agora com a flexibilidade e simplicidade proporcionadas pelo Flask.
A nova API possui quatro rotas principais. A rota /register permite registrar ou fazer login, retornando um JWT criptografado com JWE. As outras três rotas estão protegidas e requerem o JWT para acesso. A rota /message permite enviar e receber mensagens. A rota /queue fornece uma lista de mensagens contendo apenas o número da mensagem e o assunto. Por fim, a rota /keys permite buscar as chaves públicas dos outros utilizadores.

## Lado do Cliente

A aplicação cliente mantém todas as funcionalidades do servidor PD1, agora fazendo requisições à nova API. A integração assegura a mesma eficiência e experiência do utilizador. Todas as operações essenciais continuam disponíveis e funcionais.


## Segurança do Sistema

No projeto apresentado,  a segurança é abordada em várias frentes para garantir a integridade e a confidencialidade dos dados.

* **Autenticação JWT:** O sistema utiliza tokens JWT para autenticar utilizadores, gerando o token durante o login/register. Este token é necessário para acessar rotas protegidas, e o *auth* garante que apenas solicitações com tokens válidos possam acessar essas rotas.
* **Uso de certificados digitais:** Certificados digitais são utilizados para estabelecer comunicações seguras entre os serviços e os utilizadores. Eles garantem a autenticidade dos serviços, proporcionando uma camada adicional de segurança.
* **Gestão de Chaves:** O sistema utiliza chaves assimétricas para criptografia e assinatura digital. As chaves privadas são mantidas em segredo e acessíveis apenas ao proprietário, enquanto as chaves públicas são compartilháveis. A gestão correta dessas chaves é essencial para a segurança do sistema, com as chaves privadas sendo protegidas contra acesso não autorizado.
* **Assinaturas Digitais:**As mensagens são assinadas digitalmente pelo remetente usando sua chave privada, permitindo que os destinatários verifiquem a autenticidade e integridade das mensagens.
* **Criptografia de Mensagens:** As mensagens são cifradas com AES-GCM (Advanced Encryption Standard-Galois/Counter Mode) antes de serem armazenadas ou enviadas. Isso assegura a confidencialidade das mensagens, impedindo que terceiros não autorizados leiam seu conteúdo.
* **Arquitetura Micro-serviços:** A segurança nesta arquitetura envolve o uso de HTTPS e autenticação de serviços para proteger comunicações, implementar mecanismos robustos de autenticação e autorização, adotar sistemas centralizados de gestão de identidades e credenciais, monitorar continuamente o tráfego de rede e logs de atividades, além de medidas proativas para detectar e responder a ameaças.


## Conclusão

O projeto desenvolvido provou ser uma excelente aplicação dos conhecimentos teóricos e práticos adquiridos no curso. A criação de um serviço de mensagens seguro, utilizando um sistema Cliente/Servidor, permitiu garantir autenticidade, integridade e confidencialidade nas comunicações entre membros de uma organização. A implementação destacou-se pela utilização dos algoritmos de criptografia RSA e AES em configuração híbrida, além da incorporação das práticas recomendadas de segurança, incluindo a verificação de assinaturas e a validação contra injeções de JSON. Adicionalmente, a autenticação com JWT garantiu que apenas utilizadores autenticados pudessem acessar rotas protegidas, reforçando a segurança do sistema.