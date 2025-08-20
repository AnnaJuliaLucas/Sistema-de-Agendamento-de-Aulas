<p align="center">
  <a href="https://www.ufjf.br" rel="noopener" target="_blank">
    <img width="261" height="148" src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/71/Logo_da_UFJF.png/640px-Logo_da_UFJF.png" alt="Logo UFJF" />
  </a>
</p>

<div align="center">
  
  <h1 align="center">Sistema de Agendamento de Aulas</h1>
  
  <!-- Vídeo demonstração -->
  <a href="https://youtu.be/8Q2AN6Bb1D8" target="_blank">
    <img alt="Vídeo YouTube" src="https://img.shields.io/badge/YouTube-Demonstra%C3%A7%C3%A3o-FF0000?logo=youtube&logoColor=white">
  </a>
  
</div>




O **Sistema de Agendamento de Aulas** é um projeto acadêmico desenvolvido para a disciplina **Redes de Computadores - DCC042** da UFJF.  Ele simula uma plataforma de agendamento de aulas entre **alunos** e **tutores**, aplicando conceitos de:

- Comunicação via **sockets TCP**
- Autenticação com **JWT**
- Criptografia híbrida **(RSA + Fernet)**
- Segurança de senha com **bcrypt**



## 🏗️ Arquitetura

O sistema é organizado em **cliente** e **servidor**, comunicando-se via TCP sockets:

- **Servidor:** gerencia usuários, agenda de tutores, autenticação e criptografia  
- **Cliente:** interface de interação do aluno ou tutor, realiza requisições e exibe dados  
- **Banco de Dados:** SQLite local, armazena usuários, agendas e sessões  



## ⚙️ Funcionalidades

### 👩‍🎓 Aluno
- Cadastro com dados pessoais e senha criptografada  
- Login seguro com JWT  
- Visualização de tutores disponíveis  
- Agendamento, consulta, edição ou cancelamento de aulas  

### 👨‍🏫 Tutor
- Cadastro com especialidade, disciplina e horários disponíveis  
- Login seguro com JWT  
- Gerenciamento da própria agenda  

### 🛡️ Admin (opcional)
- Cadastro institucional e vinculação de tutores  
- Visão geral da operação  


## 🔐 Camada de Segurança

- Senhas armazenadas com **bcrypt**  
- Mensagens entre cliente e servidor criptografadas com **Fernet + RSA**  
- Autenticação via **tokens JWT** com tempo de expiração  


## 🚀 Como Executar

### Pré-requisitos
```bash
pip install bcrypt pyjwt cryptography pycryptodome
```

### Execução
1. **(Terminal 1): Inicie o servidor**
```bash
python server.py
```

2. **(Terminal 2): Inicie o cliente**
```bash
python client.py
```

> Certifique-se de que a porta `4444` esteja liberada. Em sistemas Linux, use o comando para "matar" a porta:
```bash
fuser -k 4444/tcp
```

### Teste Automatizado
```bash
python test_sistema_completo.py
```




