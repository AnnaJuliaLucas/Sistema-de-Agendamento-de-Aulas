# Sistema de Agendamento de Aulas Particulares (Tutor x Aluno)

Este projeto é uma aplicação cliente-servidor desenvolvida em Python, que simula o funcionamento de uma plataforma 
de agendamento de aulas entre **alunos** e **tutores**. A comunicação ocorre por **sockets TCP**, com autenticação via **JWT**, 
criptografia híbrida (**RSA + Fernet**) e segurança de senha com **bcrypt**.

## ⚙️ Funcionalidades

### Aluno
- Cadastro com dados pessoais e senha criptografada
- Login seguro com geração de token JWT
- Visualização da lista de tutores disponíveis
- Agendamento de aulas com tutores
- Consulta, edição ou cancelamento de aulas agendadas

### Tutor
- Cadastro com especialidade, disciplina e horários disponíveis
- Login seguro com token JWT
- Gerenciamento da própria agenda

### Plataforma (Admin - opcional)
- Cadastro institucional para vincular tutores
- Visão geral da operação (expansível)

---

## 🛠 Tecnologias Utilizadas
- Python 3
- socket (comunicação cliente-servidor)
- bcrypt (hash de senha)
- jwt (tokens de autenticação)
- cryptography / pycryptodome (criptografia híbrida RSA + Fernet)
- SQLite (banco de dados local)

---

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

3. **(Terminal 2): Inicie o cliente**
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
---

## 🔐 Segurança
- As senhas são armazenadas com hash `bcrypt`
- As mensagens trocadas entre cliente e servidor são criptografadas com chave simétrica Fernet (entregue com RSA)
- Os acessos são protegidos por tokens JWT com tempo de expiração

---
