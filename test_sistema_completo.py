#!/usr/bin/env python3
"""
Script de Teste Automatizado para o Sistema de Agendamento
Testa todas as funcionalidades: cadastro, login, agendamento, etc.
"""

import socket
import json
import base64
import time
from datetime import datetime, timedelta
import sys
import os

# Adiciona o diretório do projeto ao path
sys.path.append('/home/ubuntu/trabalho-final/trabalho-final')
from security_utils import SecurityManager

class TestClient:
    """Cliente de teste automatizado"""
    
    def __init__(self, host='localhost', port=4444):
        self.host = host
        self.port = port
        self.socket = None
        self.security = SecurityManager()
        self.server_public_key = None
        self.session_token = None
        self.user_type = None
        
    def connect(self):
        """Conecta ao servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self._request_server_public_key()
            return True
        except Exception as e:
            print(f"❌ Erro ao conectar: {e}")
            return False
    
    def disconnect(self):
        """Desconecta do servidor"""
        if self.socket:
            self.socket.close()
    
    def _request_server_public_key(self):
        """Solicita chave pública do servidor"""
        request = {'action': 'get_public_key'}
        self._send_message(request)
        response = self._receive_message()
        
        if response.get('success'):
            self.server_public_key = response['public_key'].encode('utf-8')
    
    def _send_message(self, message):
        """Envia mensagem para o servidor"""
        message_str = json.dumps(message)
        message_bytes = message_str.encode('utf-8')
        
        size = len(message_bytes)
        self.socket.send(size.to_bytes(4, byteorder='big'))
        self.socket.send(message_bytes)
    
    def _receive_message(self):
        """Recebe mensagem do servidor"""
        size_bytes = self.socket.recv(4)
        if not size_bytes:
            return None
        
        size = int.from_bytes(size_bytes, byteorder='big')
        
        message_bytes = b''
        while len(message_bytes) < size:
            chunk = self.socket.recv(size - len(message_bytes))
            if not chunk:
                break
            message_bytes += chunk
        
        return json.loads(message_bytes.decode('utf-8'))
    
    def _send_secure_message(self, message):
        """Envia mensagem criptografada"""
        if not self.server_public_key:
            return None
        
        encrypted = self.security.encrypt_message(json.dumps(message))
        
        fernet_key_encrypted = self.security.encrypt_with_rsa(
            base64.b64decode(encrypted['fernet_key']),
            self.server_public_key
        )
        
        secure_message = {
            'encrypted_data': encrypted['encrypted_data'],
            'encrypted_key': base64.b64encode(fernet_key_encrypted).decode('utf-8')
        }
        
        self._send_message(secure_message)
        return self._receive_message()
    
    def register_user(self, username, email, password, user_type, **kwargs):
        """Registra um usuário"""
        password_data = self.security.hash_password_client_side(password)
        
        register_data = {
            'action': 'register',
            'username': username,
            'email': email,
            'phone': kwargs.get('phone', ''),
            'password_salt': password_data['salt'],
            'password_hash': password_data['client_hash'],
            'user_type': user_type
        }
        
        # Adiciona dados específicos por tipo
        if user_type == 'aluno':
            register_data['birth_date'] = kwargs.get('birth_date', '2000-01-01')
        elif user_type == 'tutor':
            register_data.update({
                'subject': kwargs.get('subject', 'Matemática'),
                'specialty': kwargs.get('specialty', 'Álgebra'),
                'availability': kwargs.get('availability', 'Segunda a Sexta, 14h-18h'),
                'hourly_rate': kwargs.get('hourly_rate', 50.0),
                'address': kwargs.get('address', 'Centro da cidade')
            })
        elif user_type == 'plataforma':
            register_data.update({
                'address': kwargs.get('address', 'Rua Principal, 123'),
                'operating_hours': kwargs.get('operating_hours', '8h-22h')
            })
        
        return self._send_secure_message(register_data)
    
    def login_user(self, username, password):
        """Faz login do usuário"""
        # Primeiro, busca o salt do usuário no servidor
        salt_request = {
            'action': 'get_salt',
            'username': username
        }
        
        salt_response = self._send_secure_message(salt_request)
        
        if not salt_response or not salt_response.get('success'):
            return False
        
        # Usa o salt armazenado para gerar o hash da senha
        stored_salt = salt_response.get('salt')
        password_data = self.security.hash_password_client_side(password, stored_salt)
        
        login_data = {
            'action': 'login',
            'username': username,
            'password_salt': password_data['salt'],
            'password_hash': password_data['client_hash']
        }
        
        response = self._send_secure_message(login_data)
        
        if response and response.get('success'):
            self.session_token = response.get('token')
            self.user_type = response.get('user_type')
            return True
        return False
    
    def list_tutors(self):
        """Lista tutores"""
        message = {
            'action': 'list_tutors',
            'token': self.session_token
        }
        return self._send_secure_message(message)
    
    def schedule_appointment(self, tutor_id, appointment_date, notes="Teste automatizado"):
        """Agenda uma aula"""
        message = {
            'action': 'schedule_appointment',
            'token': self.session_token,
            'tutor_id': tutor_id,
            'appointment_date': appointment_date,
            'duration': 60,
            'notes': notes
        }
        return self._send_secure_message(message)
    
    def list_appointments(self):
        """Lista agendamentos"""
        message = {
            'action': 'list_appointments',
            'token': self.session_token
        }
        return self._send_secure_message(message)

def run_tests():
    """Executa todos os testes"""
    print("🧪 INICIANDO TESTES AUTOMATIZADOS DO SISTEMA")
    print("=" * 50)
    
    # Dados de teste
    test_users = [
        {
            'username': 'aluno_teste',
            'email': 'aluno@teste.com',
            'password': 'MinhaSenh@123',
            'user_type': 'aluno',
            'birth_date': '2000-05-15'
        },
        {
            'username': 'tutor_teste',
            'email': 'tutor@teste.com',
            'password': 'TutorSenh@456',
            'user_type': 'tutor',
            'subject': 'Matemática',
            'specialty': 'Cálculo',
            'availability': 'Segunda a Sexta, 9h-17h',
            'hourly_rate': 75.0
        },
        {
            'username': 'plataforma_teste',
            'email': 'plataforma@teste.com',
            'password': 'PlataSenh@789',
            'user_type': 'plataforma',
            'address': 'Av. Educação, 456',
            'operating_hours': '7h-23h'
        }
    ]
    
    results = []
    
    # Teste 1: Cadastro de usuários
    print("\n📝 TESTE 1: Cadastro de Usuários")
    client = TestClient()
    
    if not client.connect():
        print("❌ Falha na conexão com o servidor")
        return
    
    for user_data in test_users:
        username = user_data['username']
        print(f"  Cadastrando {username} ({user_data['user_type']})...")
        
        response = client.register_user(**user_data)
        
        if response and response.get('success'):
            print(f"  ✅ {username} cadastrado com sucesso")
            results.append(f"✅ Cadastro {user_data['user_type']}: OK")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta'
            print(f"  ❌ Erro ao cadastrar {username}: {error}")
            results.append(f"❌ Cadastro {user_data['user_type']}: FALHOU")
    
    client.disconnect()
    time.sleep(1)
    
    # Teste 2: Login de usuários
    print("\n🔐 TESTE 2: Login de Usuários")
    
    for user_data in test_users:
        client = TestClient()
        if not client.connect():
            continue
            
        username = user_data['username']
        password = user_data['password']
        
        print(f"  Fazendo login de {username}...")
        
        if client.login_user(username, password):
            print(f"  ✅ Login de {username} bem-sucedido")
            results.append(f"✅ Login {user_data['user_type']}: OK")
            
            # Teste 3: Funcionalidades específicas
            print(f"    Testando funcionalidades de {user_data['user_type']}...")
            
            # Lista tutores (disponível para todos)
            tutors_response = client.list_tutors()
            if tutors_response and tutors_response.get('success'):
                tutors = tutors_response.get('tutors', [])
                print(f"    ✅ Listagem de tutores: {len(tutors)} encontrados")
                
                # Se for aluno e há tutores, tenta agendar
                if user_data['user_type'] == 'aluno' and tutors:
                    tutor_id = tutors[0]['id']
                    appointment_date = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')
                    
                    schedule_response = client.schedule_appointment(tutor_id, appointment_date)
                    if schedule_response and schedule_response.get('success'):
                        print("    ✅ Agendamento de aula: OK")
                        results.append("✅ Agendamento: OK")
                        
                        # Lista agendamentos
                        appointments_response = client.list_appointments()
                        if appointments_response and appointments_response.get('success'):
                            appointments = appointments_response.get('appointments', [])
                            print(f"    ✅ Lista agendamentos: {len(appointments)} encontrados")
                            results.append("✅ Lista agendamentos: OK")
                        else:
                            print("    ❌ Erro ao listar agendamentos")
                            results.append("❌ Lista agendamentos: FALHOU")
                    else:
                        error = schedule_response.get('error', 'Erro desconhecido') if schedule_response else 'Sem resposta'
                        print(f"    ❌ Erro no agendamento: {error}")
                        results.append("❌ Agendamento: FALHOU")
            else:
                print("    ❌ Erro ao listar tutores")
                results.append("❌ Lista tutores: FALHOU")
        else:
            print(f"  ❌ Erro no login de {username}")
            results.append(f"❌ Login {user_data['user_type']}: FALHOU")
        
        client.disconnect()
        time.sleep(0.5)
    
    # Relatório final
    print("\n" + "=" * 50)
    print("📊 RELATÓRIO FINAL DOS TESTES")
    print("=" * 50)
    
    success_count = sum(1 for result in results if result.startswith('✅'))
    total_count = len(results)
    
    for result in results:
        print(result)
    
    print(f"\n📈 RESUMO: {success_count}/{total_count} testes passaram")
    
    if success_count == total_count:
        print("🎉 TODOS OS TESTES PASSARAM! Sistema funcionando perfeitamente!")
    else:
        print("⚠️  Alguns testes falharam. Verifique os logs acima.")
    
    return success_count == total_count

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

