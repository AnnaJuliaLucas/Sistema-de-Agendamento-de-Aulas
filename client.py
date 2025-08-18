"""
Cliente Seguro Completo para Sistema de Agendamento
Implementa todas as funcionalidades do README com segurança adequada
"""

import socket
import json
import getpass
import base64
from datetime import datetime
from security_utils import SecurityManager

class SecureClientComplete:
    """Cliente com implementação completa e segura"""
    
    def __init__(self, host='localhost', port=4444):
        self.host = host
        self.port = port
        self.socket = None
        self.security = SecurityManager()
        self.session_token = None
        self.user_type = None
        self.server_public_key = None
        
    def connect(self):
        """Estabelece conexão segura com o servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            
            # Solicita chave pública do servidor
            self._request_server_public_key()
            
            print("✅ Conexão segura estabelecida com o servidor")
            return True
        except Exception as e:
            print(f"❌ Erro ao conectar: {e}")
            return False
    
    def _request_server_public_key(self):
        """Solicita e armazena a chave pública do servidor"""
        request = {
            'action': 'get_public_key'
        }
        self._send_message(request)
        response = self._receive_message()
        
        if response.get('success'):
            self.server_public_key = response['public_key'].encode('utf-8')
            print("🔑 Chave pública do servidor recebida")
    
    def _send_message(self, message):
        """Envia mensagem para o servidor"""
        message_str = json.dumps(message)
        message_bytes = message_str.encode('utf-8')
        
        # Envia tamanho da mensagem primeiro
        size = len(message_bytes)
        self.socket.send(size.to_bytes(4, byteorder='big'))
        
        # Envia a mensagem
        self.socket.send(message_bytes)
    
    def _receive_message(self):
        """Recebe mensagem do servidor"""
        # Recebe tamanho da mensagem
        size_bytes = self.socket.recv(4)
        if not size_bytes:
            return None
        
        size = int.from_bytes(size_bytes, byteorder='big')
        
        # Recebe a mensagem
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
            print("❌ Chave pública do servidor não disponível")
            return None
        
        # Criptografa mensagem
        encrypted = self.security.encrypt_message(json.dumps(message))
        
        # Criptografa chave Fernet com RSA do servidor
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
    
    def register_user(self):
        """Cadastro seguro de usuário"""
        print("\n=== CADASTRO DE USUÁRIO ===")
        
        # Tipo de usuário
        print("Tipos de usuário:")
        print("1. Aluno")
        print("2. Tutor")
        print("3. Plataforma")
        
        while True:
            choice = input("Escolha o tipo (1-3): ").strip()
            if choice in ['1', '2', '3']:
                user_types = {'1': 'aluno', '2': 'tutor', '3': 'plataforma'}
                user_type = user_types[choice]
                break
            print("❌ Opção inválida!")
        
        # Dados básicos
        username = input("Nome de usuário: ").strip()
        email = input("Email: ").strip()
        phone = input("Telefone: ").strip()
        
        # Solicita senha de forma segura
        password = getpass.getpass("Senha: ")
        password_confirm = getpass.getpass("Confirme a senha: ")
        
        if password != password_confirm:
            print("❌ Senhas não coincidem!")
            return False
        
        # Valida força da senha
        if not self._validate_password_strength(password):
            return False
        
        # Hash da senha no cliente (SEGURANÇA CRÍTICA)
        password_data = self.security.hash_password_client_side(password)
        
        # Dados para envio (senha já criptografada)
        user_data = {
            'action': 'register',
            'username': username,
            'email': email,
            'phone': phone,
            'password_salt': password_data['salt'],
            'password_hash': password_data['client_hash'],
            'user_type': user_type
        }
        
        # Dados específicos por tipo
        if user_type == 'aluno':
            birth_date = input("Data de nascimento (YYYY-MM-DD): ").strip()
            user_data['birth_date'] = birth_date
        
        elif user_type == 'tutor':
            subject = input("Disciplina: ").strip()
            specialty = input("Especialidade: ").strip()
            availability = input("Horários disponíveis: ").strip()
            hourly_rate = input("Valor por hora: ").strip()
            address = input("Modalidade: ").strip()
            
            user_data.update({
                'subject': subject,
                'specialty': specialty,
                'availability': availability,
                'hourly_rate': float(hourly_rate) if hourly_rate else None,
                'address': address
            })
        
        elif user_type == 'plataforma':
            address = input("Endereço: ").strip()
            operating_hours = input("Horários de funcionamento: ").strip()
            
            user_data.update({
                'address': address,
                'operating_hours': operating_hours
            })
        
        print("🔒 Enviando dados com senha criptografada...")
        
        # Envia dados criptografados
        response = self._send_secure_message(user_data)
        
        if response and response.get('success'):
            print("✅ Usuário cadastrado com sucesso!")
            return True
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro no cadastro: {error}")
            return False
    
    def login_user(self):
        """Login seguro de usuário"""
        print("\n=== LOGIN DE USUÁRIO ===")
        
        username = input("Nome de usuário: ").strip()
        password = getpass.getpass("Senha: ")
        
        # Primeiro, busca o salt do usuário no servidor
        salt_request = {
            'action': 'get_salt',
            'username': username
        }
        
        print("🔍 Buscando dados de autenticação...")
        salt_response = self._send_secure_message(salt_request)
        
        if not salt_response or not salt_response.get('success'):
            error = salt_response.get('error', 'Erro desconhecido') if salt_response else 'Sem resposta do servidor'
            print(f"❌ Erro ao buscar dados: {error}")
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
        
        print("🔒 Autenticando com senha criptografada...")
        
        # Envia dados criptografados
        response = self._send_secure_message(login_data)
        
        if response and response.get('success'):
            self.session_token = response.get('token')
            self.user_type = response.get('user_type')
            print("✅ Login realizado com sucesso!")
            print(f"🎫 Logado como: {self.user_type}")
            return True
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro no login: {error}")
            return False
    
    def _validate_password_strength(self, password):
        """Valida força da senha"""
        if len(password) < 8:
            print("❌ Senha deve ter pelo menos 8 caracteres")
            return False
        
        if not any(c.isupper() for c in password):
            print("❌ Senha deve ter pelo menos uma letra maiúscula")
            return False
        
        if not any(c.islower() for c in password):
            print("❌ Senha deve ter pelo menos uma letra minúscula")
            return False
        
        if not any(c.isdigit() for c in password):
            print("❌ Senha deve ter pelo menos um número")
            return False
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            print("❌ Senha deve ter pelo menos um caractere especial")
            return False
        
        print("✅ Senha atende aos critérios de segurança")
        return True
    
    def list_tutors(self):
        """Lista tutores disponíveis"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        request = {
            'action': 'list_tutors',
            'token': self.session_token
        }
        
        response = self._send_secure_message(request)
        
        if response and response.get('success'):
            tutors = response.get('tutors', [])
            print(f"\n=== TUTORES DISPONÍVEIS ({len(tutors)}) ===")
            for i, tutor in enumerate(tutors, 1):
                print(f"{i}. 📚 {tutor['name']}")
                print(f"   Disciplina: {tutor['subject']}")
                print(f"   Especialidade: {tutor['specialty']}")
                print(f"   Email: {tutor['email']}")
                print(f"   Telefone: {tutor['phone']}")
                print(f"   Disponibilidade: {tutor['availability']}")
                print(f"   Valor/hora: R$ {tutor['hourly_rate']}")
                print(f"   Endereço: {tutor['address']}")
                print()
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao listar tutores: {error}")
    
    def list_students(self):
        """Lista alunos (apenas para tutores e plataformas)"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        if self.user_type == 'aluno':
            print("❌ Alunos não podem ver lista de outros alunos")
            return
        
        request = {
            'action': 'list_students',
            'token': self.session_token
        }
        
        response = self._send_secure_message(request)
        
        if response and response.get('success'):
            students = response.get('students', [])
            print(f"\n=== ALUNOS CADASTRADOS ({len(students)}) ===")
            for i, student in enumerate(students, 1):
                print(f"{i}. 👨‍🎓 {student['name']}")
                print(f"   Email: {student['email']}")
                print(f"   Telefone: {student['phone']}")
                print(f"   Data de nascimento: {student['birth_date']}")
                print()
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao listar alunos: {error}")
    
    def list_platforms(self):
        """Lista plataformas disponíveis"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        request = {
            'action': 'list_platforms',
            'token': self.session_token
        }
        
        response = self._send_secure_message(request)
        
        if response and response.get('success'):
            platforms = response.get('platforms', [])
            print(f"\n=== PLATAFORMAS DISPONÍVEIS ({len(platforms)}) ===")
            for i, platform in enumerate(platforms, 1):
                print(f"{i}. 🏢 {platform['name']}")
                print(f"   Email: {platform['email']}")
                print(f"   Telefone: {platform['phone']}")
                print(f"   Endereço: {platform['address']}")
                print(f"   Horários: {platform['operating_hours']}")
                print()
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao listar plataformas: {error}")
    
    def view_profile(self):
        """Visualiza perfil do usuário"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        request = {
            'action': 'get_profile',
            'token': self.session_token
        }
        
        response = self._send_secure_message(request)
        
        if response and response.get('success'):
            profile = response.get('profile', {})
            print(f"\n=== MEU PERFIL ({profile.get('user_type', '').upper()}) ===")
            print(f"ID: {profile.get('id')}")
            print(f"Nome: {profile.get('username')}")
            print(f"Email: {profile.get('email')}")
            print(f"Telefone: {profile.get('phone')}")
            
            if profile.get('user_type') == 'aluno':
                print(f"Data de nascimento: {profile.get('birth_date')}")
            elif profile.get('user_type') == 'tutor':
                print(f"Disciplina: {profile.get('subject')}")
                print(f"Especialidade: {profile.get('specialty')}")
                print(f"Disponibilidade: {profile.get('availability')}")
                print(f"Valor/hora: R$ {profile.get('hourly_rate')}")
                print(f"Endereço: {profile.get('address')}")
            elif profile.get('user_type') == 'plataforma':
                print(f"Endereço: {profile.get('address')}")
                print(f"Horários: {profile.get('operating_hours')}")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao obter perfil: {error}")
    
    def schedule_appointment(self):
        """Agenda uma nova aula"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        print("\n=== AGENDAR AULA ===")
        
        # Lista tutores para seleção
        request = {'action': 'list_tutors', 'token': self.session_token}
        response = self._send_secure_message(request)
        
        if not response or not response.get('success'):
            print("❌ Erro ao obter lista de tutores")
            return
        
        tutors = response.get('tutors', [])
        if not tutors:
            print("❌ Nenhum tutor disponível")
            return
        
        print("Tutores disponíveis:")
        for i, tutor in enumerate(tutors, 1):
            print(f"{i}. {tutor['name']} - {tutor['subject']} - {tutor['specialty']}")
        
        while True:
            try:
                choice = int(input("Escolha um tutor (número): ")) - 1
                if 0 <= choice < len(tutors):
                    selected_tutor = tutors[choice]
                    break
                print("❌ Opção inválida!")
            except ValueError:
                print("❌ Digite um número válido!")
        
        # Se for tutor ou plataforma, precisa escolher aluno
        student_id = None
        if self.user_type != 'aluno':
            request = {'action': 'list_students', 'token': self.session_token}
            response = self._send_secure_message(request)
            
            if response and response.get('success'):
                students = response.get('students', [])
                if students:
                    print("\nAlunos disponíveis:")
                    for i, student in enumerate(students, 1):
                        print(f"{i}. {student['name']}")
                    
                    while True:
                        try:
                            choice = int(input("Escolha um aluno (número): ")) - 1
                            if 0 <= choice < len(students):
                                student_id = students[choice]['id']
                                break
                            print("❌ Opção inválida!")
                        except ValueError:
                            print("❌ Digite um número válido!")
        
        # Plataforma (opcional)
        platform_id = None
        use_platform = input("\nUsar plataforma? (s/n): ").lower() == 's'
        
        if use_platform:
            request = {'action': 'list_platforms', 'token': self.session_token}
            response = self._send_secure_message(request)
            
            if response and response.get('success'):
                platforms = response.get('platforms', [])
                if platforms:
                    print("\nPlataformas disponíveis:")
                    for i, platform in enumerate(platforms, 1):
                        print(f"{i}. {platform['name']}")
                    
                    while True:
                        try:
                            choice = int(input("Escolha uma plataforma (número): ")) - 1
                            if 0 <= choice < len(platforms):
                                platform_id = platforms[choice]['id']
                                break
                            print("❌ Opção inválida!")
                        except ValueError:
                            print("❌ Digite um número válido!")
        
        # Data e hora
        print(f"\nDisponibilidade do tutor: {selected_tutor['availability']}")
        appointment_date = input("Data e hora (YYYY-MM-DD HH:MM): ").strip()
        duration = input("Duração em minutos (padrão 60): ").strip()
        notes = input("Observações (opcional): ").strip()
        
        # Agenda a aula
        schedule_data = {
            'action': 'schedule_appointment',
            'token': self.session_token,
            'tutor_id': selected_tutor['id'],
            'student_id': student_id,
            'platform_id': platform_id,
            'appointment_date': appointment_date,
            'duration': int(duration) if duration else 60,
            'notes': notes
        }
        
        response = self._send_secure_message(schedule_data)
        
        if response and response.get('success'):
            print("✅ Aula agendada com sucesso!")
            print(f"ID do agendamento: {response.get('appointment_id')}")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao agendar aula: {error}")
    
    def list_appointments(self):
        """Lista agendamentos do usuário"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        request = {
            'action': 'list_appointments',
            'token': self.session_token
        }
        
        response = self._send_secure_message(request)
        
        if response and response.get('success'):
            appointments = response.get('appointments', [])
            print(f"\n=== MEUS AGENDAMENTOS ({len(appointments)}) ===")
            
            for i, apt in enumerate(appointments, 1):
                print(f"{i}. 📅 {apt['appointment_date']} ({apt['duration']} min)")
                print(f"   Status: {apt['status']}")
                
                if self.user_type == 'aluno':
                    print(f"   Tutor: {apt['tutor_name']}")
                    print(f"   Disciplina: {apt['subject']}")
                    print(f"   Especialidade: {apt['specialty']}")
                    print(f"   Endereço: {apt['address']}")
                    if apt.get('platform_name'):
                        print(f"   Plataforma: {apt['platform_name']}")
                
                elif self.user_type == 'tutor':
                    print(f"   Aluno: {apt['student_name']}")
                    if apt.get('platform_name'):
                        print(f"   Plataforma: {apt['platform_name']}")
                
                elif self.user_type == 'plataforma':
                    print(f"   Aluno: {apt['student_name']}")
                    print(f"   Tutor: {apt['tutor_name']}")
                    print(f"   Disciplina: {apt['subject']}")
                
                if apt.get('notes'):
                    print(f"   Observações: {apt['notes']}")
                print(f"   ID: {apt['id']}")
                print()
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao listar agendamentos: {error}")
    
    def update_appointment(self):
        """Reagenda uma aula"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        # Lista agendamentos primeiro
        self.list_appointments()
        
        appointment_id = input("\nID do agendamento para reagendar: ").strip()
        new_date = input("Nova data e hora (YYYY-MM-DD HH:MM): ").strip()
        
        update_data = {
            'action': 'update_appointment',
            'token': self.session_token,
            'appointment_id': int(appointment_id),
            'new_date': new_date
        }
        
        response = self._send_secure_message(update_data)
        
        if response and response.get('success'):
            print("✅ Aula reagendada com sucesso!")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao reagendar aula: {error}")
    
    def cancel_appointment(self):
        """Cancela uma aula"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        # Lista agendamentos primeiro
        self.list_appointments()
        
        appointment_id = input("\nID do agendamento para cancelar: ").strip()
        
        confirm = input(f"Confirma cancelamento do agendamento {appointment_id}? (s/n): ").lower()
        if confirm != 's':
            print("Cancelamento abortado")
            return
        
        cancel_data = {
            'action': 'cancel_appointment',
            'token': self.session_token,
            'appointment_id': int(appointment_id)
        }
        
        response = self._send_secure_message(cancel_data)
        
        if response and response.get('success'):
            print("✅ Aula cancelada com sucesso!")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao cancelar aula: {error}")
    
    def update_profile(self):
        """Atualiza perfil do usuário"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        print("\n=== ATUALIZAR PERFIL ===")
        print("Deixe em branco para manter valor atual")
        
        # Dados básicos
        email = input("Novo email: ").strip() or None
        phone = input("Novo telefone: ").strip() or None
        
        update_data = {
            'action': 'update_profile',
            'token': self.session_token,
            'email': email,
            'phone': phone
        }
        
        # Dados específicos por tipo
        if self.user_type == 'aluno':
            birth_date = input("Nova data de nascimento (YYYY-MM-DD): ").strip() or None
            update_data['birth_date'] = birth_date
        
        elif self.user_type == 'tutor':
            subject = input("Nova disciplina: ").strip() or None
            specialty = input("Nova especialidade: ").strip() or None
            availability = input("Nova disponibilidade: ").strip() or None
            hourly_rate = input("Novo valor/hora: ").strip()
            address = input("Novo endereço: ").strip() or None
            
            update_data.update({
                'subject': subject,
                'specialty': specialty,
                'availability': availability,
                'hourly_rate': float(hourly_rate) if hourly_rate else None,
                'address': address
            })
        
        elif self.user_type == 'plataforma':
            address = input("Novo endereço: ").strip() or None
            operating_hours = input("Novos horários: ").strip() or None
            
            update_data.update({
                'address': address,
                'operating_hours': operating_hours
            })
        
        response = self._send_secure_message(update_data)
        
        if response and response.get('success'):
            print("✅ Perfil atualizado com sucesso!")
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao atualizar perfil: {error}")
    
    def delete_account(self):
        """Exclui conta do usuário"""
        if not self.session_token:
            print("❌ Faça login primeiro")
            return
        
        print("\n=== EXCLUIR CONTA ===")
        print("⚠️  ATENÇÃO: Esta ação é irreversível!")
        print("⚠️  Todos os seus agendamentos serão cancelados!")
        
        confirm = input("Tem certeza que deseja excluir sua conta? (digite 'EXCLUIR'): ")
        if confirm != 'EXCLUIR':
            print("Exclusão cancelada")
            return
        
        password = getpass.getpass("Digite sua senha para confirmar: ")
        
        # Hash da senha
        password_data = self.security.hash_password_client_side(password)
        
        delete_data = {
            'action': 'delete_account',
            'token': self.session_token,
            'password_hash': password_data['client_hash']
        }
        
        response = self._send_secure_message(delete_data)
        
        if response and response.get('success'):
            print("✅ Conta excluída com sucesso!")
            self.session_token = None
            self.user_type = None
        else:
            error = response.get('error', 'Erro desconhecido') if response else 'Sem resposta do servidor'
            print(f"❌ Erro ao excluir conta: {error}")
    
    def logout(self):
        """Faz logout do usuário"""
        self.session_token = None
        self.user_type = None
        print("👋 Logout realizado com sucesso!")
    
    def main_menu(self):
        """Menu principal do cliente"""
        if not self.connect():
            return
        
        while True:
            print("\n" + "="*60)
            print("🎓 SISTEMA DE AGENDAMENTO - CLIENTE SEGURO COMPLETO")
            print("="*60)
            
            if not self.session_token:
                # Menu não logado
                print("1. Cadastrar usuário")
                print("2. Fazer login")
                print("3. Sair")
                print("="*60)
                
                choice = input("Escolha uma opção: ").strip()
                
                if choice == '1':
                    self.register_user()
                elif choice == '2':
                    self.login_user()
                elif choice == '3':
                    print("👋 Encerrando cliente...")
                    break
                else:
                    print("❌ Opção inválida!")
            
            else:
                # Menu logado
                print(f"Logado como: {self.user_type.upper()}")
                print("="*60)
                print("1. Ver meu perfil")
                print("2. Atualizar perfil")
                print("3. Listar tutores")
                
                if self.user_type != 'aluno':
                    print("4. Listar alunos")
                
                print("5. Listar plataformas")
                print("6. Agendar aula")
                print("7. Ver meus agendamentos")
                print("8. Reagendar aula")
                print("9. Cancelar aula")
                print("10. Excluir conta")
                print("11. Logout")
                print("12. Sair")
                print("="*60)
                
                choice = input("Escolha uma opção: ").strip()
                
                if choice == '1':
                    self.view_profile()
                elif choice == '2':
                    self.update_profile()
                elif choice == '3':
                    self.list_tutors()
                elif choice == '4' and self.user_type != 'aluno':
                    self.list_students()
                elif choice == '5':
                    self.list_platforms()
                elif choice == '6':
                    self.schedule_appointment()
                elif choice == '7':
                    self.list_appointments()
                elif choice == '8':
                    self.update_appointment()
                elif choice == '9':
                    self.cancel_appointment()
                elif choice == '10':
                    self.delete_account()
                elif choice == '11':
                    self.logout()
                elif choice == '12':
                    print("👋 Encerrando cliente...")
                    break
                else:
                    print("❌ Opção inválida!")
        
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    print("🔐 Iniciando Cliente...")
    print("✅ Senhas são criptografadas ANTES do envio ao servidor")
    print("🎯 Todas as funcionalidades do README implementadas")
    
    client = SecureClientComplete()
    client.main_menu()

