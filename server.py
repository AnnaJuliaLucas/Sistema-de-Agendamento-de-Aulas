"""
Servidor Seguro Completo para Sistema de Agendamento
"""

import socket
import json
import threading
import sqlite3
import base64
from datetime import datetime, timedelta
from security_utils import SecurityManager

class SecureServerComplete:
    """Servidor com implementação completa e segura"""
    
    def __init__(self, host='localhost', port=4444):
        self.host = host
        self.port = port
        self.socket = None
        self.security = SecurityManager()
        self.running = False
        self._init_database()
    
    def _init_database(self):
        """Inicializa banco de dados com todas as tabelas necessárias"""
        conn = sqlite3.connect('secure_sistema.db')
        cursor = conn.cursor()
        
        # Tabela de usuários com campos de segurança
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                user_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')
        
        # Tabela de alunos (dados específicos)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                birth_date DATE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabela de tutores
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tutors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                subject TEXT NOT NULL,
                specialty TEXT,
                availability TEXT NOT NULL,
                hourly_rate REAL,
                address TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabela de plataformas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS platforms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE,
                address TEXT,
                operating_hours TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Tabela de agendamentos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER,
                tutor_id INTEGER,
                platform_id INTEGER,
                appointment_date TIMESTAMP,
                duration INTEGER DEFAULT 60,
                status TEXT DEFAULT 'scheduled',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES users (id),
                FOREIGN KEY (tutor_id) REFERENCES users (id),
                FOREIGN KEY (platform_id) REFERENCES users (id)
            )
        ''')
        
        # Tabela de logs de segurança
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("🗄️ Banco de dados seguro completo inicializado")
    
    def start_server(self):
        """Inicia o servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"🔐 Servidor seguro completo iniciado em {self.host}:{self.port}")
            print("✅ Aguardando conexões...")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"🔗 Nova conexão de {address}")
                    
                    # Cria thread para cada cliente
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"❌ Erro ao aceitar conexão: {e}")
        
        except Exception as e:
            print(f"❌ Erro ao iniciar servidor: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def _handle_client(self, client_socket, address):
        """Manipula conexão de cliente individual"""
        try:
            while True:
                # Recebe tamanho da mensagem
                size_bytes = client_socket.recv(4)
                if not size_bytes:
                    break
                
                size = int.from_bytes(size_bytes, byteorder='big')
                
                # Recebe mensagem
                message_bytes = b''
                while len(message_bytes) < size:
                    chunk = client_socket.recv(size - len(message_bytes))
                    if not chunk:
                        break
                    message_bytes += chunk
                
                if not message_bytes:
                    break
                
                # Processa mensagem
                message = json.loads(message_bytes.decode('utf-8'))
                response = self._process_message(message, address)
                
                # Envia resposta
                self._send_response(client_socket, response)
                
        except Exception as e:
            print(f"❌ Erro ao processar cliente {address}: {e}")
        finally:
            client_socket.close()
            print(f"🔌 Conexão com {address} encerrada")
    
    def _send_response(self, client_socket, response):
        """Envia resposta para o cliente"""
        response_str = json.dumps(response)
        response_bytes = response_str.encode('utf-8')
        
        # Envia tamanho primeiro
        size = len(response_bytes)
        client_socket.send(size.to_bytes(4, byteorder='big'))
        
        # Envia resposta
        client_socket.send(response_bytes)
    
    def _process_message(self, message, address):
        """Processa mensagem recebida do cliente"""
        action = message.get('action')
        
        if action == 'get_public_key':
            return self._handle_public_key_request()
        
        # Para outras ações, descriptografa mensagem
        if 'encrypted_data' in message:
            try:
                # Descriptografa chave Fernet
                encrypted_key = message['encrypted_key']
                fernet_key = self.security.decrypt_with_rsa(
                    base64.b64decode(encrypted_key)
                )
                
                # Descriptografa dados
                decrypted_message = self.security.decrypt_message(
                    message['encrypted_data'],
                    base64.b64encode(fernet_key).decode('utf-8')
                )
                
                actual_message = json.loads(decrypted_message)
                return self._process_decrypted_message(actual_message, address)
                
            except Exception as e:
                print(f"❌ Erro ao descriptografar mensagem: {e}")
                return {'success': False, 'error': 'Erro de criptografia'}
        
        return {'success': False, 'error': 'Formato de mensagem inválido'}
    
    def _handle_public_key_request(self):
        """Envia chave pública para o cliente"""
        public_key_pem = self.security.get_public_key_pem()
        return {
            'success': True,
            'public_key': public_key_pem.decode('utf-8')
        }
    
    def _process_decrypted_message(self, message, address):
        """Processa mensagem descriptografada"""
        action = message.get('action')
        
        # Mapeamento de ações
        action_handlers = {
            'register': self._handle_register,
            'get_salt': self._handle_get_salt,
            'login': self._handle_login,
            'list_tutors': self._handle_list_tutors,
            'list_students': self._handle_list_students,
            'list_platforms': self._handle_list_platforms,
            'get_profile': self._handle_get_profile,
            'update_profile': self._handle_update_profile,
            'schedule_appointment': self._handle_schedule_appointment,
            'list_appointments': self._handle_list_appointments,
            'update_appointment': self._handle_update_appointment,
            'cancel_appointment': self._handle_cancel_appointment,
            'get_tutor_availability': self._handle_get_tutor_availability,
            'delete_account': self._handle_delete_account
        }
        
        handler = action_handlers.get(action)
        if handler:
            return handler(message, address)
        else:
            return {'success': False, 'error': 'Ação não reconhecida'}
    
    def _verify_token(self, token):
        """Verifica token JWT e retorna dados do usuário"""
        token_data = self.security.verify_jwt_token(token)
        if not token_data['valid']:
            return None
        
        user_id = int(token_data['payload']['user_id'])
        
        # Busca dados do usuário
        conn = sqlite3.connect('secure_sistema.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, user_type FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return {
                'id': user_data[0],
                'username': user_data[1],
                'user_type': user_data[2]
            }
        return None
    
    def _handle_register(self, message, address):
        """Processa cadastro de usuário com senha já criptografada"""
        try:
            username = message.get('username')
            email = message.get('email')
            phone = message.get('phone', '')
            password_salt = message.get('password_salt')
            password_hash = message.get('password_hash')
            user_type = message.get('user_type', 'aluno')
            
            # Dados específicos por tipo
            birth_date = message.get('birth_date')
            subject = message.get('subject')
            specialty = message.get('specialty')
            availability = message.get('availability')
            hourly_rate = message.get('hourly_rate')
            address = message.get('address')
            operating_hours = message.get('operating_hours')
            
            # Validações
            if not all([username, email, password_salt, password_hash]):
                return {'success': False, 'error': 'Dados incompletos'}
            
            # Hash adicional no servidor (dupla proteção)
            server_hash = self.security.hash_password_server_side(password_hash)
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Verifica se usuário já existe
            cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'error': 'Usuário ou email já existe'}
            
            # Insere usuário
            cursor.execute('''
                INSERT INTO users (username, email, phone, password_salt, password_hash, user_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, phone, password_salt, server_hash, user_type))
            
            user_id = cursor.lastrowid
            
            # Insere dados específicos por tipo
            if user_type == 'aluno':
                cursor.execute('''
                    INSERT INTO students (user_id, birth_date)
                    VALUES (?, ?)
                ''', (user_id, birth_date))
            elif user_type == 'tutor':
                cursor.execute('''
                    INSERT INTO tutors (user_id, subject, specialty, availability, hourly_rate, address)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, subject, specialty, availability, hourly_rate, address))
            elif user_type == 'plataforma':
                cursor.execute('''
                    INSERT INTO platforms (user_id, address, operating_hours)
                    VALUES (?, ?, ?)
                ''', (user_id, address, operating_hours))
            
            # Log de segurança
            self._log_security_event(cursor, user_id, 'register', address[0] if address else 'unknown', True, f'Usuário {user_type} cadastrado')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Usuário {username} ({user_type}) cadastrado com segurança dupla")
            return {'success': True, 'message': 'Usuário cadastrado com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro no cadastro: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_get_salt(self, message, address):
        """Retorna o salt do usuário para login"""
        try:
            username = message.get('username')
            
            if not username:
                return {'success': False, 'error': 'Nome de usuário necessário'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Busca salt do usuário
            cursor.execute('SELECT password_salt FROM users WHERE username = ?', (username,))
            result = cursor.fetchone()
            
            conn.close()
            
            if result:
                return {'success': True, 'salt': result[0]}
            else:
                return {'success': False, 'error': 'Usuário não encontrado'}
                
        except Exception as e:
            print(f"❌ Erro ao buscar salt: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_login(self, message, address):
        """Processa login com verificação de senha criptografada"""
        try:
            username = message.get('username')
            password_salt = message.get('password_salt')
            password_hash = message.get('password_hash')
            
            if not all([username, password_salt, password_hash]):
                return {'success': False, 'error': 'Dados incompletos'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Busca usuário
            cursor.execute('''
                SELECT id, password_salt, password_hash, user_type, failed_attempts, locked_until
                FROM users WHERE username = ?
            ''', (username,))
            
            user_data = cursor.fetchone()
            
            if not user_data:
                self._log_security_event(cursor, None, 'login_failed', address[0], False, 'Usuário não encontrado')
                conn.commit()
                conn.close()
                return {'success': False, 'error': 'Credenciais inválidas'}
            
            user_id, stored_salt, stored_hash, user_type, failed_attempts, locked_until = user_data
            
            # Verifica se conta está bloqueada
            if locked_until and datetime.now() < datetime.fromisoformat(locked_until):
                self._log_security_event(cursor, user_id, 'login_blocked', address[0], False, 'Conta bloqueada')
                conn.commit()
                conn.close()
                return {'success': False, 'error': 'Conta temporariamente bloqueada'}
            
            # Verifica salt
            if password_salt != stored_salt:
                self._increment_failed_attempts(cursor, user_id)
                self._log_security_event(cursor, user_id, 'login_failed', address[0], False, 'Salt incorreto')
                conn.commit()
                conn.close()
                return {'success': False, 'error': 'Credenciais inválidas'}
            
            # Verifica hash da senha
            if self.security.verify_password_server_side(password_hash, stored_hash):
                # Login bem-sucedido
                token = self.security.generate_jwt_token(str(user_id), user_type)
                
                # Atualiza último login e reseta tentativas
                cursor.execute('''
                    UPDATE users 
                    SET last_login = CURRENT_TIMESTAMP, failed_attempts = 0, locked_until = NULL
                    WHERE id = ?
                ''', (user_id,))
                
                self._log_security_event(cursor, user_id, 'login_success', address[0], True, 'Login realizado')
                conn.commit()
                conn.close()
                
                print(f"✅ Login bem-sucedido para {username} ({user_type})")
                return {
                    'success': True, 
                    'token': token, 
                    'user_type': user_type,
                    'message': 'Login realizado com sucesso'
                }
            
            else:
                # Senha incorreta
                self._increment_failed_attempts(cursor, user_id)
                self._log_security_event(cursor, user_id, 'login_failed', address[0], False, 'Senha incorreta')
                conn.commit()
                conn.close()
                return {'success': False, 'error': 'Credenciais inválidas'}
                
        except Exception as e:
            print(f"❌ Erro no login: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _increment_failed_attempts(self, cursor, user_id):
        """Incrementa tentativas de login falhadas"""
        cursor.execute('SELECT failed_attempts FROM users WHERE id = ?', (user_id,))
        current_attempts = cursor.fetchone()[0]
        
        new_attempts = current_attempts + 1
        
        # Bloqueia conta após 5 tentativas
        if new_attempts >= 5:
            lock_until = datetime.now() + timedelta(minutes=30)
            cursor.execute('''
                UPDATE users 
                SET failed_attempts = ?, locked_until = ?
                WHERE id = ?
            ''', (new_attempts, lock_until.isoformat(), user_id))
        else:
            cursor.execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (new_attempts, user_id))
    
    def _handle_list_tutors(self, message, address):
        """Lista tutores disponíveis"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, u.email, u.phone, t.subject, t.specialty, t.availability, t.hourly_rate, t.address
                FROM tutors t
                JOIN users u ON t.user_id = u.id
                WHERE u.user_type = 'tutor'
                ORDER BY u.username
            ''')
            
            tutors = []
            for row in cursor.fetchall():
                tutors.append({
                    'id': row[0],
                    'name': row[1],
                    'email': row[2],
                    'phone': row[3],
                    'subject': row[4],
                    'specialty': row[5],
                    'availability': row[6],
                    'hourly_rate': row[7],
                    'address': row[8]
                })
            
            conn.close()
            return {'success': True, 'tutors': tutors}
            
        except Exception as e:
            print(f"❌ Erro ao listar tutores: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_list_students(self, message, address):
        """Lista alunos (apenas para tutores e plataformas)"""
        user = self._verify_token(message.get('token'))
        if not user or user['user_type'] == 'aluno':
            return {'success': False, 'error': 'Acesso negado'}
        
        try:
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, u.email, u.phone, s.birth_date
                FROM students s
                JOIN users u ON s.user_id = u.id
                WHERE u.user_type = 'aluno'
                ORDER BY u.username
            ''')
            
            students = []
            for row in cursor.fetchall():
                students.append({
                    'id': row[0],
                    'name': row[1],
                    'email': row[2],
                    'phone': row[3],
                    'birth_date': row[4]
                })
            
            conn.close()
            return {'success': True, 'students': students}
            
        except Exception as e:
            print(f"❌ Erro ao listar alunos: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_list_platforms(self, message, address):
        """Lista plataformas disponíveis"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.username, u.email, u.phone, p.address, p.operating_hours
                FROM platforms p
                JOIN users u ON p.user_id = u.id
                WHERE u.user_type = 'plataforma'
                ORDER BY u.username
            ''')
            
            platforms = []
            for row in cursor.fetchall():
                platforms.append({
                    'id': row[0],
                    'name': row[1],
                    'email': row[2],
                    'phone': row[3],
                    'address': row[4],
                    'operating_hours': row[5]
                })
            
            conn.close()
            return {'success': True, 'platforms': platforms}
            
        except Exception as e:
            print(f"❌ Erro ao listar plataformas: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_get_profile(self, message, address):
        """Obtém dados do perfil do usuário"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Dados básicos do usuário
            cursor.execute('''
                SELECT username, email, phone, user_type
                FROM users WHERE id = ?
            ''', (user['id'],))
            
            user_data = cursor.fetchone()
            if not user_data:
                conn.close()
                return {'success': False, 'error': 'Usuário não encontrado'}
            
            profile = {
                'id': user['id'],
                'username': user_data[0],
                'email': user_data[1],
                'phone': user_data[2],
                'user_type': user_data[3]
            }
            
            # Dados específicos por tipo
            if user['user_type'] == 'aluno':
                cursor.execute('SELECT birth_date FROM students WHERE user_id = ?', (user['id'],))
                student_data = cursor.fetchone()
                if student_data:
                    profile['birth_date'] = student_data[0]
            
            elif user['user_type'] == 'tutor':
                cursor.execute('''
                    SELECT subject, specialty, availability, hourly_rate, address
                    FROM tutors WHERE user_id = ?
                ''', (user['id'],))
                tutor_data = cursor.fetchone()
                if tutor_data:
                    profile.update({
                        'subject': tutor_data[0],
                        'specialty': tutor_data[1],
                        'availability': tutor_data[2],
                        'hourly_rate': tutor_data[3],
                        'address': tutor_data[4]
                    })
            
            elif user['user_type'] == 'plataforma':
                cursor.execute('''
                    SELECT address, operating_hours
                    FROM platforms WHERE user_id = ?
                ''', (user['id'],))
                platform_data = cursor.fetchone()
                if platform_data:
                    profile.update({
                        'address': platform_data[0],
                        'operating_hours': platform_data[1]
                    })
            
            conn.close()
            return {'success': True, 'profile': profile}
            
        except Exception as e:
            print(f"❌ Erro ao obter perfil: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_schedule_appointment(self, message, address):
        """Agenda uma nova aula"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            tutor_id = message.get('tutor_id')
            student_id = message.get('student_id', user['id'] if user['user_type'] == 'aluno' else None)
            platform_id = message.get('platform_id')
            appointment_date = message.get('appointment_date')
            duration = message.get('duration', 60)
            notes = message.get('notes', '')
            
            if not all([tutor_id, student_id, appointment_date]):
                return {'success': False, 'error': 'Dados incompletos'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Verifica se o horário está disponível
            cursor.execute('''
                SELECT id FROM appointments 
                WHERE tutor_id = ? AND appointment_date = ? AND status != 'cancelled'
            ''', (tutor_id, appointment_date))
            
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'error': 'Horário não disponível'}
            
            # Cria o agendamento
            cursor.execute('''
                INSERT INTO appointments (student_id, tutor_id, platform_id, appointment_date, duration, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (student_id, tutor_id, platform_id, appointment_date, duration, notes))
            
            appointment_id = cursor.lastrowid
            
            # Log de segurança
            self._log_security_event(cursor, user['id'], 'schedule_appointment', address[0], True, f'Aula agendada ID: {appointment_id}')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Aula agendada: ID {appointment_id}")
            return {'success': True, 'appointment_id': appointment_id, 'message': 'Aula agendada com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro ao agendar aula: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_list_appointments(self, message, address):
        """Lista agendamentos do usuário"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Query baseada no tipo de usuário
            if user['user_type'] == 'aluno':
                cursor.execute('''
                    SELECT a.id, a.appointment_date, a.duration, a.status, a.notes,
                           ut.username as tutor_name, t.subject, t.specialty, t.address,
                           up.username as platform_name
                    FROM appointments a
                    JOIN users ut ON a.tutor_id = ut.id
                    JOIN tutors t ON a.tutor_id = t.user_id
                    LEFT JOIN users up ON a.platform_id = up.id
                    WHERE a.student_id = ?
                    ORDER BY a.appointment_date
                ''', (user['id'],))
            
            elif user['user_type'] == 'tutor':
                cursor.execute('''
                    SELECT a.id, a.appointment_date, a.duration, a.status, a.notes,
                           us.username as student_name,
                           up.username as platform_name
                    FROM appointments a
                    JOIN users us ON a.student_id = us.id
                    LEFT JOIN users up ON a.platform_id = up.id
                    WHERE a.tutor_id = ?
                    ORDER BY a.appointment_date
                ''', (user['id'],))
            
            elif user['user_type'] == 'plataforma':
                cursor.execute('''
                    SELECT a.id, a.appointment_date, a.duration, a.status, a.notes,
                           us.username as student_name, ut.username as tutor_name,
                           t.subject, t.specialty
                    FROM appointments a
                    JOIN users us ON a.student_id = us.id
                    JOIN users ut ON a.tutor_id = ut.id
                    JOIN tutors t ON a.tutor_id = t.user_id
                    WHERE a.platform_id = ?
                    ORDER BY a.appointment_date
                ''', (user['id'],))
            
            appointments = []
            for row in cursor.fetchall():
                appointment = {
                    'id': row[0],
                    'appointment_date': row[1],
                    'duration': row[2],
                    'status': row[3],
                    'notes': row[4]
                }
                
                # Adiciona campos específicos por tipo de usuário
                if user['user_type'] == 'aluno':
                    appointment.update({
                        'tutor_name': row[5],
                        'subject': row[6],
                        'specialty': row[7],
                        'address': row[8],
                        'platform_name': row[9]
                    })
                elif user['user_type'] == 'tutor':
                    appointment.update({
                        'student_name': row[5],
                        'platform_name': row[6]
                    })
                elif user['user_type'] == 'plataforma':
                    appointment.update({
                        'student_name': row[5],
                        'tutor_name': row[6],
                        'subject': row[7],
                        'specialty': row[8]
                    })
                
                appointments.append(appointment)
            
            conn.close()
            return {'success': True, 'appointments': appointments}
            
        except Exception as e:
            print(f"❌ Erro ao listar agendamentos: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_update_appointment(self, message, address):
        """Atualiza um agendamento"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            appointment_id = message.get('appointment_id')
            new_date = message.get('new_date')
            
            if not all([appointment_id, new_date]):
                return {'success': False, 'error': 'Dados incompletos'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Verifica se o usuário pode editar este agendamento
            cursor.execute('''
                SELECT student_id, tutor_id, platform_id FROM appointments WHERE id = ?
            ''', (appointment_id,))
            
            appointment_data = cursor.fetchone()
            if not appointment_data:
                conn.close()
                return {'success': False, 'error': 'Agendamento não encontrado'}
            
            student_id, tutor_id, platform_id = appointment_data
            
            # Verifica permissão
            if not (user['id'] == student_id or user['id'] == tutor_id or user['id'] == platform_id):
                conn.close()
                return {'success': False, 'error': 'Sem permissão para editar este agendamento'}
            
            # Verifica se o novo horário está disponível
            cursor.execute('''
                SELECT id FROM appointments 
                WHERE tutor_id = ? AND appointment_date = ? AND status != 'cancelled' AND id != ?
            ''', (tutor_id, new_date, appointment_id))
            
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'error': 'Novo horário não disponível'}
            
            # Atualiza o agendamento
            cursor.execute('''
                UPDATE appointments 
                SET appointment_date = ?
                WHERE id = ?
            ''', (new_date, appointment_id))
            
            # Log de segurança
            self._log_security_event(cursor, user['id'], 'update_appointment', address[0], True, f'Aula reagendada ID: {appointment_id}')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Aula reagendada: ID {appointment_id}")
            return {'success': True, 'message': 'Aula reagendada com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro ao reagendar aula: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_cancel_appointment(self, message, address):
        """Cancela um agendamento"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            appointment_id = message.get('appointment_id')
            
            if not appointment_id:
                return {'success': False, 'error': 'ID do agendamento é obrigatório'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Verifica se o usuário pode cancelar este agendamento
            cursor.execute('''
                SELECT student_id, tutor_id, platform_id FROM appointments WHERE id = ?
            ''', (appointment_id,))
            
            appointment_data = cursor.fetchone()
            if not appointment_data:
                conn.close()
                return {'success': False, 'error': 'Agendamento não encontrado'}
            
            student_id, tutor_id, platform_id = appointment_data
            
            # Verifica permissão
            if not (user['id'] == student_id or user['id'] == tutor_id or user['id'] == platform_id):
                conn.close()
                return {'success': False, 'error': 'Sem permissão para cancelar este agendamento'}
            
            # Cancela o agendamento
            cursor.execute('''
                UPDATE appointments 
                SET status = 'cancelled'
                WHERE id = ?
            ''', (appointment_id,))
            
            # Log de segurança
            self._log_security_event(cursor, user['id'], 'cancel_appointment', address[0], True, f'Aula cancelada ID: {appointment_id}')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Aula cancelada: ID {appointment_id}")
            return {'success': True, 'message': 'Aula cancelada com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro ao cancelar aula: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_get_tutor_availability(self, message, address):
        """Obtém disponibilidade de um tutor"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            tutor_id = message.get('tutor_id')
            date = message.get('date')
            
            if not tutor_id:
                return {'success': False, 'error': 'ID do tutor é obrigatório'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Busca horários disponíveis do tutor
            cursor.execute('''
                SELECT availability FROM tutors t
                JOIN users u ON t.user_id = u.id
                WHERE u.id = ?
            ''', (tutor_id,))
            
            tutor_data = cursor.fetchone()
            if not tutor_data:
                conn.close()
                return {'success': False, 'error': 'Tutor não encontrado'}
            
            availability = tutor_data[0]
            
            # Se uma data específica foi fornecida, verifica agendamentos
            busy_times = []
            if date:
                cursor.execute('''
                    SELECT appointment_date FROM appointments
                    WHERE tutor_id = ? AND DATE(appointment_date) = ? AND status != 'cancelled'
                ''', (tutor_id, date))
                
                busy_times = [row[0] for row in cursor.fetchall()]
            
            conn.close()
            return {
                'success': True, 
                'availability': availability,
                'busy_times': busy_times
            }
            
        except Exception as e:
            print(f"❌ Erro ao obter disponibilidade: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_update_profile(self, message, address):
        """Atualiza perfil do usuário"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            # Dados básicos
            email = message.get('email')
            phone = message.get('phone')
            
            # Dados específicos por tipo
            birth_date = message.get('birth_date')
            subject = message.get('subject')
            specialty = message.get('specialty')
            availability = message.get('availability')
            hourly_rate = message.get('hourly_rate')
            address = message.get('address')
            operating_hours = message.get('operating_hours')
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Atualiza dados básicos
            if email or phone:
                update_fields = []
                update_values = []
                
                if email:
                    update_fields.append('email = ?')
                    update_values.append(email)
                if phone:
                    update_fields.append('phone = ?')
                    update_values.append(phone)
                
                update_values.append(user['id'])
                
                cursor.execute(f'''
                    UPDATE users SET {', '.join(update_fields)}
                    WHERE id = ?
                ''', update_values)
            
            # Atualiza dados específicos por tipo
            if user['user_type'] == 'aluno' and birth_date:
                cursor.execute('''
                    UPDATE students SET birth_date = ? WHERE user_id = ?
                ''', (birth_date, user['id']))
            
            elif user['user_type'] == 'tutor':
                update_fields = []
                update_values = []
                
                for field, value in [('subject', subject), ('specialty', specialty), 
                                   ('availability', availability), ('hourly_rate', hourly_rate), 
                                   ('address', address)]:
                    if value is not None:
                        update_fields.append(f'{field} = ?')
                        update_values.append(value)
                
                if update_fields:
                    update_values.append(user['id'])
                    cursor.execute(f'''
                        UPDATE tutors SET {', '.join(update_fields)}
                        WHERE user_id = ?
                    ''', update_values)
            
            elif user['user_type'] == 'plataforma':
                update_fields = []
                update_values = []
                
                for field, value in [('address', address), ('operating_hours', operating_hours)]:
                    if value is not None:
                        update_fields.append(f'{field} = ?')
                        update_values.append(value)
                
                if update_fields:
                    update_values.append(user['id'])
                    cursor.execute(f'''
                        UPDATE platforms SET {', '.join(update_fields)}
                        WHERE user_id = ?
                    ''', update_values)
            
            # Log de segurança
            self._log_security_event(cursor, user['id'], 'update_profile', address[0], True, 'Perfil atualizado')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Perfil atualizado para usuário {user['id']}")
            return {'success': True, 'message': 'Perfil atualizado com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro ao atualizar perfil: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _handle_delete_account(self, message, address):
        """Exclui conta do usuário"""
        user = self._verify_token(message.get('token'))
        if not user:
            return {'success': False, 'error': 'Token inválido'}
        
        try:
            password_hash = message.get('password_hash')
            
            if not password_hash:
                return {'success': False, 'error': 'Confirmação de senha é obrigatória'}
            
            conn = sqlite3.connect('secure_sistema.db')
            cursor = conn.cursor()
            
            # Verifica senha
            cursor.execute('SELECT password_hash FROM users WHERE id = ?', (user['id'],))
            stored_hash = cursor.fetchone()[0]
            
            if self.security.verify_password_server_side(password_hash.encode("utf-8"), stored_hash):
                conn.close()
                return {'success': False, 'error': 'Senha incorreta'}
            
            # Cancela todos os agendamentos
            cursor.execute('''
                UPDATE appointments 
                SET status = 'cancelled'
                WHERE student_id = ? OR tutor_id = ? OR platform_id = ?
            ''', (user['id'], user['id'], user['id']))
            
            # Remove dados específicos
            if user['user_type'] == 'aluno':
                cursor.execute('DELETE FROM students WHERE user_id = ?', (user['id'],))
            elif user['user_type'] == 'tutor':
                cursor.execute('DELETE FROM tutors WHERE user_id = ?', (user['id'],))
            elif user['user_type'] == 'plataforma':
                cursor.execute('DELETE FROM platforms WHERE user_id = ?', (user['id'],))
            
            # Remove usuário
            cursor.execute('DELETE FROM users WHERE id = ?', (user['id'],))
            
            # Log de segurança
            self._log_security_event(cursor, user['id'], 'delete_account', address[0], True, 'Conta excluída')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Conta excluída para usuário {user['id']}")
            return {'success': True, 'message': 'Conta excluída com sucesso'}
            
        except Exception as e:
            print(f"❌ Erro ao excluir conta: {e}")
            return {'success': False, 'error': 'Erro interno do servidor'}
    
    def _log_security_event(self, cursor, user_id, action, ip_address, success, details):
        """Registra evento de segurança"""
        cursor.execute('''
            INSERT INTO security_logs (user_id, action, ip_address, success, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, ip_address, success, details))
    
    def stop_server(self):
        """Para o servidor"""
        self.running = False
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    print("🔐 Iniciando Servidor...")
    print("🛡️ Segurança máxima com criptografia dupla")
    print("📊 Logs de segurança habilitados")
    
    server = SecureServerComplete()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Parando servidor...")
        server.stop_server()
        print("👋 Servidor encerrado")

